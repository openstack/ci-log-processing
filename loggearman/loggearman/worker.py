#!/usr/bin/env python3
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import argparse
import daemon
import gear
import json
import logging
import os
import queue
import re
import requests
import select
import socket
import subprocess
import sys
import threading
import time
import yaml

import paho.mqtt.publish as publish

try:
    import daemon.pidlockfile as pidfile_mod
except ImportError:
    import daemon.pidfile as pidfile_mod


def semi_busy_wait(seconds):
    # time.sleep() may return early. If it does sleep() again and repeat
    # until at least the number of seconds specified has elapsed.
    start_time = time.time()
    while True:
        time.sleep(seconds)
        cur_time = time.time()
        seconds = seconds - (cur_time - start_time)
        if seconds <= 0.0:
            return


class FilterException(Exception):
    pass


class CRM114Filter(object):
    def __init__(self, script, path, build_status):
        self.p = None
        self.script = script
        self.path = path
        self.build_status = build_status
        if build_status not in ['SUCCESS', 'FAILURE']:
            return
        if not os.path.exists(path):
            os.makedirs(path)
        args = [script, path, build_status]
        self.p = subprocess.Popen(args,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  stdin=subprocess.PIPE,
                                  close_fds=True)

    def process(self, data):
        if not self.p:
            return True
        self.p.stdin.write(data['message'].encode('utf-8') + '\n')
        (r, w, x) = select.select([self.p.stdout], [],
                                  [self.p.stdin, self.p.stdout], 20)
        if not r:
            self.p.kill()
            raise FilterException('Timeout reading from CRM114')
        r = self.p.stdout.readline()
        if not r:
            err = self.p.stderr.read()
            if err:
                raise FilterException(err)
            else:
                raise FilterException('Early EOF from CRM114')
        r = r.strip()
        data['error_pr'] = float(r)
        return True

    def _catchOSError(self, method):
        try:
            method()
        except OSError:
            logging.exception("Subprocess cleanup failed.")

    def close(self):
        if not self.p:
            return
        # CRM114 should die when its stdinput is closed. Close that
        # fd along with stdout and stderr then return.
        self._catchOSError(self.p.stdin.close)
        self._catchOSError(self.p.stdout.close)
        self._catchOSError(self.p.stderr.close)
        self._catchOSError(self.p.wait)


class CRM114FilterFactory(object):
    name = "CRM114"

    def __init__(self, script, basepath):
        self.script = script
        self.basepath = basepath
        # Precompile regexes
        self.re_remove_suffix = re.compile(r'(\.[^a-zA-Z]+)?(\.gz)?$')
        self.re_remove_dot = re.compile(r'\.')

    def create(self, fields):
        # We only want the basename so that the same logfile at different
        # paths isn't treated as different
        filename = os.path.basename(fields['filename'])
        # We want to collapse any numeric or compression suffixes so that
        # nova.log and nova.log.1 and nova.log.1.gz are treated as the same
        # logical file
        filename = self.re_remove_suffix.sub(r'', filename)
        filename = self.re_remove_dot.sub('_', filename)
        path = os.path.join(self.basepath, filename)
        return CRM114Filter(self.script, path, fields['build_status'])


class OsloSeverityFilter(object):
    DATEFMT = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}((\.|\,)\d{3,6})?'
    SEVERITYFMT = '(DEBUG|INFO|WARNING|ERROR|TRACE|AUDIT|CRITICAL)'
    OSLO_LOGMATCH = (r'^(?P<date>%s)(?P<line>(?P<pid> \d+)? '
                     '(?P<severity>%s).*)' %
                     (DATEFMT, SEVERITYFMT))
    OSLORE = re.compile(OSLO_LOGMATCH)

    def process(self, data):
        msg = data['message']
        m = self.OSLORE.match(msg)
        if m:
            data['severity'] = m.group('severity')
            if data['severity'].lower == 'debug':
                # Ignore debug-level lines
                return False
        return True

    def close(self):
        pass


class OsloSeverityFilterFactory(object):
    name = "OsloSeverity"

    def create(self, fields):
        return OsloSeverityFilter()


class SystemdSeverityFilter(object):
    '''Match systemd DEBUG level logs

    A line to match looks like:

    Aug 15 18:58:49.910786 hostname devstack@keystone.service[31400]:
                           DEBUG uwsgi ...
    '''
    SYSTEMDDATE = r'\w+\s+\d+\s+\d{2}:\d{2}:\d{2}((\.|\,)\d{3,6})?'
    DATEFMT = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}((\.|\,)\d{3,6})?'
    SEVERITYFMT = '(DEBUG|INFO|WARNING|ERROR|TRACE|AUDIT|CRITICAL)'
    SYSTEMD_LOGMATCH = r'^(?P<date>%s)( (\S+) \S+\[\d+\]\: ' \
        '(?P<severity>%s)?.*)' % (SYSTEMDDATE, SEVERITYFMT)
    SYSTEMDRE = re.compile(SYSTEMD_LOGMATCH)

    def process(self, data):
        msg = data['message']
        m = self.SYSTEMDRE.match(msg)
        if m:
            if m.group('severity') == 'DEBUG':
                return False
        return True

    def close(self):
        pass


class SystemdSeverityFilterFactory(object):
    name = "SystemdSeverity"

    def create(self, fields):
        return SystemdSeverityFilter()


class LogRetriever(threading.Thread):
    def __init__(self, gearman_worker, filters, logq,
                 log_cert_verify, log_ca_certs, mqtt=None):
        threading.Thread.__init__(self)
        self.gearman_worker = gearman_worker
        self.filters = filters
        self.logq = logq
        self.mqtt = mqtt
        self.log_cert_verify = log_cert_verify
        self.log_ca_certs = log_ca_certs

    def run(self):
        while True:
            try:
                self._handle_event()
            except Exception:
                logging.exception("Exception retrieving log event.")

    def _handle_event(self):
        fields = {}
        num_log_lines = 0
        source_url = ''
        http_session = None
        job = self.gearman_worker.getJob()
        try:
            arguments = json.loads(job.arguments.decode('utf-8'))
            source_url = arguments['source_url']
            event = arguments['event']
            logging.debug("Handling event: " + json.dumps(event))
            fields = event.get('fields') or event.get('@fields')
            tags = event.get('tags') or event.get('@tags')
            if fields['build_status'] != 'ABORTED':
                # Handle events ignoring aborted builds. These builds are
                # discarded by zuul.
                file_obj, http_session = self._open_log_file_url(source_url)

                try:
                    all_filters = []
                    for f in self.filters:
                        logging.debug("Adding filter: %s" % f.name)
                        all_filters.append(f.create(fields))
                    filters = all_filters

                    base_event = {}
                    base_event.update(fields)
                    base_event["tags"] = tags
                    for line in self._retrieve_log_line(file_obj):
                        keep_line = True
                        out_event = base_event.copy()
                        out_event["message"] = line
                        new_filters = []
                        for f in filters:
                            if not keep_line:
                                new_filters.append(f)
                                continue
                            try:
                                keep_line = f.process(out_event)
                                new_filters.append(f)
                            except FilterException:
                                logging.exception("Exception filtering event: "
                                                  "%s" % line.encode("utf-8"))
                        filters = new_filters
                        if keep_line:
                            self.logq.put(out_event)
                        num_log_lines += 1

                    logging.debug("Pushed %s log lines." % num_log_lines)
                finally:
                    for f in all_filters:
                        f.close()
                    if http_session:
                        http_session.close()
            job.sendWorkComplete()
            # Only send mqtt events for log files we processed.
            if self.mqtt and num_log_lines:
                msg = json.dumps({
                    'build_uuid': fields.get('build_uuid'),
                    'source_url': source_url,
                    'status': 'success',
                })
                self.mqtt.publish_single(msg, fields.get('project'),
                                         fields.get('build_change'),
                                         'retrieve_logs',
                                         fields.get('build_queue'))
        except Exception as e:
            logging.exception("Exception handling log event.")
            job.sendWorkException(str(e).encode('utf-8'))
            if self.mqtt:
                msg = json.dumps({
                    'build_uuid': fields.get('build_uuid'),
                    'source_url': source_url,
                    'status': 'failure',
                })
                self.mqtt.publish_single(msg, fields.get('project'),
                                         fields.get('build_change'),
                                         'retrieve_logs',
                                         fields.get('build_queue'))

    def _retrieve_log_line(self, file_obj, chunk_size=4096):
        if not file_obj:
            return
        # Response.iter_lines automatically decodes 'gzip' and 'deflate'
        # encodings.
        # https://requests.readthedocs.io/en/master/user/quickstart/#raw-response-content
        for line in file_obj.iter_lines(chunk_size, decode_unicode=True):
            yield line

    def _open_log_file_url(self, source_url):
        file_obj = None

        kwargs = {}
        if self.log_cert_verify and self.log_ca_certs:
            kwargs['verify'] = self.log_ca_certs
        elif not self.log_cert_verify:
            kwargs['verify'] = self.log_cert_verify

        try:
            logging.debug("Retrieving: " + source_url)
            # Use a session to persist the HTTP connection across requests
            # while downloading chunks of the log file.
            session = requests.Session()
            session.headers = {'Accept-encoding': 'deflate, gzip'}
            file_obj = session.get(source_url, stream=True, **kwargs)
            file_obj.raise_for_status()
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                logging.info("Unable to retrieve %s: HTTP error 404" %
                             source_url)
            else:
                logging.exception("Unable to get log data.")
        except Exception:
            # Silently drop fatal errors when retrieving logs.
            # TODO(clarkb): Handle these errors.
            # Perhaps simply add a log message to file_obj?
            logging.exception("Unable to retrieve source file.")
            raise

        return file_obj, session


class StdOutLogProcessor(object):
    def __init__(self, logq, pretty_print=False):
        self.logq = logq
        self.pretty_print = pretty_print

    def handle_log_event(self):
        log = self.logq.get()
        if self.pretty_print:
            print(json.dumps(log, sort_keys=True,
                  indent=4, separators=(',', ': ')))
        else:
            print(json.dumps(log))
        # Push each log event through to keep logstash up to date.
        sys.stdout.flush()


class INETLogProcessor(object):
    socket_type = None

    def __init__(self, logq, host, port):
        self.logq = logq
        self.host = host
        self.port = port
        self.socket = None

    def _connect_socket(self):
        logging.debug("Creating socket.")
        self.socket = socket.socket(socket.AF_INET, self.socket_type)
        self.socket.connect((self.host, self.port))

    def handle_log_event(self):
        log = self.logq.get()
        try:
            if self.socket is None:
                self._connect_socket()
            self.socket.sendall((json.dumps(log) + '\n').encode('utf-8'))
        except Exception:
            logging.exception("Exception sending INET event.")
            # Logstash seems to take about a minute to start again. Wait 90
            # seconds before attempting to reconnect. If logstash is not
            # available after 90 seconds we will throw another exception and
            # die.
            semi_busy_wait(90)
            self._connect_socket()
            self.socket.sendall((json.dumps(log) + '\n').encode('utf-8'))


class UDPLogProcessor(INETLogProcessor):
    socket_type = socket.SOCK_DGRAM


class TCPLogProcessor(INETLogProcessor):
    socket_type = socket.SOCK_STREAM


class PushMQTT(object):
    def __init__(self, hostname, base_topic, port=1883, client_id=None,
                 keepalive=60, will=None, auth=None, tls=None, qos=0):
        self.hostname = hostname
        self.port = port
        self.client_id = client_id
        self.keepalive = 60
        self.will = will
        self.auth = auth
        self.tls = tls
        self.qos = qos
        self.base_topic = base_topic

    def _generate_topic(self, project, job_id, action):
        return '/'.join([self.base_topic, project, job_id, action])

    def publish_single(self, msg, project, job_id, action, build_queue=None):
        if job_id:
            topic = self._generate_topic(project, job_id, action)
        elif build_queue:
            topic = self._generate_topic(project, build_queue, action)
        else:
            topic = self.base_topic + '/' + project

        publish.single(topic, msg, hostname=self.hostname,
                       port=self.port, client_id=self.client_id,
                       keepalive=self.keepalive, will=self.will,
                       auth=self.auth, tls=self.tls, qos=self.qos)


class Server(object):
    def __init__(self, config, debuglog):
        # Config init.
        self.config = config
        self.gearman_host = self.config['gearman-host']
        self.gearman_port = self.config['gearman-port']
        self.output_host = self.config['output-host']
        self.output_port = self.config['output-port']
        self.output_mode = self.config['output-mode']
        mqtt_host = self.config.get('mqtt-host')
        mqtt_port = self.config.get('mqtt-port', 1883)
        mqtt_user = self.config.get('mqtt-user')
        mqtt_pass = self.config.get('mqtt-pass')
        mqtt_topic = self.config.get('mqtt-topic', 'gearman-subunit')
        mqtt_ca_certs = self.config.get('mqtt-ca-certs')
        mqtt_certfile = self.config.get('mqtt-certfile')
        mqtt_keyfile = self.config.get('mqtt-keyfile')
        self.log_ca_certs = self.config.get('log-ca-certs')
        self.log_cert_verify = self.config.get('log-cert-verify', True)
        # Pythong logging output file.
        self.debuglog = debuglog
        self.retriever = None
        self.logqueue = queue.Queue(16384)
        self.processor = None
        self.filter_factories = []
        # Run the severity filter first so it can filter out chatty
        # logs.
        self.filter_factories.append(OsloSeverityFilterFactory())
        self.filter_factories.append(SystemdSeverityFilterFactory())
        crmscript = self.config.get('crm114-script')
        crmdata = self.config.get('crm114-data')
        if crmscript and crmdata:
            self.filter_factories.append(
                CRM114FilterFactory(crmscript, crmdata))
        # Setup MQTT
        self.mqtt = None
        if mqtt_host:
            auth = None
            if mqtt_user:
                auth = {'username': mqtt_user}
            if mqtt_pass:
                auth['password'] = mqtt_pass
            tls = None
            if mqtt_ca_certs:
                tls = {'ca_certs': mqtt_ca_certs,
                       'certfile': mqtt_certfile,
                       'keyfile': mqtt_keyfile}

            self.mqtt = PushMQTT(mqtt_host, mqtt_topic, port=mqtt_port,
                                 auth=auth, tls=tls)

    def setup_logging(self):
        if self.debuglog:
            logging.basicConfig(format='%(asctime)s %(message)s',
                                filename=self.debuglog, level=logging.DEBUG)
        else:
            # Prevent leakage into the logstash log stream.
            logging.basicConfig(level=logging.CRITICAL)
        logging.debug("Log pusher starting.")

    def wait_for_name_resolution(self, host, port):
        while True:
            try:
                socket.getaddrinfo(host, port)
            except socket.gaierror as e:
                if e.errno == socket.EAI_AGAIN:
                    logging.debug("Temporary failure in name resolution")
                    time.sleep(2)
                    continue
                else:
                    raise
            break

    def setup_retriever(self):
        hostname = socket.gethostname()
        gearman_worker = gear.Worker(hostname + '-pusher')
        self.wait_for_name_resolution(self.gearman_host, self.gearman_port)
        gearman_worker.addServer(self.gearman_host,
                                 self.gearman_port)
        gearman_worker.registerFunction(b'push-log')
        self.retriever = LogRetriever(gearman_worker, self.filter_factories,
                                      self.logqueue, self.log_cert_verify,
                                      self.log_ca_certs, mqtt=self.mqtt)

    def setup_processor(self):
        if self.output_mode == "tcp":
            self.processor = TCPLogProcessor(self.logqueue,
                                             self.output_host,
                                             self.output_port)
        elif self.output_mode == "udp":
            self.processor = UDPLogProcessor(self.logqueue,
                                             self.output_host,
                                             self.output_port)
        else:
            # Note this processor will not work if the process is run as a
            # daemon. You must use the --foreground option.
            self.processor = StdOutLogProcessor(self.logqueue)

    def main(self):
        self.setup_retriever()
        self.setup_processor()

        self.retriever.daemon = True
        self.retriever.start()

        while True:
            try:
                self.processor.handle_log_event()
            except Exception:
                logging.exception("Exception processing log event.")
                raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", required=True,
                        help="Path to yaml config file.")
    parser.add_argument("-d", "--debuglog",
                        help="Enable debug log. "
                             "Specifies file to write log to.")
    parser.add_argument("--foreground", action='store_true',
                        help="Run in the foreground.")
    parser.add_argument("-p", "--pidfile",
                        default="/var/run/jenkins-log-pusher/"
                                "jenkins-log-gearman-worker.pid",
                        help="PID file to lock during daemonization.")
    args = parser.parse_args()

    with open(args.config, 'r') as config_stream:
        config = yaml.safe_load(config_stream)
    server = Server(config, args.debuglog)

    if args.foreground:
        server.setup_logging()
        server.main()
    else:
        pidfile = pidfile_mod.TimeoutPIDLockFile(args.pidfile, 10)
        with daemon.DaemonContext(pidfile=pidfile):
            server.setup_logging()
            server.main()


if __name__ == '__main__':
    main()
