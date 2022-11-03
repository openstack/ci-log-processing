#!/usr/bin/env python3
#
# Copyright (C) 2021 Red Hat
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

"""
The goal is to push recent zuul builds into log gearman processor.

[ CLI ] -> [ Config ] -> [ ZuulFetcher ] -> [ LogPublisher ]


# Zuul builds results are not sorted by end time. Here is a problematic
scenario:

Neutron01 build starts at 00:00
Many smolXX build starts and stops at 01:00
Neutron01 build stops at 02:00


When at 01:55 we query the /builds:

- smol42   ends at 01:54
- smol41   ends at 01:50
- smol40   ends at 01:49
- ...


When at 02:05 we query the /builds:

- smol42   ends at 01:54    # already in build cache, skip
- smol41   ends at 01:50    # already in build cache, skip
- smol40   ends at 01:49    # already in build cache, skip
- ...
- neutron01  ends at 02:00  # not in build cache, get_last_job_results yield

Question: when to stop the builds query?

We could check that all the _id value got processed, but that can be tricky
when long running build are interleaved with short one. For example, the
scrapper could keep track of the oldest _id and ensure it got them all.

But Instead, we'll always grab the last 1000 builds and process new builds.
This is not ideal, because we might miss builds if more than 1000 builds
happens between two query.
But that will have todo until the zuul builds api can return builds sorted by
end_time.
"""


import argparse
import datetime
import gear
import itertools
import json
import logging
import multiprocessing
import os
import requests
import socket
import sqlite3
import sys
import time
import yaml

from concurrent.futures import ThreadPoolExecutor
from distutils.version import StrictVersion as s_version
from prometheus_client import Gauge
from prometheus_client import start_http_server
import tenacity
from urllib.parse import urljoin


retry_request = tenacity.retry(
    # Raise the real exception instead of RetryError
    reraise=True,
    # Stop after 10 attempts
    stop=tenacity.stop_after_attempt(10),
    # Slowly wait more
    wait=tenacity.wait_exponential(multiplier=1, min=1, max=10),
)


@retry_request
def requests_get(url, verify=True):
    return requests.get(url, verify=verify)


def requests_get_json(url, verify=True):
    resp = requests_get(url, verify)
    resp.raise_for_status()
    return resp.json()


def is_zuul_host_up(url, verify=True):
    try:
        resp = requests_get(url, verify)
        return resp.status_code < 400
    except requests.exceptions.HTTPError:
        pass


###############################################################################
#                                    CLI                                      #
###############################################################################
def get_arguments():
    parser = argparse.ArgumentParser(description="Fetch and push last Zuul "
                                     "CI job logs into gearman.")
    parser.add_argument("--config", help="Logscraper config file",
                        required=True)
    parser.add_argument("--file-list", help="File list to download")
    parser.add_argument("--zuul-api-url", help="URL(s) for Zuul API. Parameter"
                        " can be set multiple times.", action='append')
    parser.add_argument("--job-name", help="CI job name(s). Parameter can be "
                        "set multiple times. If not set it would scrape "
                        "every latest builds.", action='append')
    parser.add_argument("--gearman-server", help="Gearman host address")
    parser.add_argument("--gearman-port", help="Gearman listen port.")
    parser.add_argument("--follow", help="Keep polling zuul builds", type=bool,
                        default=True)
    parser.add_argument("--insecure", help="Skip validating SSL cert",
                        action="store_false")
    parser.add_argument("--checkpoint-file", help="File that will keep "
                        "information about last uuid timestamp for a job.")
    parser.add_argument("--logstash-url", help="When provided, script will "
                        "check connection to Logstash service before sending "
                        "to log processing system. For example: "
                        "logstash.local:9999")
    parser.add_argument("--workers", help="Worker processes for logscraper",
                        type=int)
    parser.add_argument("--max-skipped", help="How many job results should be "
                        "checked until last uuid written in checkpoint file "
                        "is founded")
    parser.add_argument("--debug", help="Print more information", type=bool,
                        default=False)
    parser.add_argument("--download", help="Download logs and do not send "
                        "to gearman service")
    parser.add_argument("--directory", help="Directory, where the logs will "
                        "be stored.")
    parser.add_argument("--wait-time", help="Pause time for the next "
                        "iteration", type=int)
    parser.add_argument("--ca-file", help="Provide custom CA certificate")
    parser.add_argument("--monitoring-port", help="Expose an Prometheus "
                        "exporter to collect monitoring metrics."
                        "NOTE: When no port set, monitoring will be disabled.",
                        type=int)
    args = parser.parse_args()
    return args


def get_config_args(config_path):
    config_file = load_config(config_path)
    if config_file:
        return config_file


def parse_args(app_args, config_args):
    if not config_args:
        logging.warning("Can not get information from config files")

    if not config_args:
        print("The config file is necessary to provide!")
        sys.exit(1)

    # NOTE: When insecure flag is set as an argument, the value is False,
    # so if insecure is set to True in config file, it should also be False.
    if not getattr(app_args, 'insecure') or (
            'insecure' in config_args and config_args['insecure']):
        setattr(app_args, 'insecure', False)

    for k, v in config_args.items():
        # Arguments provided via CLI should have higher priority than
        # provided in config.
        if getattr(app_args, k, None) is None:
            setattr(app_args, k, v)

    return app_args


###############################################################################
#                      Configuration of this process                          #
###############################################################################
class Config:
    def __init__(self, args, zuul_api_url, job_name=None):
        url_path = zuul_api_url.split("/")
        if url_path[-3] != "api" and url_path[-2] != "tenant":
            print(
                "ERROR: zuul-api-url needs to be in the form "
                "of: https://<fqdn>/api/tenant/<tenant-name>"
            )
            sys.exit(1)
        self.tenant = url_path[-1]

        self.filename = "%s" % args.checkpoint_file

        if job_name:
            self.filename = "%s-%s" % (self.filename, job_name)

        self.build_cache = BuildCache(self.filename)
        self.config_file = load_config(args.file_list)

    def save(self):
        try:
            self.build_cache.save()
        except Exception as e:
            logging.critical("Can not write status to the build_cache "
                             "file %s" % e)


class BuildCache:
    def __init__(self, filepath=None):
        self.builds = dict()

        if not filepath:
            logging.critical("No cache file provided. Can not continue")
            sys.exit(1)

        self.create_db(filepath)
        self.create_table()

        # clean builds that are older than 1 day
        self.clean()
        self.vacuum()

        rows = self.fetch_data()
        if rows:
            for r in rows:
                uid, date = r
                self.builds[uid] = date

    def create_db(self, filepath):
        try:
            self.connection = sqlite3.connect(filepath)
            self.cursor = self.connection.cursor()
        except Exception as e:
            logging.critical("Can not create cache DB! Error %s" % e)

    def create_table(self):
        try:
            self.cursor.execute("CREATE TABLE IF NOT EXISTS logscraper ("
                                "uid INTEGER, timestamp INTEGER)")
        except sqlite3.OperationalError:
            logging.debug("The logscraper table already exists")

    def fetch_data(self):
        try:
            return self.cursor.execute(
                "SELECT uid, timestamp FROM logscraper").fetchall()
        except Exception as e:
            logging.exception("Can't get data from cache file! Error %s" % e)

    def add(self, uid):
        self.builds[uid] = int(datetime.datetime.now().timestamp())

    def vacuum(self):
        self.cursor.execute("vacuum")
        self.connection.commit()

    def clean(self):
        # Remove old builds
        yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
        self.cursor.execute("DELETE FROM logscraper WHERE timestamp < %s" %
                            yesterday.timestamp())
        self.connection.commit()

    def save(self):
        self.cursor.executemany('INSERT INTO logscraper VALUES (?,?)',
                                list(self.builds.items()))
        self.connection.commit()

    def contains(self, uid):
        return uid in self.builds


class Monitoring:
    def __init__(self):
        self.job_count = Gauge('logscraper_job_count',
                               'Number of jobs processed by logscraper',
                               ['job_name'])

    def parse_metrics(self, builds):
        self.job_count.labels('summary').inc(len(builds))
        for build in builds:
            self.job_count.labels(build['job_name']).inc()


###############################################################################
#                             Log Processing                                  #
###############################################################################
class LogMatcher(object):
    def __init__(self, server, port, success, log_url, host_vars, config):
        self.client = gear.Client()
        self.client.addServer(server, port)
        self.hosts = host_vars
        self.success = success
        self.log_url = log_url
        self.config_file = config

    def submitJobs(self, jobname, files, result):
        self.client.waitForServer(90)
        ret = []
        for f in files:
            output = self.makeOutput(f, result)
            output = json.dumps(output).encode("utf8")
            job = gear.TextJob(jobname, output)
            self.client.submitJob(job, background=True)
            ret.append(dict(handle=job.handle, arguments=output))
        return ret

    def makeOutput(self, file_object, result):
        output = {}
        output["retry"] = False
        output["event"] = self.makeEvent(file_object, result)
        output["source_url"] = output["event"]["fields"]["log_url"]
        return output

    def makeEvent(self, file_object, result):
        out_event = {}
        tags = []
        out_event["fields"] = self.makeFields(file_object, result)
        for f in self.config_file["files"]:
            if file_object in f["name"] or \
                    file_object.replace(".gz", "") in f["name"]:
                tags = f["tags"]
                break

        out_event["tags"] = [file_object] + tags
        return out_event

    def makeFields(self, filename, result):
        fields = {}
        fields["build_node"] = "zuul-executor"
        fields["filename"] = filename
        fields["build_name"] = result["job_name"]
        fields["build_status"] = (
            "SUCCESS" if result["result"] == "SUCCESS" else "FAILURE"
        )
        fields["project"] = result["project"]
        fields["voting"] = int(result["voting"])
        fields["build_set"] = result["buildset"]
        fields["build_queue"] = result["pipeline"]
        fields["build_ref"] = result["ref"]
        fields["build_branch"] = result.get("branch", "UNKNOWN")
        fields["build_zuul_url"] = "N/A"
        fields["build_duration"] = result.get("duration", 0)

        if "change" in result:
            fields["build_change"] = result["change"]
            fields["build_patchset"] = result["patchset"]
        elif "newrev" in result:
            fields["build_newrev"] = result.get("newrev", "UNKNOWN")

        fields["node_provider"] = "local"
        log_url = urljoin(result["log_url"], filename)
        fields["log_url"] = log_url
        fields["tenant"] = result["tenant"]

        if "executor" in result and "hostname" in result["executor"]:
            fields["zuul_executor"] = result["executor"]["hostname"]

        fields["build_uuid"] = result["buildset"]["uuid"]

        return fields


###############################################################################
#                             Fetch zuul builds                               #
###############################################################################
def parse_version(zuul_version_txt):
    """Parse the zuul version returned by the different services:

    >>> parse_version("4.6.0-1.el7")
    StrictVersion ('4.6')
    >>> parse_version("4.10.2.dev6 22f04be1")
    StrictVersion ('4.10.2')
    >>> parse_version("4.10.2.dev6 22f04be1") > parse_version("4.6.0-1.el7")
    True
    >>> parse_version("4.6.0-1.el7") > parse_version("4.7.0")
    False
    """
    if not zuul_version_txt:
        return
    zuul_version = zuul_version_txt
    # drop rpm package suffix
    zuul_version = zuul_version.split("-")[0]
    # drop pip package suffix
    zuul_version = zuul_version.split(".dev")[0]
    try:
        return s_version(zuul_version)
    except Exception:
        raise ValueError("Invalid zuul version: %s" % zuul_version_txt)


def _zuul_complete_available(zuul_url, insecure):
    """Return additional parameter for zuul url

    When Zuul version is newer that 4.7.0, return additional
    parameter.
    """
    url = zuul_url + "/status"
    zuul_status = requests_get_json(url, verify=insecure)
    zuul_version = parse_version(zuul_status.get("zuul_version"))
    if zuul_version and zuul_version >= s_version("4.7.0"):
        return "&complete=true"


def get_builds(zuul_url, insecure, job_name):
    """Yield builds dictionary."""
    extra = ("&job_name=" + job_name) if job_name else ""
    pos, size = 0, 100
    zuul_url = zuul_url.rstrip("/")
    zuul_complete = _zuul_complete_available(zuul_url, insecure)
    if zuul_complete:
        extra = extra + zuul_complete
    base_url = zuul_url + "/builds?limit=" + str(size) + extra

    known_builds = set()
    while True:
        url = base_url + "&skip=" + str(pos)
        logging.info("Getting job results %s", url)
        jobs_result = requests_get_json(url, verify=insecure)

        if not jobs_result:
            return iter([])

        for job in jobs_result:
            # It is important here to check we didn't yield builds twice,
            # as this can happen when using skip if new build get reported
            # between the two requests.
            if job["uuid"] not in known_builds:
                yield job
            known_builds.add(job["uuid"])
            pos += 1


def filter_available_jobs(zuul_api_url, job_names, insecure):
    filtered_jobs = []
    url = zuul_api_url + "/jobs"
    logging.info("Getting available jobs %s", url)
    available_jobs = requests_get_json(url, verify=insecure)
    if not available_jobs:
        return []
    for defined_job in job_names:
        for job in available_jobs:
            if defined_job == job.get('name'):
                filtered_jobs.append(defined_job)
    return filtered_jobs


def get_last_job_results(zuul_url, insecure, max_builds, build_cache,
                         job_name):
    """Yield builds until we find the last uuid."""
    count = 0
    for build in get_builds(zuul_url, insecure, job_name):
        count += 1
        if count > int(max_builds):
            break
        if build_cache.contains(build["_id"]):
            continue
        build_cache.add(build["_id"])
        yield build


###############################################################################
#                              Log scraper                                    #
###############################################################################
def save_build_info(directory, build):
    with open("%s/buildinfo" % directory, "w") as text_file:
        yaml.dump(build, text_file)


def load_config(config_path):
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except PermissionError:
        logging.critical("Can not open config file %s" % config_path)
    except FileNotFoundError:
        logging.critical("Can not find provided config file! %s" % config_path)
    except Exception as e:
        logging.critical("Exception occurred on reading config file %s" % e)


def get_files_to_check(config):
    files = []
    if not config:
        logging.critical("Can not get info from config file")
        return

    for f in config.get("files", []):
        files.append(f['name'])

    if files:
        files = files + [l_file + '.gz' for l_file in files]

    return files


def download_file(url, directory, insecure=False):
    logging.debug("Started fetching %s" % url)
    filename = url.split("/")[-1]
    try:
        response = requests.get(url, verify=insecure, stream=True)
        if response.status_code == 200:
            if directory:
                with open("%s/%s" % (directory, filename), 'wb') as f:
                    for txt in response.iter_content(1024):
                        f.write(txt)
            return filename
    except requests.exceptions.ContentDecodingError:
        logging.critical("Can not decode content from %s" % url)


def is_job_with_result(job_result):
    results_with_status = ['failure', 'success']
    if (job_result["result"].lower() in results_with_status and
            job_result["log_url"]):
        return True


def create_custom_result(job_result, directory):
    try:
        with open("%s/custom-job-results.txt" % directory, "w") as f:
            f.write("%s | %s" % (job_result["end_time"], job_result["result"]))
        with open("%s/inventory.yaml" % directory, "w") as f:
            f.write(job_result["result"])
    except Exception as e:
        logging.critical("Can not write custom-job-results.txt %s" % e)


def cleanup_logs_to_check(config_files, log_url, insecure):
    """Check if on logserver exists main directory"""
    filtered_config_files = []
    existing_dirs = []
    directories = set()
    # get unique directories
    for config_file in config_files:
        directories.add(os.path.dirname(config_file))

    # check if directory exists on logserver
    for directory in directories:
        # job-results.txt doesn't contain dirname, so it will be an empty value
        if not directory:
            continue
        url = '%s%s' % (log_url, directory)
        response = requests.head(url, verify=insecure)
        if response.ok:
            existing_dirs.append(directory)

    # remove directories, that does not exists on log server
    for config_file in config_files:
        if ('/' not in config_file or os.path.dirname(config_file) in
                existing_dirs):
            filtered_config_files.append(config_file)
    return filtered_config_files


def check_specified_files(job_result, insecure, directory=None):
    """Return list of specified files if they exists on logserver."""

    args = job_result.get("build_args")
    config = job_result.get('config_file')

    check_files = get_files_to_check(config)
    if not check_files:
        logging.warning("No file provided to check!")
        return

    filtered_files = cleanup_logs_to_check(check_files, job_result["log_url"],
                                           insecure)

    logging.debug("After filtering, files to check are: %s for job "
                  "result %s" % (filtered_files, job_result['uuid']))

    build_log_urls = [
        urljoin(job_result["log_url"], s) for s in filtered_files
    ]

    results = []
    pool = ThreadPoolExecutor(max_workers=args.workers)
    for page in pool.map(download_file, build_log_urls,
                         itertools.repeat(directory),
                         itertools.repeat(insecure)):
        if page:
            results.append(page)

    return results


def setup_logging(debug):
    if debug:
        logging.basicConfig(format="%(asctime)s %(message)s",
                            level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.debug("Zuul Job Scraper is starting...")


def run_build(build):
    """Submit job information into log processing system.

    If CI job result is different than 'SUSSESS' or 'FAILURE' and download
    argument is set, it will create special file: 'custom-job-results.txt'
    that will contain:
    job_result["end_time"] | job_result["result"]
    """

    args = build.get("build_args")
    config_file = build.get("config_file")

    logging.info(
        "Processing logs for %s | %s | %s | %s",
        build["job_name"],
        build["end_time"],
        build["result"],
        build["uuid"],
    )

    if args.download:
        logging.debug("Started fetching build logs")
        directory = "%s/%s" % (args.directory, build["uuid"])
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
        except PermissionError:
            logging.critical("Can not create directory %s" % directory)
        except Exception as e:
            logging.critical("Exception occurred %s on creating dir %s" % (
                e, directory))

        if is_job_with_result(build):
            check_specified_files(build, args.insecure, directory)
        else:
            # NOTE: if build result is "ABORTED" or "NODE_FAILURE, there is
            # no any job result files to parse, but we would like to have that
            # knowledge, so it will create own job-results.txt file that
            # contains:
            # build["end_time"] | build["result"]
            logging.info("There is no log url for the build %s, so no file can"
                         " be downloaded. Creating custom job-results.txt " %
                         build["uuid"])
            create_custom_result(build, directory)

        save_build_info(directory, build)
    else:
        # NOTE: As it was earlier, logs that contains status other than
        # "SUCCESS" or "FAILURE" will be parsed by Gearman service.
        logging.debug("Parsing content for gearman service")
        results = dict(files=[], jobs=[], invocation={})
        files = check_specified_files(build, args.insecure)

        results["files"] = files
        lmc = LogMatcher(
            args.gearman_server,
            args.gearman_port,
            build["result"],
            build["log_url"],
            {},
            config_file
        )

        lmc.submitJobs("push-log", results["files"], build)


def check_connection(logstash_url):
    """Return True when Logstash service is reachable

    Check if service is up before pushing results.
    """
    host, port = logstash_url.split(':')
    logging.debug("Checking connection to %s on port %s" % (host, port))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


def run_scraping(args, zuul_api_url, job_name=None, monitoring=None):
    """Get latest job results and push them into log processing service.

    On the end, write build_cache file, so in the future
    script will not push duplicate build.
    """
    config = Config(args, zuul_api_url, job_name)

    builds = []
    for build in get_last_job_results(zuul_api_url, args.insecure,
                                      args.max_skipped, config.build_cache,
                                      job_name):
        logging.debug("Working on build %s" % build['uuid'])
        # add missing information
        build["tenant"] = config.tenant
        build["build_args"] = args
        build["config_file"] = config.config_file
        builds.append(build)

    logging.info("Processing %d builds", len(builds))

    if args.logstash_url and not check_connection(args.logstash_url):
        logging.critical("Can not connect to logstash %s. "
                         "Is it up?" % args.logstash_url)
        return

    if builds:
        pool = multiprocessing.Pool(int(args.workers))
        try:
            r = pool.map_async(run_build, builds)
            r.wait()
        finally:
            config.save()

    if monitoring:
        monitoring.parse_metrics(builds)


def run(args, monitoring):
    if args.ca_file:
        validate_ca = args.ca_file
    else:
        validate_ca = args.insecure

    for zuul_api_url in args.zuul_api_url:

        if not is_zuul_host_up(zuul_api_url, validate_ca):
            logging.warning("Zuul %s seems not to be reachable. "
                            "Postponing pulling logs..." % zuul_api_url)
            continue

        if args.job_name:
            jobs_in_zuul = filter_available_jobs(zuul_api_url, args.job_name,
                                                 validate_ca)
            logging.info("Available jobs for %s are %s" % (
                zuul_api_url, jobs_in_zuul))
            for job_name in jobs_in_zuul:
                logging.info("Starting checking logs for job %s in %s" % (
                    job_name, zuul_api_url))
                run_scraping(args, zuul_api_url, job_name, monitoring)
        else:
            logging.info("Starting checking logs for %s" % zuul_api_url)
            run_scraping(args, zuul_api_url, monitoring=monitoring)

    logging.info("Finished pulling logs!")


def main():
    app_args = get_arguments()
    config_args = get_config_args(app_args.config)
    args = parse_args(app_args, config_args)

    setup_logging(args.debug)

    monitoring = None
    if args.monitoring_port:
        monitoring = Monitoring()
        start_http_server(args.monitoring_port)

    if args.download and args.gearman_server and args.gearman_port:
        logging.critical("Can not use logscraper to send logs to gearman "
                         "and download logs. Choose one")
        sys.exit(1)
    while True:
        run(args, monitoring)

        if not args.follow:
            break
        time.sleep(args.wait_time)


if __name__ == "__main__":
    main()
