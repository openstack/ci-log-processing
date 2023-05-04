#!/usr/bin/env python3
#
# Copyright (C) 2022 Red Hat
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
The goal is to get content from build uuid directory and send to Opensearch

[ CLI ] -> [ Log directory ] -> [ Zuul inventory ] -> [ Send logs to ES ]
"""

import argparse
import configparser
import copy
import datetime
import itertools
import json
import logging
import multiprocessing
import os
import re
import shutil
import sys
import time

from ast import literal_eval
from opensearchpy import exceptions as opensearch_exceptions
from opensearchpy import helpers
from opensearchpy import OpenSearch
from ruamel.yaml import YAML
from subunit2sql.read_subunit import ReadSubunit


###############################################################################
#                                    CLI                                      #
###############################################################################
def get_arguments():
    parser = argparse.ArgumentParser(description="Check log directories "
                                     "and push to the Opensearch service")
    parser.add_argument("--config", help="Logscraper config file",
                        required=True)
    parser.add_argument("--file-list", help="File list to download")
    parser.add_argument("--directory",
                        help="Directory, where the logs will "
                        "be stored.")
    parser.add_argument("--host", help="Opensearch host")
    parser.add_argument("--port", help="Opensearch port", type=int)
    parser.add_argument("--username", help="Opensearch username")
    parser.add_argument("--password", help="Opensearch user password")
    parser.add_argument("--index-prefix", help="Prefix for the index.",
                        default="logstash-")
    parser.add_argument("--index", help="Opensearch index")
    parser.add_argument("--performance-index-prefix", help="Prefix for the"
                        "index that will proceed performance.json file"
                        "NOTE: it will use same opensearch user credentials",
                        default="performance-")
    parser.add_argument("--subunit-index-prefix", help="Prefix for the"
                        "index that will proceed testrepository.subunit file"
                        "NOTE: it will use same opensearch user credentials",
                        default="subunit-")
    parser.add_argument("--insecure", help="Skip validating SSL cert",
                        action="store_true")
    parser.add_argument("--follow", help="Keep sending CI logs",
                        action="store_true")
    parser.add_argument("--workers", help="Worker processes for logsender",
                        type=int)
    parser.add_argument("--chunk-size", help="The bulk chunk size", type=int)
    parser.add_argument("--skip-debug", help="Skip messages that contain: "
                        "DEBUG word",
                        action="store_true")
    parser.add_argument("--keep", help="Do not remove log directory after",
                        action="store_true")
    parser.add_argument("--debug", help="Be more verbose",
                        action="store_true")
    parser.add_argument("--wait-time", help="Pause time for the next "
                        "iteration", type=int)
    parser.add_argument("--ca-file", help="Provide custom CA certificate")
    args = parser.parse_args()

    defaults = {}
    if args.config:
        config = configparser.ConfigParser(delimiters=('=', ':'))
        config.read(args.config)
        defaults = config["DEFAULT"]
        defaults = dict(defaults)

    parsed_values = {}
    for k, v in defaults.items():
        if not v:
            continue
        try:
            parsed_values[k] = literal_eval(v)
        except (SyntaxError, ValueError):
            pass

    parser.set_defaults(**defaults)
    parser.set_defaults(**parsed_values)
    args = parser.parse_args()

    return args


###############################################################################
#                              Log sender                                     #
###############################################################################
def _is_file_not_empty(file_path):
    """Return True when file is not empty"""
    # NOTE: we can assume, that when file exists, all
    # content have been downloaded to the directory.
    return os.path.getsize(file_path) > 0


def check_info_files(root, files):
    return True if (
        'buildinfo' in files and 'inventory.yaml' in files and
        _is_file_not_empty("%s/buildinfo" % root) and
        _is_file_not_empty("%s/inventory.yaml" % root)
    ) else False


def read_yaml_file(file_path):
    # FIXME: In logscraper yaml.dump seems not to be dumping correctly the
    # dictionary, so ruamel lib is needed.
    yaml = YAML()
    with open(file_path, 'r') as f:
        return yaml.load(f)


def get_inventory_info(directory):
    try:
        return read_yaml_file("%s/inventory.yaml" % directory)
    except FileNotFoundError:
        logging.warning("Can not find inventory.yaml in build "
                        "dir %s" % directory)


def get_build_info(directory):
    return read_yaml_file("%s/buildinfo" % directory)


def get_ready_directories(directory):
    """Returns a directory with list of files

    That directories should have a 'buildinfo' and 'inventory.yaml' file
    which are not empty.
    """

    log_files = {}
    for root, _, files in os.walk(directory):
        build_uuid = root.split('/')[-1]
        if check_info_files(root, files):
            files.remove("buildinfo")
            files.remove("inventory.yaml")
            log_files[build_uuid] = files
        else:
            logging.info("Skipping build with uuid %s. Probably all files "
                         "are not downloaded yet." % build_uuid)
            continue

    return log_files


def get_hosts_id(build_inventory):
    hosts_id = []
    hosts_region = []
    if 'all' not in build_inventory:
        return hosts_id, hosts_region

    for _, host_info in build_inventory['all']['hosts'].items():
        if 'host_id' in host_info.get('nodepool', {}):
            hosts_id.append(host_info['nodepool']['host_id'])
            hosts_region.append("%s-%s" % (host_info['nodepool']['cloud'],
                                           host_info['nodepool']['region']))
    return hosts_id, list(set(hosts_region))


def remove_directory(dir_path):
    logging.debug("Removing directory %s" % dir_path)
    shutil.rmtree(dir_path)


def makeFields(build_inventory, buildinfo):
    fields = {}

    if 'all' in build_inventory:
        # if builds is SUCCESS or FAILURE, it will get inventory with content
        build_details = build_inventory['all']['vars']['zuul']
    else:
        # if custom build provided, inventory.yaml file does not have info
        build_details = {}

    fields["build_node"] = "zuul-executor"
    fields["build_name"] = buildinfo.get("job_name")
    fields["build_status"] = buildinfo["result"]
    fields["project"] = buildinfo.get('project')
    fields["voting"] = int(build_details.get("voting", 2))
    fields["build_set"] = str(build_details.get("buildset", "NONE"))
    fields["build_queue"] = build_details.get("pipeline", "NONE")
    fields["build_ref"] = buildinfo.get("ref")
    fields["build_branch"] = buildinfo.get("branch")
    fields["build_change"] = buildinfo.get("change")
    fields["build_patchset"] = buildinfo.get("patchset")
    fields["build_newrev"] = build_details.get("newrev", "UNKNOWN")
    fields["build_uuid"] = str(buildinfo.get("uuid"))
    fields["node_provider"] = "local"
    fields["log_url"] = buildinfo.get("log_url")
    fields["tenant"] = buildinfo.get("tenant")
    fields["hosts_id"], fields["hosts_region"] = get_hosts_id(build_inventory)
    if "executor" in build_details and "hostname" in build_details["executor"]:
        fields["zuul_executor"] = build_details["executor"]["hostname"]
    return fields


def makeJsonFields(content):
    content = json.loads(content)

    fields = {}
    fields['hostname'] = content['report']['hostname']

    for service in content.get('services', []):
        key_name = "service_%s_memorycurrent" % service.get('service')
        current_mem = service.get('MemoryCurrent', 0)
        if (not isinstance(current_mem, int) or
                current_mem > 9223372036854775807):
            logging.debug("Incorrect service %s memory consumption %s."
                          "Setting value to 0" % (service, current_mem))
            current_mem = 0

        fields[key_name] = current_mem

    for db in content.get('db', []):
        key_name = "db_%s_%s" % (db.get('db'), db.get('op').lower())
        db_count = db.get('count', 0)
        if not isinstance(db_count, int):
            logging.debug("Incorrect DB %s count %s. Setting value to 0" % (
                db.get('db'), db_count))
            continue

        fields[key_name] = db_count

    for api_call in content.get('api', []):
        name = api_call.get('service')
        for api_type, count in api_call.items():
            if api_type == 'service' or api_type == 'log':
                continue

            if not isinstance(count, int):
                logging.debug("Incorrect api call for %s with value: %s" % (
                    name, count))
                continue

            key_name = "api_%s_%s" % (name, api_type.lower())
            fields[key_name] = count

    return fields


timestamp_patterns = [
    # 2022-03-25T17:40:37.220547Z
    (re.compile(r"(\S+)"), "%Y-%m-%dT%H:%M:%S.%fZ"),
    # 2022-02-28 09:44:58.839036
    (re.compile(r"(\S+ \S+)"), "%Y-%m-%d %H:%M:%S.%f"),
    # Mar 31 04:50:23.795709
    (re.compile(r"(\S+ [0-9]{2}\s[0-9:.]{14})"), "%b %d %H:%M:%S.%f"),
    # Mar 25 17:40:37 : TODO(tdecacqu): fix the log file format
    # because guessing the YEAR is error prone
    (re.compile(r"(\S+ \S+ \S+)"), "%b %d %H:%M:%S"),
    # 2022-03-23T11:46:49+0000 - isoformat
    (re.compile(r"([0-9-T:]{19})"), "%Y-%m-%dT%H:%M:%S"),
    # Friday 25 February 2022 09:27:51 +0000 - ansible
    (re.compile(r"(\S+ [0-9]{2} \S+ [0-9: ]{14})"), "%A %d %B %Y %H:%M:%S")
]


def try_timestamp(regex, fmt, line):
    try:
        if match := regex.match(line):
            timestamp_string = match.groups()[0]
            date = datetime.datetime.strptime(timestamp_string, fmt)
            if date.year == 1900:
                # Handle missing year
                date = date.replace(year=datetime.date.today().year)
            return date
    except ValueError:
        pass


def get_timestamp(line):
    for (regex, fmt) in timestamp_patterns:
        if res := try_timestamp(regex, fmt, line):
            return res


def get_message(line):
    try:
        return line.split("|", 1)[1].replace('\n', '').lstrip()
    except IndexError:
        return line.replace('\n', '')


def open_file(path):
    return open(path, 'r')


def get_file_info(config, build_file):
    yaml = YAML()
    with open_file(config) as f:
        config_files = yaml.load(f)
        for f in config_files["files"]:
            file_name = os.path.basename(f["name"])
            if build_file.endswith(file_name):
                return f["name"], f.get('tags', []) + [file_name]
    return os.path.basename(build_file), [os.path.basename(build_file)]


def json_iter(build_file):
    with open_file(build_file) as f:
        parse_file = json.load(f)
        if 'report' in parse_file and 'timestamp' in parse_file['report']:
            ts = get_timestamp(parse_file['report']['timestamp'])
        else:
            ts = datetime.datetime.utcnow()
        yield (ts, json.dumps(parse_file))


def logline_iter(build_file, skip_debug):
    last_known_timestamp = None
    with open_file(build_file) as f:
        while True:
            line = f.readline()
            if (last_known_timestamp is None and line.startswith(
                    "-- Logs begin at ")) or (skip_debug and
                                              'DEBUG' in line):
                continue
            if line:
                ts = get_timestamp(line)
                if ts:
                    last_known_timestamp = ts
                elif not last_known_timestamp and not ts:
                    ts = datetime.datetime.utcnow()
                else:
                    ts = last_known_timestamp
                yield (ts, line)
            else:
                break


def doc_iter(inner, index, es_fields):
    for (ts, line) in inner:
        fields = copy.deepcopy(es_fields)
        fields["@timestamp"] = ts.isoformat()

        message = get_message(line)
        if not message:
            continue

        fields["message"] = message

        doc = {"_index": index, "_source": fields}
        yield doc


def subunit_iter(file_name, index, es_fields):

    try:
        with open(file_name) as f:
            subunit = ReadSubunit(f)
            parsed_subunit = subunit.get_results()
    except Exception as e:
        if 'Non subunit content' in e.args:
            logging.info("The %s file does not contain any subunit "
                         "content. Skipping..." % file_name)
            return

    if not parsed_subunit:
        logging.info("Parsed subunit file is empty. Skipping...")
        return

    for test_name in parsed_subunit:
        if test_name == "run_time":
            continue

        start_time = parsed_subunit[test_name]['start_time']
        end_time = parsed_subunit[test_name]['end_time']
        test_duration = end_time - start_time
        test_duration = str(test_duration.seconds) + "." + \
            str(test_duration.microseconds)

        fields = copy.deepcopy(es_fields)

        fields["test_name"] = test_name
        fields["test_duration"] = float(test_duration)
        fields["test_status"] = parsed_subunit[test_name]["status"]
        fields["@timestamp"] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')

        yield {"_index": index, "_source": fields}


def send_to_es(build_file, es_fields, es_client, index, chunk_size,
               skip_debug, perf_index, subunit_index):
    """Send document to the Opensearch"""
    logging.info("Working on %s" % build_file)
    try:
        # NOTE: The performance.json file will be only pushed into
        # --performance-index-prefix index.
        if build_file.endswith('performance.json') and perf_index:
            working_doc = json_iter(build_file)
            working_doc, working_doc_copy = itertools.tee(working_doc)
            for (_, json_doc) in working_doc_copy:
                performance_fields = makeJsonFields(json_doc)
                es_fields.update(performance_fields)
            docs = doc_iter(working_doc, perf_index, es_fields)
            return helpers.bulk(es_client, docs, chunk_size=chunk_size)

        # NOTE: The parsed testrepository.subunit file will be only pushed
        # to the --subunit-index-prefix index.
        if build_file.endswith('.subunit'):
            docs = subunit_iter(build_file, subunit_index, es_fields)
            return helpers.bulk(es_client, docs, chunk_size=chunk_size)

        docs = doc_iter(logline_iter(build_file, skip_debug), index, es_fields)
        return helpers.bulk(es_client, docs, chunk_size=chunk_size)
    except opensearch_exceptions.TransportError as e:
        logging.critical("Can not send message to Opensearch. Error: %s" % e)
    except Exception as e:
        logging.critical("An error occurred on sending message to "
                         "Opensearch %s" % e)


def get_build_information(build_dir):
    """Return dictionary with build information"""
    build_inventory = get_inventory_info(build_dir)
    buildinfo = get_build_info(build_dir)
    return makeFields(build_inventory, buildinfo)


def send(ready_directory, args, directory, index, perf_index, subunit_index):
    """Gen Opensearch fields and send"""
    # NOTE: each process should have own Opensearch session,
    # due error: TypeError: cannot pickle 'SSLSocket' object -
    # SSLSocket cannot be serialized.
    es_client = get_es_client(args)

    build_uuid, build_files = ready_directory
    build_dir = "%s/%s" % (directory, build_uuid)
    es_fields = get_build_information(build_dir)
    if not es_fields:
        return

    send_status = False
    logging.debug("Provided build info %s" % es_fields)

    for build_file in build_files:
        # NOTE(dpawlik): In some job results, there is a file
        # testrepository.subunit.gz that does not contain anything, but it
        # raise an error on parsing it, so later the logsender is not removing
        # the CI job directory, so the job results is sended many times until
        # the file is not removed.
        if build_file == 'testrepository.subunit.gz':
            logging.warning("The file %s is marked as broken. "
                            "Skipping..." % build_file)
            continue

        # NOTE(dpawlik): Sometimes file might be empty, but other files
        # in the build dir are fine, and the dir is keeped because of it.
        # We don't want to skip removing dir, when one of the file was empty.
        if not _is_file_not_empty("%s/%s" % (build_dir, build_file)):
            continue

        fields = copy.deepcopy(es_fields)
        file_name, file_tags = get_file_info(args.file_list, build_file)
        fields["filename"] = build_file
        fields["log_url"] = (fields["log_url"] + file_name if fields[
            "log_url"] else file_name)
        fields['tags'] = file_tags
        send_status = send_to_es("%s/%s" % (build_dir, build_file),
                                 fields, es_client, index, args.chunk_size,
                                 args.skip_debug, perf_index, subunit_index)

    if args.keep:
        logging.info("Keeping file %s" % build_dir)
        return

    if send_status:
        remove_directory(build_dir)
    else:
        logging.warning("The document was not send. Keeping log file")


def get_index(args):
    indexes = [None, None, None]
    perf_index = None
    subunit_index = None
    index = args.index

    if not index:
        index = args.index_prefix + \
            datetime.datetime.today().strftime('%Y.%m.%d')

    if create_indices(index, args):
        indexes[0] = index

    if args.performance_index_prefix:
        perf_index = args.performance_index_prefix + \
            datetime.datetime.today().strftime('%Y.%m.%d')

        if create_indices(perf_index, args):
            indexes[1] = perf_index

    if args.subunit_index_prefix:
        subunit_index = args.subunit_index_prefix + \
               datetime.datetime.today().strftime('%Y.%m.%d')
        if create_indices(subunit_index, args):
            indexes[2] = subunit_index

    return tuple(indexes)


def create_indices(index, args):
    es_client = get_es_client(args)
    try:
        logging.info("Creating index %s" % index)
        return es_client.indices.create(index)
    except opensearch_exceptions.AuthorizationException:
        logging.critical("You need to have permissions to create an index. "
                         "Probably you need to add [indices:admin/create] or "
                         "'create_index' permission to the index permissions "
                         "inside your role.")
    except opensearch_exceptions.RequestError as e:
        # NOTE(dpawlik) Use same functionality as Logstash do, so it
        # will not require any additional permissions set to the default
        # logstash role.
        if e.error.lower() == 'resource_already_exists_exception':
            logging.debug("The %s indices already exists, continue" % index)
            return True
    except opensearch_exceptions.TransportError as e:
        # NOTE(dpawlik) To avoid error: "TOO_MANY_REQUESTS/12/disk usage
        # exceeded flood-stage watermark", let's wait some time before
        # continue.
        if 'too_many_requests' in e.error.lower():
            logging.warning("Cluster is probably overloaded/flooded. "
                            "Logsender will wait some time, then continue."
                            "Exception details: %s" % e)
            time.sleep(120)
            return True


def prepare_and_send(ready_directories, args):
    """Prepare information to send and Opensearch"""

    directory = args.directory
    index, perf_index, subunit_index = get_index(args)
    if not index:
        logging.critical("Can not continue without created indices")
        sys.exit(1)

    with multiprocessing.Pool(processes=args.workers) as pool:
        pool.starmap_async(send, zip(
            list(ready_directories.items()),
            itertools.repeat(args),
            itertools.repeat(directory), itertools.repeat(index),
            itertools.repeat(perf_index),
            itertools.repeat(subunit_index))).wait()


def setup_logging(debug):
    if debug:
        logging.basicConfig(format="%(asctime)s %(message)s",
                            level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.debug("Log sender is starting...")


def get_es_client(args):
    es_creds = {
            "host": args.host,
            "port": args.port,
            "http_compress": True,
            "use_ssl": True,
            "verify_certs": not args.insecure,
            "ssl_show_warn": not args.insecure,
        }

    if args.username and args.password:
        es_creds["http_auth"] = "%s:%s" % (args.username, args.password)

    if args.ca_file:
        es_creds['ca_certs'] = args.ca_file

    es_client = OpenSearch([es_creds], timeout=60)
    logging.info("Connected to Opensearch: %s" % es_client.info())
    return es_client


def run(args):
    ready_directories = get_ready_directories(args.directory)
    logging.info("Found %s builds to send to Opensearch service" % len(
        ready_directories))
    prepare_and_send(ready_directories, args)
    logging.info("Finished pushing logs!")


def main():
    args = get_arguments()
    setup_logging(args.debug)
    while True:
        run(args)
        if not args.follow:
            break
        time.sleep(args.wait_time)


if __name__ == "__main__":
    main()
