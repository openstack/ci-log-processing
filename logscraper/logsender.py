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

from opensearchpy import exceptions as opensearch_exceptions
from opensearchpy import helpers
from opensearchpy import OpenSearch
from ruamel.yaml import YAML


###############################################################################
#                                    CLI                                      #
###############################################################################
def get_arguments():
    parser = argparse.ArgumentParser(description="Check log directories "
                                     "and push to the Opensearch service")
    parser.add_argument("--config", help="Logscraper config file",
                        required=True)
    parser.add_argument("--directory",
                        help="Directory, where the logs will "
                        "be stored. Defaults to: /tmp/logscraper",
                        default="/tmp/logscraper")
    parser.add_argument("--host",
                        help="Opensearch host",
                        default='localhost')
    parser.add_argument("--port",
                        help="Opensearch port",
                        type=int,
                        default=9200)
    parser.add_argument("--username",
                        help="Opensearch username",
                        default='logstash')
    parser.add_argument("--password", help="Opensearch user password")
    parser.add_argument("--index-prefix", help="Prefix for the index. "
                        "Defaults to logstash-",
                        default='logstash-')
    parser.add_argument("--index",
                        help="Opensearch index. Defaults to: "
                        "<index-prefix>-YYYY-DD")
    parser.add_argument("--doc-type", help="Doc type information that will be"
                        "send to the Opensearch service",
                        default="_doc")
    parser.add_argument("--insecure",
                        help="Skip validating SSL cert",
                        action="store_false")
    parser.add_argument("--follow", help="Keep sending CI logs",
                        action="store_true")
    parser.add_argument("--workers", help="Worker processes for logsender",
                        type=int,
                        default=1)
    parser.add_argument("--chunk-size", help="The bulk chunk size",
                        type=int,
                        default=1500)
    parser.add_argument("--keep", help="Do not remove log directory after",
                        action="store_true")
    parser.add_argument("--debug", help="Be more verbose",
                        action="store_true")
    parser.add_argument("--wait-time", help="Pause time for the next "
                        "iteration",
                        type=int,
                        default=120)
    parser.add_argument("--ca-file", help="Provide custom CA certificate")
    args = parser.parse_args()
    return args


###############################################################################
#                              Log sender                                     #
###############################################################################
def _is_file_not_empty(file_path):
    """Return True when buildinfo file is not empty"""
    # NOTE: we can assume, that when file exists, all
    # content have been dowloaded to the directory.
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
                         "are not dowloaded yet." % build_uuid)
            continue

    return log_files


def get_hosts_id(build_inventory):
    hosts_id = []
    if 'all' not in build_inventory:
        return hosts_id

    for _, host_info in build_inventory['all']['hosts'].items():
        if 'host_id' in host_info.get('nodepool', {}):
            hosts_id.append(host_info['nodepool']['host_id'])
    return hosts_id


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
    fields["hosts_id"] = get_hosts_id(build_inventory)
    if "executor" in build_details and "hostname" in build_details["executor"]:
        fields["zuul_executor"] = build_details["executor"]["hostname"]
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


def logline_iter(build_file):
    last_known_timestamp = None
    with open_file(build_file) as f:
        while True:
            line = f.readline()
            if last_known_timestamp is None and line.startswith(
                    "-- Logs begin at "):
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


def doc_iter(inner, index, es_fields, doc_type):
    for (ts, line) in inner:
        fields = copy.deepcopy(es_fields)
        fields["@timestamp"] = ts.isoformat()

        message = get_message(line)
        if not message:
            continue
        fields["message"] = message

        doc = {"_index": index, "_type": doc_type, "_source": fields}
        yield doc


def send_to_es(build_file, es_fields, es_client, index, chunk_size, doc_type):
    """Send document to the Opensearch"""
    logging.info("Working on %s" % build_file)

    try:
        if build_file.endswith('performance.json'):
            docs = doc_iter(json_iter(build_file), index, es_fields, doc_type)
            return helpers.bulk(es_client, docs, chunk_size=chunk_size)

        docs = doc_iter(logline_iter(build_file), index, es_fields, doc_type)
        return helpers.bulk(es_client, docs, chunk_size=chunk_size)
    except opensearch_exceptions.TransportError as e:
        logging.critical("Can not send message to Opensearch. Error: %s" % e)
    except Exception as e:
        logging.critical("An error occured on sending message to "
                         "Opensearch %s" % e)


def get_build_information(build_dir):
    """Return dictionary with build information"""
    build_inventory = get_inventory_info(build_dir)
    buildinfo = get_build_info(build_dir)
    return makeFields(build_inventory, buildinfo)


def send(ready_directory, args, directory, index):
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
        fields = copy.deepcopy(es_fields)
        file_name, file_tags = get_file_info(args.config, build_file)
        fields["filename"] = build_file
        fields["log_url"] = (fields["log_url"] + file_name if fields[
            "log_url"] else file_name)
        fields['tags'] = file_tags
        send_status = send_to_es("%s/%s" % (build_dir, build_file),
                                 fields, es_client, index, args.chunk_size,
                                 args.doc_type)

    if args.keep:
        logging.info("Keeping file %s" % build_dir)
        return

    if send_status:
        remove_directory(build_dir)
    else:
        logging.warning("The document was not send. Keeping log file")


def get_index(args):
    index = args.index

    if not index:
        index = args.index_prefix + \
            datetime.datetime.today().strftime('%Y.%m.%d')

    if create_indices(index, args):
        return index


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
            logging.debug("The indices already exists, continue")
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
    index = get_index(args)
    if not index:
        logging.critical("Can not continue without created indices")
        sys.exit(1)

    with multiprocessing.Pool(processes=args.workers) as pool:
        pool.starmap(send, zip(
            list(ready_directories.items()),
            itertools.repeat(args),
            itertools.repeat(directory), itertools.repeat(index)))


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
            "verify_certs": args.insecure,
            "ssl_show_warn": args.insecure,
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
