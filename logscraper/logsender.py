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
import collections
import copy
import datetime
import itertools
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
    parser.add_argument("--ignore-es-status", help="Ignore Opensearch bulk",
                        action="store_true")
    parser.add_argument("--debug", help="Be more verbose",
                        action="store_true")
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


def read_text_file(file_path):
    with open(file_path, 'r') as f:
        return f.readlines()


def get_inventory_info(directory):
    try:
        build_inventory = read_yaml_file("%s/inventory.yaml" % directory)
        return build_inventory['all']['vars']['zuul']
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


def remove_directory(dir_path):
    logging.debug("Removing directory %s" % dir_path)
    shutil.rmtree(dir_path)


def makeFields(build_details, buildinfo):
    fields = {}
    fields["build_node"] = "zuul-executor"
    # NOTE: that field is added later
    # fields["filename"] = build_file
    fields["build_name"] = buildinfo.get("job_name")
    fields["build_status"] = buildinfo["result"]
    fields["project"] = buildinfo.get('project')
    fields["voting"] = int(build_details["voting"])
    fields["build_set"] = build_details["buildset"]
    fields["build_queue"] = build_details["pipeline"]
    fields["build_ref"] = buildinfo.get("ref")
    fields["build_branch"] = buildinfo.get("branch")
    fields["build_change"] = buildinfo.get("change")
    fields["build_patchset"] = buildinfo.get("patchset")
    fields["build_newrev"] = build_details.get("newrev", "UNKNOWN")
    fields["build_uuid"] = buildinfo.get("uuid")
    fields["node_provider"] = "local"
    fields["log_url"] = buildinfo.get("log_url")
    fields["tenant"] = buildinfo.get("tenant")
    if "executor" in build_details and "hostname" in build_details["executor"]:
        fields["zuul_executor"] = build_details["executor"]["hostname"]
    return fields


def send_bulk(es_client, request, workers, ignore_es_status, chunk_size):
    """Send bulk request to Opensearch"""
    try:
        if ignore_es_status:
            return collections.deque(helpers.parallel_bulk(
                es_client, request, thread_count=workers,
                chunk_size=chunk_size))

        # NOTE: To see bulk update status, we can use:
        # https://elasticsearch-py.readthedocs.io/en/7.10.0/helpers.html#example
        for success, info in helpers.parallel_bulk(es_client, request,
                                                   thread_count=workers,
                                                   chunk_size=chunk_size):
            if not success:
                logging.error("Chunk was not send to Opensearch %s" % info)
                return
        # If all bulk updates are fine, return True
        return True
    except Exception as e:
        logging.critical("Exception occured on pushing data to "
                         "Opensearch %s" % e)
        return


def get_timestamp(line):
    try:
        timestamp_search = re.search(r'[-0-9]{10}\s+[0-9.:]{12}', line)
        timestamp = (timestamp_search.group() if timestamp_search else
                     datetime.datetime.utcnow().isoformat())
        # NOTE: On python 3.6, it should be:
        # datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
        # Ci-log-processing is using container with Python 3.8, where
        # fromisoformat attribute is available.
        return datetime.datetime.fromisoformat(timestamp).isoformat()
    except Exception as e:
        logging.critical("Exception occured on parsing timestamp %s" % e)


def get_message(line):
    try:
        return line.split("|", 1)[1].replace('\n', '')
    except IndexError:
        return line.replace('\n', '')


def send_to_es(build_file, es_fields, es_client, index, workers,
               ignore_es_status, chunk_size, doc_type):
    """Send document to the Opensearch"""
    request = []
    logging.info("Working on %s" % build_file)
    file_content = read_text_file(build_file)
    for line in file_content:
        fields = copy.deepcopy(es_fields)
        fields["@timestamp"] = get_timestamp(line)

        message = get_message(line)
        if not message:
            continue
        fields["message"] = message

        doc = {"_index": index, "_type": doc_type, "_source": fields}
        request.append(doc)
    return send_bulk(es_client, request, workers, ignore_es_status, chunk_size)


def get_build_information(build_dir):
    """Return dictionary with build information"""
    build_inventory = get_inventory_info(build_dir)
    buildinfo = get_build_info(build_dir)
    return makeFields(build_inventory, buildinfo)


def send(ready_directory, args, directory, index, workers):
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
        es_fields["filename"] = build_file
        send_status = send_to_es("%s/%s" % (build_dir, build_file),
                                 es_fields, es_client, index, workers,
                                 args.ignore_es_status, args.chunk_size,
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


def prepare_and_send(ready_directories, args):
    """Prepare information to send and Opensearch"""

    directory = args.directory
    workers = args.workers
    index = get_index(args)
    if not index:
        logging.critical("Can not continue without created indices")
        sys.exit(1)

    with multiprocessing.Pool(processes=args.workers) as pool:
        pool.starmap(send, zip(
            list(ready_directories.items()),
            itertools.repeat(args),
            itertools.repeat(directory), itertools.repeat(index),
            itertools.repeat(workers)))


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
        time.sleep(60)


if __name__ == "__main__":
    main()
