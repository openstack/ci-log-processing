#!/usr/bin/env python3
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
import datetime
import json
import logging
import os
import requests
import sys
import time
import yaml

try:
    from logsender import get_es_client
except ImportError:
    from logscraper.logsender import get_es_client

from urllib.parse import urlparse

saved_objects_types = ('index-pattern', 'visualization', 'dashboard')

to_remove_keys = ['updated_at', 'version', 'migrationVersion']


def get_arguments():
    args_parser = argparse.ArgumentParser(
        description='Backup, restore or convert OpenSearch Dashboards '
        'saved objects.')
    args_parser.add_argument('action',
                             choices=['backup', 'restore', 'convert'],
                             metavar='N')
    args_parser.add_argument('--dashboard-api-url',
                             default='http://127.0.0.1:5601',
                             help='URL to access Opensearch Dashboards API. '
                             'NOTE: if the instance is AWS Opensearch service,'
                             ' url should end with /_dashboards.')
    args_parser.add_argument('--file', help='File to restore or convert from '
                             'ndjson to yaml')
    args_parser.add_argument('--username', default='',
                             help='Opensearch dashboards username')
    args_parser.add_argument('--password', default='', help='Opensearch '
                             'dasboards password')
    args_parser.add_argument('--backup-dir',
                             help='Dir where backups will be stored',
                             default=os.path.dirname(
                                 os.path.realpath(__file__)))
    args_parser.add_argument('--no-resolve-conflicts',
                             action="store_true",
                             help='Resolve conflicts by removing index '
                             'id reference in backup file')
    args_parser.add_argument('--overwrite-index-pattern',
                             action='store_true',
                             help='WARNING: Use that option if you want'
                             'to restart also index pattern')
    args_parser.add_argument('--insecure',
                             action='store_true',
                             help='Use that option to ignore if SSL cert '
                             'has been verified by root CA')
    args_parser.add_argument('--tenant',
                             help='Specify tenant for getting data.'
                             'NOTE: if none is set, it will take Global')
    args_parser.add_argument('--all-tenants',
                             action='store_true',
                             help='Bakup all objects in all '
                             'tenants. Works only with backup.'
                             'NOTE: requires param: --opensearch-api-url')
    args_parser.add_argument('--skip-verify-index',
                             action='store_true',
                             help='Skip checking that if object reference to '
                             'index pattern exists in the Opensearch '
                             'Dashboards.')
    args_parser.add_argument('--host',
                             help='Opensearch host. Need to ensure that '
                             'index pattern exists before restore')
    args_parser.add_argument('--port',
                             help='Opensearch port. Need to ensure that '
                             'index pattern exists before restore')
    args_parser.add_argument("--subpath", help="Add the subpath to the host. "
                             "That is useful, when the host url contains "
                             "a slash(/). For example: "
                             "'http://localhost/opensearch' then the subpath "
                             "is 'opensearch'.")
    args_parser.add_argument('--ca-file',
                             help='Custom CA certificate file')
    args_parser.add_argument("--debug", help="Print more information",
                             action="store_true")
    return args_parser.parse_args()


def convert_to_yaml(text, remove_references):
    # reparse text
    text_lines = []
    try:
        for line in text:
            if isinstance(line, dict):
                text_lines.append(line)
            else:
                text_lines.append(json.loads(line))
    except Exception as e:
        logging.critical(e)

    if remove_references:
        text_lines = remove_reference(text_lines)
    # Disable aliases/anchors
    yaml.Dumper.ignore_aliases = lambda *args: True
    return yaml.dump(text_lines)


def save_content_to_file(text, backup_file, remove_references=True):
    if isinstance(text, dict):
        text = str(text)
    text = convert_to_yaml(text, remove_references)
    with open(backup_file, 'a') as f:
        f.write(text)


def parse_dashboards_output(text):
    new_text = []
    try:
        text = [json.loads(text)]
    except json.decoder.JSONDecodeError:
        for text_obj in text.rsplit('\n'):
            n_text = json.loads(text_obj)
            new_text.append(n_text)
    return new_text if new_text else text


def check_if_empty(text):
    text = json.loads(text)
    if 'exportedCount' in text and text['exportedCount'] == 0:
        return True


def remove_obj_keys(ref):
    for k in to_remove_keys:
        ref.pop(k, None)
    return ref


def check_kibana_api(dashboard_api_url):
    """Check if OpenSearch Dashboards API is available"""
    r = requests.get(dashboard_api_url)
    if r.status_code != 404:
        return True


def remove_reference(text):
    new_text = []
    new_references = []
    for text_obj in text:
        if 'references' not in text_obj:
            new_text.append(text_obj)
            continue
        for ref in text_obj['references']:
            if (not ref.get('id').startswith('AX')
                    and len(ref.get('id')) != 20 and
                    remove_obj_keys(ref) not in new_references):
                new_references.append(remove_obj_keys(ref))
            text_obj['references'] = new_references
            new_text.append(text_obj)
    return new_text if new_text else text


def _ensure_index_exists(index_id, es_client):
    '''Ensure that index_id exists in the Opensearch dashboards'''
    body = {
        "_source": ["index-pattern.title"],
        "query": {
            "term": {
                "type": "index-pattern"
            }
        }
    }
    index_patterns = es_client.search(body=body)
    if 'hits' not in index_patterns:
        logging.critical("Can not get any index pattern list. "
                         "Check permissions!")
        return

    if not index_patterns['hits']['total']['value']:
        logging.info("Index pattern with id %s does not exists" % index_id)
        return

    for index in index_patterns['hits']['hits']:
        if index['_id'] == "index-pattern:%s" % index_id:
            index_name = index['_source']['index-pattern']['title']
            logging.info("Found index pattern. It belongs to %s" % index_name)
            # Ensure once again that the index pattern exists
            return es_client.indices.exists(index=index_name)


def filter_dashboards_object(dash_obj, overwrite_index, es_client,
                             skip_verify_index):
    """Filter OpenSearch Dasjboards object

    Filter objects that got index-pattern or have reference to unexisting
    index pattern
    """
    if not isinstance(dash_obj, dict):
        dash_obj = json.loads(dash_obj)

    # Restore index pattern when it does not exists. Otherwise restore it.
    if dash_obj.get('type') == 'index-pattern' and not skip_verify_index:
        is_index = _ensure_index_exists(dash_obj.get('id'), es_client)
        if is_index and not overwrite_index:
            return

    if 'references' in dash_obj and dash_obj.get('references', []):
        for ref in dash_obj['references']:
            if skip_verify_index:
                continue
            if ref.get('type') == 'index-pattern' and not skip_verify_index:
                is_index = _ensure_index_exists(ref.get('id'), es_client)
                if not is_index:
                    logging.critical("Can not restore that object due index "
                                     "pattern %s does not exists!" %
                                     ref.get('id'))
                    return
    return dash_obj


def make_request(url, username, password, text, tenant, cookies,
                 insecure=False, retry=True):
    r = None
    headers = {'osd-xsrf': 'true'}
    if tenant:
        headers['securitytenant'] = tenant

    try:
        r = requests.post(url,
                          auth=(username, password),
                          headers=headers,
                          files={'file': ('backup.ndjson', text)},
                          timeout=10,
                          verify=insecure)
    except requests.exceptions.ReadTimeout:
        if not retry:
            logging.warning("Importing failed. Retrying...")
            time.sleep(10)
            make_request(url, username, password, text, tenant, cookies,
                         insecure)

    if r is None:
        logging.critical("Can not reach Opensearch Dashboards service.")
        sys.exit(1)

    if r and "Please enter your credentials" in r.text:
        logging.warning("Please provide correct username and password")
        sys.exit(1)

    if r.status_code == 401:
        logging.warning("Unauthorized. Please provide username and password")

    return r


def _get_file_content(backup_file):
    if (backup_file.endswith('yml') or backup_file.endswith('yaml')):
        with open(backup_file) as f:
            text = yaml.safe_load(f)
    else:
        with open(backup_file) as f:
            text = f.readlines()
    return text


def _get_cookies(base_url, tenant, user, password):
    # NOTE: Helpful link:
    # https://github.com/Petes77/AWS-Native-SIEM/blob/main/source/lambda/deploy_es/index.py
    headers = {'Content-Type': 'application/json', 'osd-xsrf': 'true'}
    url = '%s/auth/login?security_tenant=%s' % (base_url, tenant)
    auth = {'username': user, 'password': password}
    response = requests.post(url, headers=headers, json=json.dumps(auth))
    return response.cookies


def setup_logging(debug):
    if debug:
        logging.basicConfig(format="%(asctime)s %(message)s",
                            level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)


def backup(dashboard_api_url, username, password, backup_dir, insecure,
           tenant):
    """Return string with newline-delimitered json """

    saved_objects = {}
    if not backup_dir:
        backup_dir = os.path.dirname(os.path.realpath(__file__))

    # Set the same time for all backups if previous exists
    b_time = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M")

    cookies = _get_cookies(dashboard_api_url, tenant, username, password)

    url = dashboard_api_url + '/api/saved_objects/_export'
    for obj_type in saved_objects_types:
        logging.debug("Working on %s" % obj_type)

        headers = {'Content-Type': 'application/json',
                   'osd-xsrf': 'true'}

        if tenant:
            headers['securitytenant'] = tenant

        payload = {'type': [obj_type], 'excludeExportDetails': True}

        r = requests.post(url,
                          auth=(username, password),
                          cookies=cookies,
                          headers=headers,
                          json=json.dumps(payload),
                          verify=insecure)

        if r.status_code == 400:
            # Print warning on missing object, but continue
            logging.warning("Can not backup object %s" % obj_type)
            continue
        else:
            r.raise_for_status()

        if not r.text:
            continue

        if tenant:
            backup_file = "%s/%s-%s.yaml" % (backup_dir, obj_type, tenant)
        else:
            backup_file = "%s/%s.yaml" % (backup_dir, obj_type)

        if os.path.exists(backup_file):
            backup_file = "%s-%s" % (backup_file, b_time)

        text = parse_dashboards_output(r.text)
        saved_objects[obj_type] = text
        save_content_to_file(text, backup_file)


def restore(dashboard_api_url, username, password, text, resolve_conflicts,
            insecure, tenant, overwrite_index, es_client, skip_verify_index):
    """Restore object to OpenSearch Dashboards."""

    cookies = _get_cookies(dashboard_api_url, tenant, username, password)
    url = dashboard_api_url + '/api/saved_objects/_import?overwrite=true'

    if not isinstance(text, list):
        text = [text]

    for dash_obj in text:
        logging.debug("Working on %s" % dash_obj)

        dash_obj = filter_dashboards_object(dash_obj, overwrite_index,
                                            es_client, skip_verify_index)
        if not dash_obj:
            continue

        if not isinstance(dash_obj, dict):
            # Ensure that the dash_obj is one-time converted json object
            dash_obj = json.dumps(json.loads(dash_obj))
        else:
            dash_obj = json.dumps(dash_obj)

        if check_if_empty(dash_obj):
            logging.info("Spotted empty object. Continue...")
            continue

        r = make_request(url, username, password, dash_obj, tenant, cookies,
                         insecure)

        try:
            response_error = json.loads(r.text)
            if response_error.get('errors'):
                logging.warning("\n\nSome problem on restoring %s: %s\n\n" %
                                (dash_obj, response_error['errors']))
        except Exception as e:
            logging.critical("The object to restore does not "
                             "look correct: %s" % e)

        if not r:
            logging.warning("Can not import %s into OpenSearch "
                            "Dashboards. Skipping..." % dash_obj)
            continue

        response_text = json.loads(r.text)
        if not response_text['success'] and resolve_conflicts:
            text = remove_reference(dash_obj)
            r = make_request(url, username, password, text, tenant, cookies,
                             insecure)

        logging.info("Restore status: %s with details %s" % (r.reason, r.text))
        r.raise_for_status()


def convert(text,  convert_file):
    convert_file = "%s-converted.yaml" % convert_file
    save_content_to_file(text, convert_file, False)
    logging.info("File converted. You can check %s" % convert_file)


def get_all_tenants(opensearch_api_url, username, password, insecure):
    url = "%s/_opendistro/_security/api/tenants/" % opensearch_api_url
    r = requests.get(url, auth=(username, password), verify=insecure)
    if r.status_code != 200:
        r.raise_for_status()
        sys.exit(1)
    return list(json.loads(r.text))


def main():
    args = get_arguments()
    dashboard_api_url = args.dashboard_api_url
    setup_logging(args.debug)

    if (not args.dashboard_api_url.startswith('http')
            and not args.dashboard_api_url.startswith('https')):
        dashboard_api_url = "https://%s" % args.dashboard_api_url

    if (not dashboard_api_url.endswith('_dashboards') and
            not urlparse(dashboard_api_url).port == 5601 and
            not check_kibana_api(dashboard_api_url)):
        # NOTE: The url should look like:
        # https://opensearch.logs.openstack.org/_dashboards
        # Old OpenSearch might not contain the _dashboards in the url.
        dashboard_api_url = "%s/_dashboards" % dashboard_api_url

    if args.action == 'backup':
        if args.all_tenants and args.tenant:
            logging.critical("Can not use --all-tenants with --tenant option")
            sys.exit(1)

        if args.all_tenants:
            if not args.opensearch_api_url:
                logging.critical('Please provide --opensearch-api-url to list '
                                 'all tenants available in Elasticsearch.')
                sys.exit(1)
            all_tenants = get_all_tenants(args.opensearch_api_url,
                                          args.username, args.password,
                                          args.insecure)

            for tenant in all_tenants:
                backup(dashboard_api_url, args.username, args.password,
                       args.backup_dir, args.insecure, tenant)
        else:
            backup(dashboard_api_url, args.username, args.password,
                   args.backup_dir, args.insecure, args.tenant)
    elif args.action == 'restore':
        if not args.file:
            logging.critical("Please provide --file to restore!")
            sys.exit(1)

        es_client = None
        if not args.skip_verify_index and (not args.host and not args.port):
            logging.critical("Can not continue. Please provide --host and "
                             "--port params")
            sys.exit(1)

        if args.host and args.port:
            es_client = get_es_client(args)

        text = _get_file_content(args.file)
        restore(dashboard_api_url, args.username, args.password,
                text, args.no_resolve_conflicts, args.insecure, args.tenant,
                args.overwrite_index_pattern, es_client,
                args.skip_verify_index)

    elif args.action == 'convert':
        if not args.file:
            logging.critical("Please provide --file to convert!")
            sys.exit(1)

        text = _get_file_content(args.file)
        convert(text, args.file)


if __name__ == "__main__":
    main()
