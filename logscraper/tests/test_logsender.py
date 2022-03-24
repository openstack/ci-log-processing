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

import datetime
import io

from logscraper import logsender
from logscraper.tests import base
from opensearchpy.exceptions import TransportError
from ruamel.yaml import YAML
from unittest import mock


buildinfo = """
_id: 17428524
branch: master
build_args:
  checkpoint_file: /tmp/results-checkpoint
  debug: false
  directory: /tmp/logscraper
  download: true
  follow: false
  gearman_port: 4730
  gearman_server: null
  insecure: true
  job_name: null
  logstash_url: null
  max_skipped: 500
  workers: 32
  zuul_api_url:
  - https://zuul.opendev.org/api/tenant/openstack
buildset:
  uuid: 52b29e0e716a4436bd20eed47fa396ce
change: 829161
duration: 1707.0
end_time: '2022-02-28T10:07:36'
error_detail: null
event_id: dda0cbf9caaa496b9127a7646b8a28a8
event_timestamp: '2022-02-28T09:32:08'
final: true
held: false
job_name: openstack-tox-py39
log_url: https://somehost/829161/3/check/openstack-tox-py39/38bf2cd/
newrev: null
nodeset: fedora-35
patchset: '3'
pipeline: check
project: openstack/neutron
provides: []
ref: refs/changes/61/829161/3
ref_url: https://review.opendev.org/829161
result: SUCCESS
start_time: '2022-02-28T09:39:09'
tenant: openstack
uuid: 38bf2cdc947643c9bb04f11f40a0f211
voting: true
"""

inventory_info = """
all:
  hosts:
    fedora-35:
      ansible_connection: ssh
      ansible_host: 127.0.0.1
      ansible_port: 22
      ansible_python_interpreter: auto
      ansible_user: zuul
      ara_compress_html: false
      ara_report_path: ara-report
      ara_report_type: html
      bindep_profile: test py39
      enable_fips: false
      nodepool:
        az: null
        cloud: rax
        external_id: 3b2da968-7ec3-4356-b12c-b55b574902f8
        host_id: ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21
        interface_ip: 127.0.0.2
        label: fedora-35
        private_ipv4: 127.0.0.3
        private_ipv6: null
        provider: rax-dfw
        public_ipv4: 127.0.0.2
        public_ipv6: ''
        region: DFW
      python_version: 3.9
      tox_constraints_file: 'requirements/upper-constraints.txt'
      tox_environment:
        NOSE_HTML_OUT_FILE: nose_results.html
        NOSE_WITH_HTML_OUTPUT: 1
        NOSE_WITH_XUNIT: 1
      tox_envlist: py39
  vars:
    ara_compress_html: false
    ara_report_path: ara-report
    ara_report_type: html
    bindep_profile: test py39
    enable_fips: false
    python_version: 3.9
    tox_constraints_file: 'requirements/upper-constraints.txt'
    tox_environment:
      NOSE_HTML_OUT_FILE: nose_results.html
      NOSE_WITH_HTML_OUTPUT: 1
      NOSE_WITH_XUNIT: 1
    tox_envlist: py39
    zuul:
      _inheritance_path:
      - 'some_path'
      - 'some_path_2'
      attempts: 1
      branch: master
      build: 38bf2cdc947643c9bb04f11f40a0f211
      buildset: 52b29e0e716a4436bd20eed47fa396ce
      change: '829161'
      change_url: https://review.opendev.org/829161
      child_jobs: []
      event_id: dda0cbf9caaa496b9127a7646b8a28a8
      executor:
        hostname: ze07.opendev.org
        inventory_file: /var/lib/zuul/builds/build/ansible/inventory.yaml
        log_root: /var/lib/zuul/builds/build/work/logs
        result_data_file: /var/lib/zuul/builds/build/work/results.json
        src_root: /var/lib/zuul/builds/build/work/src
        work_root: /var/lib/zuul/builds/build/work
      items:
      - branch: master
        change: '828673'
        change_url: https://review.opendev.org/828673
        patchset: '4'
        project:
          canonical_hostname: opendev.org
          canonical_name: opendev.org/openstack/neutron
          name: openstack/neutron
          short_name: neutron
          src_dir: src/opendev.org/openstack/neutron
      - branch: master
        change: '829161'
        change_url: https://review.opendev.org/829161
        patchset: '3'
        project:
          canonical_hostname: opendev.org
          canonical_name: opendev.org/openstack/neutron
          name: openstack/neutron
          short_name: neutron
          src_dir: src/opendev.org/openstack/neutron
      job: openstack-tox-py39
      jobtags: []
      message: Q3YmM0Y2QzNzhkMWZhOWE5ODYK
      patchset: '3'
      pipeline: check
      playbook_context:
        playbook_projects:
          trusted/project_0/opendev.org/opendev/base-jobs:
            canonical_name: opendev.org/opendev/base-jobs
            checkout: master
            commit: 19dc53290a26b20d5c2c5b1bb25f029c4b04a716
          trusted/project_1/opendev.org/zuul/zuul-jobs:
            canonical_name: opendev.org/zuul/zuul-jobs
            checkout: master
            commit: e160f59e0e76c7e8625ec2d174b044a7c92cd32e
          untrusted/project_0/opendev.org/zuul/zuul-jobs:
            canonical_name: opendev.org/zuul/zuul-jobs
            checkout: master
            commit: e160f59e0e76c7e8625ec2d174b044a7c92cd32e
          untrusted/project_1/opendev.org/opendev/base-jobs:
            canonical_name: opendev.org/opendev/base-jobs
            checkout: master
            commit: 19dc53290a26b20d5c2c5b1bb25f029c4b04a716
        playbooks:
        - path: untrusted/project/opendev/zuul/zuul-jobs/playbooks/tox/run.yaml
          roles:
          - checkout: master
            checkout_description: zuul branch
            link_name: ansible/playbook_0/role_0/base-jobs
            link_target: untrusted/project_1/opendev.org/opendev/base-jobs
            role_path: ansible/playbook_0/role_0/base-jobs/roles
          - checkout: master
            checkout_description: playbook branch
            link_name: ansible/playbook_0/role_1/zuul-jobs
            link_target: untrusted/project_0/opendev.org/zuul/zuul-jobs
            role_path: ansible/playbook_0/role_1/zuul-jobs/roles
      post_review: false
      project:
        canonical_hostname: opendev.org
        canonical_name: opendev.org/openstack/neutron
        name: openstack/neutron
        short_name: neutron
        src_dir: src/opendev.org/openstack/neutron
      projects:
        opendev.org/openstack/neutron:
          canonical_hostname: opendev.org
          canonical_name: opendev.org/openstack/neutron
          checkout: master
          checkout_description: zuul branch
          commit: 7be5a0aff1123b381674191f3baa1ec9c128e0f3
          name: openstack/neutron
          required: false
          short_name: neutron
          src_dir: src/opendev.org/openstack/neutron
        opendev.org/openstack/requirements:
          canonical_hostname: opendev.org
          canonical_name: opendev.org/openstack/requirements
          checkout: master
          checkout_description: zuul branch
          commit: 48fb5c24764d91833d8ca7084ee9f183785becd6
          name: openstack/requirements
          required: true
          short_name: requirements
          src_dir: src/opendev.org/openstack/requirements
      ref: refs/changes/61/829161/3
      resources: {}
      tenant: openstack
      timeout: 3600
      voting: true
"""

parsed_fields = {
    'build_node': 'zuul-executor',
    'build_name': 'openstack-tox-py39',
    'build_status': 'SUCCESS',
    'project': 'openstack/neutron',
    'voting': 1,
    'build_set': '52b29e0e716a4436bd20eed47fa396ce',
    'build_queue': 'check',
    'build_ref': 'refs/changes/61/829161/3',
    'build_branch': 'master',
    'build_change': 829161,
    'build_patchset': '3',
    'build_newrev': 'UNKNOWN',
    'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
    'node_provider': 'local',
    'hosts_id': ['ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21'],
    'log_url':
    'https://somehost/829161/3/check/openstack-tox-py39/38bf2cd/',
    'tenant': 'openstack',
    'zuul_executor': 'ze07.opendev.org'
}


def _parse_get_yaml(text):
    yaml = YAML()
    return yaml.load(text)


class _MockedPoolMapResult:
    def __init__(self, func, iterable):
        self.func = func
        self.iterable = iterable

        # mocked results
        self._value = [self.func(i) for i in iterable]

    def get(self, timeout=0):
        return self._value


class FakeArgs(object):
    def __init__(self, directory=None, host=None, port=None, username=None,
                 password=None, index_prefix=None, index=None, doc_type=None,
                 insecure=None, follow=None, workers=None, chunk_size=None,
                 keep=None, debug=None):

        self.directory = directory
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.index_prefix = index_prefix
        self.index = index
        self.doc_type = doc_type
        self.insecure = insecure
        self.follow = follow
        self.workers = workers
        self.chunk_size = chunk_size
        self.keep = keep
        self.debug = debug


class TestSender(base.TestCase):

    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", doc_type='_doc'))
    def test_send(self, mock_args, mock_es_client, mock_build_info,
                  mock_send_to_es, mock_remove_dir):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        workers = 1
        mock_build_info.return_value = parsed_fields
        mock_es_client.return_value = 'fake_client_object'
        expected_fields = {
            'build_node': 'zuul-executor', 'build_name': 'openstack-tox-py39',
            'build_status': 'SUCCESS', 'project': 'openstack/neutron',
            'voting': 1, 'build_set': '52b29e0e716a4436bd20eed47fa396ce',
            'build_queue': 'check', 'build_ref': 'refs/changes/61/829161/3',
            'build_branch': 'master', 'build_change': 829161,
            'build_patchset': '3', 'build_newrev': 'UNKNOWN',
            'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
            'node_provider': 'local', 'hosts_id':
            ['ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21'],
            'log_url': 'https://somehost/829161/3/check/openstack-tox-py39/'
                       '38bf2cd/job-result.txt',
            'tenant': 'openstack', 'zuul_executor': 'ze07.opendev.org',
            'filename': 'job-result.txt'
        }
        args = logsender.get_arguments()
        mock_send_to_es.return_value = True
        logsender.send((build_uuid, build_files), args, directory, index,
                       workers)
        self.assertTrue(mock_remove_dir.called)
        mock_send_to_es.assert_called_with(
            "%s/%s/job-result.txt" % (directory, build_uuid), expected_fields,
            'fake_client_object', index, workers, None, '_doc')

    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", keep=True, doc_type="_doc"))
    def test_send_keep_dir(self, mock_args, mock_es_client, mock_build_info,
                           mock_send_to_es, mock_remove_dir):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        workers = 1
        args = logsender.get_arguments()
        # No metter what is ES status, it should keep dir
        mock_send_to_es.return_value = None
        logsender.send((build_uuid, build_files), args, directory, index,
                       workers)
        self.assertFalse(mock_remove_dir.called)

    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", keep=False, doc_type="_doc"))
    def test_send_error_keep_dir(self, mock_args, mock_es_client,
                                 mock_build_info, mock_send_to_es,
                                 mock_remove_dir):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        workers = 1
        args = logsender.get_arguments()
        mock_send_to_es.return_value = None
        logsender.send((build_uuid, build_files), args, directory, index,
                       workers)
        self.assertFalse(mock_remove_dir.called)

    @mock.patch('logscraper.logsender.doc_iter')
    @mock.patch('logscraper.logsender.logline_iter')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, doc_type="zuul"))
    def test_send_to_es(self, mock_args, mock_text, mock_bulk, mock_doc_iter,
                        mock_logline_chunk):
        build_file = 'job-result.txt'
        es_fields = parsed_fields
        es_client = mock.Mock()
        args = logsender.get_arguments()
        text = ["2022-02-28 09:39:09.596010 | Job console starting...",
                "2022-02-28 09:39:09.610160 | Updating repositories",
                "2022-02-28 09:39:09.996235 | Preparing job workspace"]
        mock_text.return_value = io.StringIO("\n".join(text))
        es_doc = [{
            '_index': 'myindex',
            '_type': 'zuul',
            '_source': {
                'build_node': 'zuul-executor',
                'build_name': 'openstack-tox-py39',
                'build_status': 'SUCCESS',
                'project': 'openstack/neutron',
                'voting': 1,
                'build_set': '52b29e0e716a4436bd20eed47fa396ce',
                'build_queue': 'check',
                'build_ref': 'refs/changes/61/829161/3',
                'build_branch': 'master',
                'build_change': 829161,
                'build_patchset': '3',
                'build_newrev': 'UNKNOWN',
                'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
                'node_provider': 'local',
                'hosts_id':
                ['ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21'],
                'log_url':
                'https://somehost/829161/3/check/openstack-tox-py39/38bf2cd/',
                'tenant': 'openstack',
                'zuul_executor': 'ze07.opendev.org',
                '@timestamp': '2022-02-28T09:39:09.596000',
                'message': ' Job console starting...'
            }
        }, {
            '_index': 'myindex',
            '_type': 'zuul',
            '_source': {
                'build_node': 'zuul-executor',
                'build_name': 'openstack-tox-py39',
                'build_status': 'SUCCESS',
                'project': 'openstack/neutron',
                'voting': 1,
                'build_set': '52b29e0e716a4436bd20eed47fa396ce',
                'build_queue': 'check',
                'build_ref': 'refs/changes/61/829161/3',
                'build_branch': 'master',
                'build_change': 829161,
                'build_patchset': '3',
                'build_newrev': 'UNKNOWN',
                'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
                'node_provider': 'local',
                'hosts_id':
                ['ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21'],
                'log_url':
                'https://somehost/829161/3/check/openstack-tox-py39/38bf2cd/',
                'tenant': 'openstack',
                'zuul_executor': 'ze07.opendev.org',
                '@timestamp': '2022-02-28T09:39:09.610000',
                'message': ' Updating repositories'
            }
        }, {
            '_index': 'myindex',
            '_type': 'zuul',
            '_source': {
                'build_node': 'zuul-executor',
                'build_name': 'openstack-tox-py39',
                'build_status': 'SUCCESS',
                'project': 'openstack/neutron',
                'voting': 1,
                'build_set': '52b29e0e716a4436bd20eed47fa396ce',
                'build_queue': 'check',
                'build_ref': 'refs/changes/61/829161/3',
                'build_branch': 'master',
                'build_change': 829161,
                'build_patchset': '3',
                'build_newrev': 'UNKNOWN',
                'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
                'node_provider': 'local',
                'hosts_id':
                ['ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21'],
                'log_url':
                'https://somehost/829161/3/check/openstack-tox-py39/38bf2cd/',
                'tenant': 'openstack',
                'zuul_executor': 'ze07.opendev.org',
                '@timestamp': '2022-02-28T09:39:09.996000',
                'message': ' Preparing job workspace'
            }
        }]
        mock_doc_iter.return_value = es_doc
        logsender.send_to_es(build_file, es_fields, es_client, args.index,
                             args.workers, args.chunk_size, args.doc_type)
        self.assertEqual(1, mock_bulk.call_count)

    @mock.patch('logscraper.logsender.doc_iter')
    @mock.patch('logscraper.logsender.logline_iter')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, doc_type="zuul"))
    def test_send_to_es_error(self, mock_args, mock_text, mock_bulk,
                              mock_logline, mock_doc_iter):
        build_file = 'job-result.txt'
        es_fields = parsed_fields
        es_client = mock.Mock()
        args = logsender.get_arguments()
        text = ["2022-02-28 09:39:09.596010 | Job console starting...",
                "2022-02-28 09:39:09.610160 | Updating repositories",
                "2022-02-28 09:39:09.996235 | Preparing job workspace"]
        mock_text.return_value = io.StringIO("\n".join(text))
        es_doc = [{
            '_index': 'myindex',
            '_type': 'zuul',
            '_source': {
                'build_node': 'zuul-executor',
                'build_name': 'openstack-tox-py39',
                'build_status': 'SUCCESS',
                'project': 'openstack/neutron',
                'voting': 1,
                'build_set': '52b29e0e716a4436bd20eed47fa396ce',
                'build_queue': 'check',
                'build_ref': 'refs/changes/61/829161/3',
                'build_branch': 'master',
                'build_change': 829161,
                'build_patchset': '3',
                'build_newrev': 'UNKNOWN',
                'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
                'node_provider': 'local',
                'log_url':
                'https://somehost/829161/3/check/openstack-tox-py39/38bf2cd/',
                'tenant': 'openstack',
                'zuul_executor': 'ze07.opendev.org',
                '@timestamp': '2022-02-28T09:39:09.596000',
                'message': ' Job console starting...'
            }
        }]
        mock_doc_iter.return_value = es_doc
        mock_bulk.side_effect = TransportError(500, "InternalServerError", {
            "error": {
                "root_cause": [{
                    "type": "error",
                    "reason": "error reason"
                }]
            }
        })
        send_status = logsender.send_to_es(build_file, es_fields, es_client,
                                           args.index, args.workers,
                                           args.chunk_size, args.doc_type)
        self.assertIsNone(send_status)

    @mock.patch('logscraper.logsender.logline_iter')
    def test_doc_iter(self, mock_logline):
        text = [('2022-02-28T09:39:09.596000',
                 '2022-02-28 09:39:09.596010 | Job console starting...\n'),
                ('2022-02-28T09:39:09.610000',
                 '2022-02-28 09:39:09.610160 | Updating repositories\n')]
        expected_chunk = [{
            '_index': 'someindex',
            '_source': {
                '@timestamp': '2022-02-28T09:39:09.596000',
                'field': 'test',
                'message': 'Job console starting...'
            },
            '_type': '_doc'
        }, {
            '_index': 'someindex',
            '_source': {
                '@timestamp': '2022-02-28T09:39:09.610000',
                'field': 'test',
                'message': 'Updating repositories'
            },
            '_type': '_doc'
        }]
        chunk_text = list(
            logsender.doc_iter(text, 'someindex', {'field': 'test'}, '_doc',
                               1000))
        self.assertEqual(expected_chunk, chunk_text)

    def test_logline_iter(self):
        text = """2022-02-28 09:39:09.596010 | Job console starting...
2022-02-28 09:39:09.610160 | Updating repositories
2022-02-28 09:39:09.996235 | Preparing job workspace"""

        expected_data = [
            ('2022-02-28T09:39:09.596000',
             '2022-02-28 09:39:09.596010 | Job console starting...\n'),
            ('2022-02-28T09:39:09.610000',
             '2022-02-28 09:39:09.610160 | Updating repositories\n'),
            ('2022-02-28T09:39:09.996000',
             '2022-02-28 09:39:09.996235 | Preparing job workspace')
        ]
        readed_data = mock.mock_open(read_data=text)
        with mock.patch('builtins.open', readed_data) as mocked_open_file:
            generated_text = list(logsender.logline_iter('nofile'))
            self.assertEqual(expected_data, generated_text)
            self.assertTrue(mocked_open_file.called)

    @mock.patch('logscraper.logsender.read_yaml_file',
                side_effect=[_parse_get_yaml(buildinfo),
                             _parse_get_yaml(inventory_info)])
    def test_makeFields(self, mock_read_yaml_file):
        buildinfo_yaml = logsender.get_build_info('fake_dir')
        inventory_info_yaml = logsender.get_inventory_info('other_fake_dir')
        generated_info = logsender.makeFields(inventory_info_yaml,
                                              buildinfo_yaml)
        self.assertEqual(parsed_fields, generated_info)

    def test_get_message(self):
        line_1 = "28-02-2022 09:44:58.839036 | Some message"
        line_2 = "2022-02-28 09:44:58.839036 | Other message | other log info"
        self.assertEqual("Some message", logsender.get_message(line_1))
        self.assertEqual("Other message | other log info",
                         logsender.get_message(line_2))

    def test_get_timestamp(self):
        line_1 = "28-02-2022 09:44:58.839036 | Some message"
        line_2 = "2022-02-28 09:44:58.839036 | Other message"
        self.assertEqual(None, logsender.get_timestamp(line_1))
        self.assertEqual("2022-02-28T09:44:58.839000",
                         logsender.get_timestamp(line_2))

    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                index_prefix="my-index-", workers=2))
    def test_get_index(self, mock_args, mock_es_client):
        args = logsender.get_arguments()
        expected_index = ("my-index-%s" %
                          datetime.datetime.today().strftime('%Y.%m.%d'))
        index = logsender.get_index(args)
        self.assertEqual(expected_index, index)

    @mock.patch('logscraper.logsender.send')
    @mock.patch('logscraper.logsender.get_index')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", workers=2, index='myindex'))
    def test_prepare_and_send(self, mock_args, mock_index, mock_send):
        args = logsender.get_arguments()
        ready_directories = {'builduuid': ['job-result.txt']}
        mock_index.return_value = args.index
        with mock.patch(
                'multiprocessing.pool.Pool.starmap',
                lambda self, func, iterable, chunksize=None,
                callback=None,
                error_callback=None: _MockedPoolMapResult(func, iterable),
        ):
            logsender.prepare_and_send(ready_directories, args)
            self.assertTrue(mock_send.called)
            mock_send.assert_called_with((('builduuid', ['job-result.txt']),
                                          args, args.directory, args.index, 2))
