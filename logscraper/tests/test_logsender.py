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
import json
import os

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

performance_json = open(os.path.join(os.path.dirname(__file__),
                                     'performance-example.json')).read()


def _parse_get_yaml(text):
    yaml = YAML()
    return yaml.load(text)


class _MockedPoolMapAsyncResult:
    def __init__(self, func, iterable):
        self.func = func
        self.iterable = iterable
        self.wait = mock.Mock()

        # mocked results
        self._value = [self.func(i) for i in iterable]

    def get(self, timeout=0):
        return self._value


class FakeArgs(object):
    def __init__(self, config=None, directory=None, host=None, port=None,
                 username=None, password=None, index_prefix=None, index=None,
                 doc_type=None, insecure=None, follow=None, workers=None,
                 chunk_size=None, skip_debug=None, keep=None, debug=None,
                 wait_time=None, file_list=None,
                 performance_index_prefix=None):

        self.config = config
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
        self.skip_debug = skip_debug
        self.keep = keep
        self.debug = debug
        self.wait_time = wait_time
        self.file_list = file_list
        self.performance_index_prefix = performance_index_prefix


class TestSender(base.TestCase):

    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", doc_type='_doc',
                config='config.yaml'))
    def test_send(self, mock_args, mock_es_client, mock_build_info,
                  mock_send_to_es, mock_remove_dir, mock_info):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        perf_index = 'performance-index'
        mock_build_info.return_value = parsed_fields
        mock_es_client.return_value = 'fake_client_object'
        tags = ['test', 'info']
        mock_info.return_value = ('job-result.txt', tags)
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
            'filename': 'job-result.txt',
            'tags': tags
        }
        args = logsender.get_arguments()
        mock_send_to_es.return_value = True
        logsender.send((build_uuid, build_files), args, directory, index,
                       perf_index)
        self.assertTrue(mock_remove_dir.called)
        mock_send_to_es.assert_called_with(
            "%s/%s/job-result.txt" % (directory, build_uuid), expected_fields,
            'fake_client_object', index, None, '_doc', None, perf_index)

    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", keep=True, doc_type="_doc"))
    def test_send_keep_dir(self, mock_args, mock_es_client, mock_build_info,
                           mock_send_to_es, mock_remove_dir, mock_info):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        perf_index = 'performance-index'
        args = logsender.get_arguments()
        mock_info.return_value = ('somefile.txt', ['somefile.txt'])
        # No metter what is ES status, it should keep dir
        mock_send_to_es.return_value = None
        logsender.send((build_uuid, build_files), args, directory, index,
                       perf_index)
        self.assertFalse(mock_remove_dir.called)

    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", keep=False, doc_type="_doc"))
    def test_send_error_keep_dir(self, mock_args, mock_es_client,
                                 mock_build_info, mock_send_to_es,
                                 mock_remove_dir, mock_info):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        perf_index = 'performance-index'
        args = logsender.get_arguments()
        mock_info.return_value = ('somefile.txt', ['somefile.txt'])
        mock_send_to_es.return_value = None
        logsender.send((build_uuid, build_files), args, directory, index,
                       perf_index)
        self.assertFalse(mock_remove_dir.called)

    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.doc_iter')
    @mock.patch('logscraper.logsender.logline_iter')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, doc_type="zuul",
                config='config.yaml', skip_debug=False,
                performance_index_prefix="perf"))
    def test_send_to_es(self, mock_args, mock_text, mock_bulk, mock_doc_iter,
                        mock_logline_chunk, mock_file_info):
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
                             args.chunk_size, args.doc_type, args.skip_debug,
                             args.performance_index_prefix)
        self.assertEqual(1, mock_bulk.call_count)

    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.doc_iter')
    @mock.patch('logscraper.logsender.logline_iter')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, doc_type="zuul",
                config='test.yaml', skip_debug=False,
                performance_index_prefix="perf"))
    def test_send_to_es_error(self, mock_args, mock_text, mock_bulk,
                              mock_logline, mock_doc_iter, mock_file_info):
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
                                           args.index, args.chunk_size,
                                           args.doc_type, args.skip_debug,
                                           args.performance_index_prefix)
        self.assertIsNone(send_status)

    @mock.patch('json.load')
    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, doc_type="zuul",
                config='test.yaml', skip_debug=False,
                performance_index_prefix="perf"))
    def test_send_to_es_performance(self, mock_args, mock_text, mock_bulk,
                                    mock_file_info, mock_json_load):
        build_file = 'performance.json'
        es_fields = parsed_fields
        es_client = mock.Mock()
        args = logsender.get_arguments()
        mock_json_load.return_value = json.loads(performance_json)
        mock_text.new_callable = mock.mock_open(
            read_data=str(performance_json))
        es_doc = {
            '_index': 'perf',
            '_source': {
                '@timestamp': '2022-05-17T22:49:50',
                'build_branch': 'master',
                'build_change': 829161,
                'build_name': 'openstack-tox-py39',
                'build_newrev': 'UNKNOWN',
                'build_node': 'zuul-executor',
                'build_patchset': '3',
                'build_queue': 'check',
                'build_ref': 'refs/changes/61/829161/3',
                'build_set': '52b29e0e716a4436bd20eed47fa396ce',
                'build_status': 'SUCCESS',
                'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
                'cinder': 0,
                'compute_delete': None,
                'compute_get': 17,
                'compute_largest': 2568,
                'compute_post': 20,
                'devstack@c-api.service': 256569344,
                'devstack@c-bak.service': 135827456,
                'devstack@c-sch.service': 112668672,
                'devstack@c-vol.service': 150151168,
                'devstack@etcd.service': 80420864,
                'devstack@g-api.service': 241049600,
                'devstack@keystone.service': 260157440,
                'devstack@memory_tracker.service': 5562368,
                'devstack@n-api-meta.service': 223076352,
                'devstack@n-api.service': 261332992,
                'devstack@n-cond-cell1.service': 171405312,
                'devstack@n-cpu.service': 138313728,
                'devstack@n-novnc-cell1.service': 110931968,
                'devstack@n-sch.service': 162050048,
                'devstack@n-super-cond.service': 162463744,
                'devstack@placement-api.service': 166539264,
                'devstack@q-ovn-metadata-agent.service': 222007296,
                'devstack@q-svc.service': 422805504,
                'devstack@s-account.service': 62246912,
                'devstack@s-container-sync.service': 45375488,
                'devstack@s-container.service': 64376832,
                'devstack@s-object.service': 64589824,
                'devstack@s-proxy.service': 81174528,
                'hostname': 'ubuntu-focal-ovh-gra1-0029678038',
                'hosts_id':
                ['ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21'],
                'identity_delete': None,
                'identity_get': 1174,
                'identity_largest': 3856,
                'identity_post': 283,
                'image_delete': None,
                'image_get': 2,
                'image_largest': 1410,
                'image_post': 1,
                'info_delete': None,
                'info_get': 4,
                'info_largest': 1659,
                'info_post': None,
                'keystone': 0,
                'log_url':
                'https://somehost/829161/3/check/openstack-tox-py39/38bf2cd/',
                'message':
                    '{"services": [{"service": '
                    '"devstack@s-object.service", "MemoryCurrent": '
                    '64589824}, {"service": "devstack@keystone.service", '
                    '"MemoryCurrent": 260157440}, {"service": '
                    '"devstack@q-ovn-metadata-agent.service", '
                    '"MemoryCurrent": 222007296}, {"service": '
                    '"devstack@n-super-cond.service", "MemoryCurrent": '
                    '162463744}, {"service": "devstack@c-vol.service", '
                    '"MemoryCurrent": 150151168}, {"service": '
                    '"devstack@n-api-meta.service", "MemoryCurrent": '
                    '223076352}, {"service": "devstack@c-bak.service", '
                    '"MemoryCurrent": 135827456}, {"service": '
                    '"devstack@n-novnc-cell1.service", "MemoryCurrent": '
                    '110931968}, {"service": "devstack@n-api.service", '
                    '"MemoryCurrent": 261332992}, {"service": '
                    '"devstack@memory_tracker.service", "MemoryCurrent": '
                    '5562368}, {"service": "devstack@etcd.service", '
                    '"MemoryCurrent": 80420864}, {"service": '
                    '"devstack@q-svc.service", "MemoryCurrent": '
                    '422805504}, {"service": '
                    '"devstack@s-container-sync.service", "MemoryCurrent": '
                    '45375488}, {"service": "devstack@g-api.service", '
                    '"MemoryCurrent": 241049600}, {"service": '
                    '"devstack@s-proxy.service", "MemoryCurrent": '
                    '81174528}, {"service": "devstack@s-account.service", '
                    '"MemoryCurrent": 62246912}, {"service": '
                    '"devstack@c-sch.service", "MemoryCurrent": '
                    '112668672}, {"service": "devstack@n-sch.service", '
                    '"MemoryCurrent": 162050048}, {"service": '
                    '"devstack@s-container.service", "MemoryCurrent": '
                    '64376832}, {"service": "devstack@c-api.service", '
                    '"MemoryCurrent": 256569344}, {"service": '
                    '"devstack@n-cpu.service", "MemoryCurrent": '
                    '138313728}, {"service": '
                    '"devstack@placement-api.service", "MemoryCurrent": '
                    '166539264}, {"service": '
                    '"devstack@n-cond-cell1.service", "MemoryCurrent": '
                    '171405312}], "db": [{"db": "placement", "op": '
                    '"SELECT", "count": 4}, {"db": "nova_cell0", "op": '
                    '"UPDATE", "count": 12}, {"db": "nova_cell0", "op": '
                    '"SELECT", "count": 33}, {"db": "neutron", "op": '
                    '"UPDATE", "count": 1}, {"db": "neutron", "op": '
                    '"DELETE", "count": 1}, {"db": "neutron", "op": '
                    '"SELECT", "count": 10}, {"db": "nova_cell1", "op": '
                    '"SELECT", "count": 32}, {"db": "cinder", "op": '
                    '"DELETE", "count": 1}, {"db": "keystone", "op": '
                    '"SELECT", "count": 59}, {"db": "nova_cell1", "op": '
                    '"UPDATE", "count": 12}, {"db": "cinder", "op": '
                    '"INSERT", "count": 1}, {"db": "cinder", "op": '
                    '"UPDATE", "count": 7}, {"db": "cinder", "op": '
                    '"SELECT", "count": 52}], "processes": [{"cmd": '
                    '"/usr/lib/erlang/erts-10.6.4/bin/beam.smp", "pid": '
                    '34343, "args": "-W w -A 128 -MBas ageffcbf -MHas '
                    'ageffcbf", "rss": 86900736}, {"cmd": '
                    '"/usr/sbin/mysqld", "pid": 62703, "args": "", "rss": '
                    '739282944}, {"cmd": "/opt/stack/bin/etcd", "pid": '
                    '63704, "args": "--name '
                    'ubuntu-focal-ovh-gra1-0029678038", "rss": 19349504}, '
                    '{"cmd": "/usr/local/bin/privsep-helper", "pid": '
                    '91395, "args": "--config-file '
                    '/etc/neutron/neutron_ovn_metadata_agent.ini", "rss": '
                    '82690048}], "api": [{"service": "identity", "log": '
                    '"tls-proxy_access.log", "largest": 3402, "GET": 1173, '
                    '"POST": 283}, {"service": "info", "log": '
                    '"tls-proxy_access.log", "largest": 1659, "GET": 4}, '
                    '{"service": "placement", "log": '
                    '"tls-proxy_access.log", "largest": 1315, "GET": 9, '
                    '"POST": 1, "PUT": 2}, {"service": "v2.0", "log": '
                    '"tls-proxy_access.log", "largest": 10862, "GET": 19, '
                    '"POST": 9, "PUT": 3}, {"service": "compute", "log": '
                    '"tls-proxy_access.log", "largest": 2146, "GET": 16, '
                    '"POST": 20}, {"service": "volume", "log": '
                    '"tls-proxy_access.log", "largest": 390, "GET": 2, '
                    '"POST": 2}, {"service": "image", "log": '
                    '"tls-proxy_access.log", "largest": 1235, "GET": 2, '
                    '"POST": 1}, {"service": "identity", "log": '
                    '"access.log", "largest": 3856, "GET": 1174, "POST": '
                    '283, "PUT": 34}, {"service": "compute", "log": '
                    '"access.log", "largest": 2568, "GET": 17, "POST": '
                    '20}, {"service": "placement", "log": "access.log", '
                    '"largest": 1609, "GET": 9, "POST": 1, "PUT": 2}, '
                    '{"service": "volume", "log": "access.log", "largest": '
                    '758, "GET": 2, "POST": 2}, {"service": "image", '
                    '"log": "access.log", "largest": 1410, "GET": 2, '
                    '"POST": 1, "PUT": 1}], "report": {"timestamp": '
                    '"2022-05-17T22:49:50.871392", "hostname": '
                    '"ubuntu-focal-ovh-gra1-0029678038"}}',
                'neutron': 0,
                'node_provider': 'local',
                'nova_cell0': 0,
                'nova_cell1': 0,
                'placement': 0,
                'placement_delete': None,
                'placement_get': 9,
                'placement_largest': 1609,
                'placement_post': 1,
                'project': 'openstack/neutron',
                'tenant': 'openstack',
                'v2.0_delete': None,
                'v2.0_get': 19,
                'v2.0_largest': 10862,
                'v2.0_post': 9,
                'volume_delete': None,
                'volume_get': 2,
                'volume_largest': 758,
                'volume_post': 2,
                'voting': 1,
                'zuul_executor': 'ze07.opendev.org'},
            '_type': 'zuul'}

        logsender.send_to_es(build_file, es_fields, es_client, args.index,
                             args.chunk_size, args.doc_type, args.skip_debug,
                             args.performance_index_prefix)
        self.assertEqual(es_doc, list(mock_bulk.call_args.args[1])[0])
        self.assertEqual(1, mock_bulk.call_count)

    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.doc_iter')
    @mock.patch('logscraper.logsender.logline_iter')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, doc_type="zuul",
                config='test.yaml', skip_debug=True,
                performance_index_prefix="perf"))
    def test_send_to_es_skip_debug(self, mock_args, mock_text, mock_bulk,
                                   mock_logline, mock_doc_iter,
                                   mock_file_info):
        build_file = 'job-result.txt'
        es_fields = parsed_fields
        es_client = mock.Mock()
        args = logsender.get_arguments()
        text = ["2022-02-28 09:39:09.596010 | Job console starting...",
                "2022-02-28 09:39:09.610160 | DEBUG Updating repositories",
                "2022-02-28 09:39:09.996235 | DEBUG Preparing job workspace"]
        mock_text.return_value = io.StringIO("\n".join(text))
        es_doc = [{
            '_index': 'myindex',
            '_source': {
                '@timestamp': '2022-02-28T09:39:09.596000',
                'build_branch': 'master',
                'build_change': 829161,
                'build_name': 'openstack-tox-py39',
                'build_newrev': 'UNKNOWN',
                'build_node': 'zuul-executor',
                'build_patchset': '3',
                'build_queue': 'check',
                'build_ref': 'refs/changes/61/829161/3',
                'build_set': '52b29e0e716a4436bd20eed47fa396ce',
                'build_status': 'SUCCESS',
                'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
                'log_url':
                'https://somehost/829161/3/check/openstack-tox-py39/38bf2cd/',
                'message': ' Job console starting...',
                'node_provider': 'local',
                'project': 'openstack/neutron',
                'tenant': 'openstack',
                'voting': 1,
                'zuul_executor': 'ze07.opendev.org'},
            '_type': 'zuul'}]
        mock_doc_iter.return_value = es_doc
        logsender.send_to_es(build_file, es_fields, es_client, args.index,
                             args.chunk_size, args.doc_type, args.skip_debug,
                             args.performance_index_prefix)
        self.assertEqual(es_doc, list(mock_bulk.call_args.args[1]))
        self.assertEqual(1, mock_bulk.call_count)

    @mock.patch('logscraper.logsender.logline_iter')
    def test_doc_iter(self, mock_logline):
        text = [(datetime.datetime(2022, 2, 28, 9, 39, 9, 596000),
                 '2022-02-28 09:39:09.596010 | Job console starting...\n'),
                (datetime.datetime(2022, 2, 28, 9, 39, 9, 610000),
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
        chunk_text = list(logsender.doc_iter(
            text, 'someindex', {'field': 'test'}, '_doc'))
        self.assertEqual(expected_chunk, chunk_text)

    def test_logline_iter(self):
        text = """2022-02-28 09:39:09.596 | Job console starting...
2022-02-28 09:39:09.610 | Updating repositories
2022-02-28 09:39:09.996 | Preparing job workspace"""

        expected_data = [
            (datetime.datetime(2022, 2, 28, 9, 39, 9, 596000),
             '2022-02-28 09:39:09.596 | Job console starting...\n'),
            (datetime.datetime(2022, 2, 28, 9, 39, 9, 610000),
             '2022-02-28 09:39:09.610 | Updating repositories\n'),
            (datetime.datetime(2022, 2, 28, 9, 39, 9, 996000),
             '2022-02-28 09:39:09.996 | Preparing job workspace')
        ]
        skip_debug = False
        readed_data = mock.mock_open(read_data=text)
        with mock.patch('builtins.open', readed_data) as mocked_open_file:
            generated_text = list(logsender.logline_iter('nofile', skip_debug))
            self.assertEqual(expected_data, generated_text)
            self.assertTrue(mocked_open_file.called)

    @mock.patch('json.load')
    @mock.patch('logscraper.logsender.open_file')
    def test_json_iter(self, mock_open_file, mock_json_load):
        text = {
            "transient": {
                "cluster.index_state_management.coordinator.sweep_period": "1m"
            },
            "report": {
                "timestamp": "2022-04-18T19:51:55.394370",
                "hostname": "ubuntu-focal-rax-dfw-0029359041"
            }
        }
        mock_json_load.return_value = text
        result = logsender.json_iter('somefile')
        self.assertEqual(datetime.datetime(2022, 4, 18, 19, 51, 55),
                         list(result)[0][0])

        result = logsender.json_iter('somefile')
        self.assertEqual(str(text).replace("\'", "\""), list(result)[0][1])

    @mock.patch('logscraper.logsender.read_yaml_file',
                side_effect=[_parse_get_yaml(buildinfo),
                             _parse_get_yaml(inventory_info)])
    def test_makeFields(self, mock_read_yaml_file):
        buildinfo_yaml = logsender.get_build_info('fake_dir')
        inventory_info_yaml = logsender.get_inventory_info('other_fake_dir')
        generated_info = logsender.makeFields(inventory_info_yaml,
                                              buildinfo_yaml)
        self.assertEqual(parsed_fields, generated_info)

    def test_makeJsonFields(self):
        expected_fields = {
            'hostname': 'ubuntu-focal-ovh-gra1-0029678038',
            'devstack@s-object.service': 64589824,
            'devstack@keystone.service': 260157440,
            'devstack@q-ovn-metadata-agent.service': 222007296,
            'devstack@n-super-cond.service': 162463744,
            'devstack@c-vol.service': 150151168,
            'devstack@n-api-meta.service': 223076352,
            'devstack@c-bak.service': 135827456,
            'devstack@n-novnc-cell1.service': 110931968,
            'devstack@n-api.service': 261332992,
            'devstack@memory_tracker.service': 5562368,
            'devstack@etcd.service': 80420864,
            'devstack@q-svc.service': 422805504,
            'devstack@s-container-sync.service': 45375488,
            'devstack@g-api.service': 241049600,
            'devstack@s-proxy.service': 81174528,
            'devstack@s-account.service': 62246912,
            'devstack@c-sch.service': 112668672,
            'devstack@n-sch.service': 162050048,
            'devstack@s-container.service': 64376832,
            'devstack@c-api.service': 256569344,
            'devstack@n-cpu.service': 138313728,
            'devstack@placement-api.service': 166539264,
            'devstack@n-cond-cell1.service': 171405312,
            'placement': 0, 'nova_cell0': 0, 'neutron': 0,
            'nova_cell1': 0, 'cinder': 0, 'keystone': 0,
            'identity_get': 1174, 'identity_post': 283,
            'identity_delete': None, 'identity_largest': 3856,
            'info_get': 4, 'info_post': None, 'info_delete':
            None, 'info_largest': 1659, 'placement_get': 9,
            'placement_post': 1, 'placement_delete': None,
            'placement_largest': 1609, 'v2.0_get': 19,
            'v2.0_post': 9, 'v2.0_delete': None, 'v2.0_largest':
            10862, 'compute_get': 17, 'compute_post': 20,
            'compute_delete': None, 'compute_largest': 2568,
            'volume_get': 2, 'volume_post': 2, 'volume_delete':
            None, 'volume_largest': 758, 'image_get': 2,
            'image_post': 1, 'image_delete': None,
            'image_largest': 1410
        }
        fields = logsender.makeJsonFields(performance_json)
        self.assertEqual(expected_fields, fields)

    def test_get_message(self):
        line_1 = "28-02-2022 09:44:58.839036 | Some message"
        line_2 = "2022-02-28 09:44:58.839036 | Other message | other log info"
        self.assertEqual("Some message", logsender.get_message(line_1))
        self.assertEqual("Other message | other log info",
                         logsender.get_message(line_2))

    def test_get_timestamp(self):
        for (line, expected) in [
            ("2022-02-28 09:44:58.839036 | Other message",
             datetime.datetime(2022, 2, 28, 9, 44, 58, 839036)),
            ("2022-03-21T08:39:18.220547Z | Last metadata expiration",
             datetime.datetime(2022, 3, 21, 8, 39, 18, 220547)),
            ("Mar 31 04:50:23.795709 nested-virt some log",
             datetime.datetime(2022, 3, 31, 4, 50, 23, 795700)),
            ("Mar 21 09:33:23 fedora-rax-dfw-0028920567 sudo[2786]: zuul ",
             datetime.datetime(datetime.date.today().year, 3, 21, 9, 33, 23)),
            ("2022-03-23T13:09:08.644Z|00040|connmgr|INFO|br-int: added",
             datetime.datetime(2022, 3, 23, 13, 9, 8)),
            ("Friday 25 February 2022  09:27:51 +0000 (0:00:00.056)",
             datetime.datetime(2022, 2, 25, 9, 27, 51)),
        ]:
            got = logsender.get_timestamp(line)
            self.assertEqual(expected, got)

    @mock.patch('ruamel.yaml.YAML.load')
    @mock.patch('logscraper.logsender.open_file')
    def test_get_file_info(self, mock_open_file, mock_yaml):
        config = {'files': [{
            'name': 'job-output.txt',
            'tags': ['console', 'console.html']
        }, {'name': 'logs/undercloud/var/log/extra/logstash.txt',
            'tags': ['console', 'postpci']}]}
        expected_output_1 = ('logs/undercloud/var/log/extra/logstash.txt',
                             ['console', 'postpci', 'logstash.txt'])
        expected_output_2 = ('job-output.txt',
                             ['console', 'console.html', 'job-output.txt'])
        expected_output_3 = ('somejob.txt', ['somejob.txt'])
        mock_yaml.return_value = config
        self.assertEqual(expected_output_1, logsender.get_file_info(
            config, './9e7bbfb1a4614bc4be06776658fa888f/logstash.txt'))
        self.assertEqual(expected_output_2, logsender.get_file_info(
            config, './9e7bbfb1a4614bc4be06776658fa888f/job-output.txt'))
        self.assertEqual(expected_output_3, logsender.get_file_info(
            config, './9e7bbfb1a4614bc4be06776658fa888f/somejob.txt'))

    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                index_prefix="my-index-", workers=2))
    def test_get_index(self, mock_args, mock_es_client):
        args = logsender.get_arguments()
        expected_index = ("my-index-%s" %
                          datetime.datetime.today().strftime('%Y.%m.%d'))
        index = logsender.get_index(args)
        self.assertEqual((expected_index, None), index)

    @mock.patch('logscraper.logsender.send')
    @mock.patch('logscraper.logsender.get_index')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", workers=2, index='myindex',
                performance_index_prefix="perf"))
    def test_prepare_and_send(self, mock_args, mock_index, mock_send):
        args = logsender.get_arguments()
        ready_directories = {'builduuid': ['job-result.txt']}
        mock_index.return_value = (args.index, args.performance_index_prefix)
        with mock.patch(
                'multiprocessing.pool.Pool.starmap_async',
                lambda self, func, iterable, chunksize=None,
                callback=None,
                error_callback=None: _MockedPoolMapAsyncResult(func, iterable),
        ):
            logsender.prepare_and_send(ready_directories, args)
            self.assertTrue(mock_send.called)
            mock_send.assert_called_with((('builduuid', ['job-result.txt']),
                                          args, args.directory, args.index,
                                          args.performance_index_prefix))
