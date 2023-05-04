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
import copy
import datetime
import io
import json
import os

from logscraper import logsender
from logscraper.tests import base
from opensearchpy.exceptions import TransportError
from pathlib import Path
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
    'hosts_region': ['rax-DFW'],
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
                 insecure=None, follow=None, workers=None,
                 chunk_size=None, skip_debug=None, keep=None, debug=None,
                 wait_time=None, file_list=None,
                 performance_index_prefix=None, subunit_index_prefix=None):

        self.config = config
        self.directory = directory
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.index_prefix = index_prefix
        self.index = index
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
        self.subunit_index_prefix = subunit_index_prefix


class TestSender(base.TestCase):

    @mock.patch('argparse.ArgumentParser.parse_args')
    def test_get_arguments(self, mock_args):
        mock_args.return_value = FakeArgs(
            host='somehost.com',
            debug=True,
            insecure=False,
            config='/tmp/somefile.conf',
            port=9200,
            subunit_index_prefix='test-'
        )
        m = mock.mock_open(read_data="[DEFAULT]\ndebug: False\n"
                           "insecure: True\nport: 9000\n"
                           "subunit_index_prefix: subunit-")
        with mock.patch('builtins.open', m) as mocked_open:
            args = logsender.get_arguments()
            self.assertEqual(True, args.debug)
            self.assertEqual(False, args.insecure)
            self.assertEqual(9200, args.port)
            self.assertEqual('test-', args.subunit_index_prefix)
            mocked_open.assert_called_once()

    @mock.patch('os.path.getsize')
    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir",
                config='config.yaml'))
    def test_send(self, mock_args, mock_es_client, mock_build_info,
                  mock_send_to_es, mock_remove_dir, mock_info,
                  mock_get_size):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        perf_index = 'performance-index'
        subunit_index = 'subunit-index'
        mock_build_info.return_value = parsed_fields
        mock_es_client.return_value = 'fake_client_object'
        mock_get_size.return_value = 1
        tags = ['test', 'info']
        mock_info.return_value = ('job-result.txt', tags)

        expected_fields = {
                'build_node': 'zuul-executor',
                'build_name': 'openstack-tox-py39',
                'build_status': 'SUCCESS', 'project': 'openstack/neutron',
                'voting': 1, 'build_set': '52b29e0e716a4436bd20eed47fa396ce',
                'build_queue': 'check',
                'build_ref': 'refs/changes/61/829161/3',
                'build_branch': 'master', 'build_change': 829161,
                'build_patchset': '3', 'build_newrev': 'UNKNOWN',
                'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
                'node_provider': 'local',
                'hosts_region': ['rax-DFW'],
                'hosts_id': [
                    'ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21'
                    ],
                'log_url': 'https://somehost/829161/3/check/'
                           'openstack-tox-py39/38bf2cd/job-result.txt',
                'tenant': 'openstack', 'zuul_executor': 'ze07.opendev.org',
                'filename': 'job-result.txt', 'tags': tags}

        args = logsender.get_arguments()
        mock_send_to_es.return_value = True
        logsender.send((build_uuid, build_files), args, directory, index,
                       perf_index, subunit_index)
        self.assertTrue(mock_remove_dir.called)
        mock_send_to_es.assert_called_with(
            "%s/%s/job-result.txt" % (directory, build_uuid), expected_fields,
            'fake_client_object', index, None, None, perf_index, subunit_index)

    @mock.patch('os.path.getsize')
    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", keep=True))
    def test_send_keep_dir(self, mock_args, mock_es_client, mock_build_info,
                           mock_send_to_es, mock_remove_dir, mock_info,
                           mock_get_size):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        perf_index = 'performance-index'
        subunit_index = 'subunit-index'
        args = logsender.get_arguments()
        mock_info.return_value = ('somefile.txt', ['somefile.txt'])
        # No metter what is ES status, it should keep dir
        mock_send_to_es.return_value = None
        mock_get_size.return_value = 1
        logsender.send((build_uuid, build_files), args, directory, index,
                       perf_index, subunit_index)
        self.assertFalse(mock_remove_dir.called)

    @mock.patch('os.path.getsize')
    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", keep=False))
    def test_send_error_keep_dir(self, mock_args, mock_es_client,
                                 mock_build_info, mock_send_to_es,
                                 mock_remove_dir, mock_info,
                                 mock_get_size):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        perf_index = 'performance-index'
        subunit_index = 'subunit-index'
        args = logsender.get_arguments()
        mock_info.return_value = ('somefile.txt', ['somefile.txt'])
        mock_send_to_es.return_value = None
        mock_get_size.return_value = 1
        logsender.send((build_uuid, build_files), args, directory, index,
                       perf_index, subunit_index)
        self.assertFalse(mock_remove_dir.called)

    @mock.patch('os.path.getsize')
    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch('logscraper.logsender.send_to_es')
    @mock.patch('logscraper.logsender.get_build_information')
    @mock.patch('logscraper.logsender.get_es_client')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir",
                config='config.yaml'))
    def test_send_skip_broken_file(self, mock_args, mock_es_client,
                                   mock_build_info, mock_send_to_es,
                                   mock_remove_dir, mock_info, mock_get_size):
        build_uuid = '38bf2cdc947643c9bb04f11f40a0f211'
        build_files = ['job-result.txt', 'testrepository.subunit.gz']
        directory = '/tmp/testdir'
        index = 'logstash-index'
        perf_index = 'performance-index'
        subunit_index = 'subunit-index'
        mock_build_info.return_value = parsed_fields
        mock_es_client.return_value = 'fake_client_object'
        mock_get_size.return_value = 1
        tags = ['test', 'info']
        mock_info.return_value = ('job-result.txt', tags)

        expected_fields = {
                'build_node': 'zuul-executor',
                'build_name': 'openstack-tox-py39',
                'build_status': 'SUCCESS', 'project': 'openstack/neutron',
                'voting': 1, 'build_set': '52b29e0e716a4436bd20eed47fa396ce',
                'build_queue': 'check',
                'build_ref': 'refs/changes/61/829161/3',
                'build_branch': 'master', 'build_change': 829161,
                'build_patchset': '3', 'build_newrev': 'UNKNOWN',
                'build_uuid': '38bf2cdc947643c9bb04f11f40a0f211',
                'node_provider': 'local',
                'hosts_region': ['rax-DFW'],
                'hosts_id': [
                    'ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21'
                    ],
                'log_url': 'https://somehost/829161/3/check/'
                           'openstack-tox-py39/38bf2cd/job-result.txt',
                'tenant': 'openstack', 'zuul_executor': 'ze07.opendev.org',
                'filename': 'job-result.txt', 'tags': tags}

        args = logsender.get_arguments()
        mock_send_to_es.return_value = True
        logsender.send((build_uuid, build_files), args, directory, index,
                       perf_index, subunit_index)
        self.assertTrue(mock_remove_dir.called)
        # Ensure that send_to_es was called just once
        mock_send_to_es.assert_called_once_with(
            "%s/%s/job-result.txt" % (directory, build_uuid), expected_fields,
            'fake_client_object', index, None, None, perf_index, subunit_index)

    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.doc_iter')
    @mock.patch('logscraper.logsender.logline_iter')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000,
                config='config.yaml', skip_debug=False,
                performance_index_prefix="perf",
                subunit_index_prefix="subunit"))
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
                             args.chunk_size, args.skip_debug,
                             args.performance_index_prefix,
                             args.subunit_index_prefix)
        self.assertEqual(1, mock_bulk.call_count)

    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.doc_iter')
    @mock.patch('logscraper.logsender.logline_iter')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, config='test.yaml', skip_debug=False,
                performance_index_prefix="perf",
                subunit_index_prefix="subunit"))
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
                                           args.skip_debug,
                                           args.performance_index_prefix,
                                           args.subunit_index_prefix)
        self.assertIsNone(send_status)

    @mock.patch('json.load')
    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, config='test.yaml', skip_debug=False,
                performance_index_prefix="perf",
                subunit_index_prefix="subunit"))
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
                'api_compute_get': 17,
                'api_compute_largest': 2568,
                'api_compute_post': 20,
                'api_identity_get': 1174,
                'api_identity_largest': 3856,
                'api_identity_post': 283,
                'api_identity_put': 34,
                'api_image_get': 2,
                'api_image_largest': 1410,
                'api_image_post': 1,
                'api_image_put': 1,
                'api_info_get': 4,
                'api_info_largest': 1659,
                'api_placement_get': 9,
                'api_placement_largest': 1609,
                'api_placement_post': 1,
                'api_placement_put': 2,
                'api_v2.0_get': 19,
                'api_v2.0_largest': 10862,
                'api_v2.0_post': 9,
                'api_v2.0_put': 3,
                'api_volume_get': 2,
                'api_volume_largest': 758,
                'api_volume_post': 2,
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
                'db_cinder_delete': 1,
                'db_cinder_insert': 1,
                'db_cinder_select': 52,
                'db_cinder_update': 7,
                'db_keystone_select': 59,
                'db_neutron_delete': 1,
                'db_neutron_select': 10,
                'db_neutron_update': 1,
                'db_nova_cell0_select': 33,
                'db_nova_cell0_update': 12,
                'db_nova_cell1_select': 32,
                'db_nova_cell1_update': 12,
                'db_placement_select': 4,
                'hostname': 'ubuntu-focal-ovh-gra1-0029678038',
                'hosts_region': ['rax-DFW'],
                'hosts_id':
                ['ed82a4a59ac22bf396288f0b93bf1c658af932130f9d336aad528f21'],
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
                'node_provider': 'local',
                'project': 'openstack/neutron',
                'service_devstack@c-api.service_memorycurrent': 256569344,
                'service_devstack@c-bak.service_memorycurrent': 135827456,
                'service_devstack@c-sch.service_memorycurrent': 112668672,
                'service_devstack@c-vol.service_memorycurrent': 150151168,
                'service_devstack@etcd.service_memorycurrent': 80420864,
                'service_devstack@g-api.service_memorycurrent': 241049600,
                'service_devstack@keystone.service_memorycurrent': 260157440,
                'service_devstack@memory_tracker.service_memorycurrent':
                5562368,
                'service_devstack@n-api-meta.service_memorycurrent': 223076352,
                'service_devstack@n-api.service_memorycurrent': 261332992,
                'service_devstack@n-cond-cell1.service_memorycurrent':
                171405312,
                'service_devstack@n-cpu.service_memorycurrent': 138313728,
                'service_devstack@n-novnc-cell1.service_memorycurrent':
                110931968,
                'service_devstack@n-sch.service_memorycurrent': 162050048,
                'service_devstack@n-super-cond.service_memorycurrent':
                162463744,
                'service_devstack@placement-api.service_memorycurrent':
                166539264,
                'service_devstack@q-ovn-metadata-agent.service_memorycurrent':
                222007296,
                'service_devstack@q-svc.service_memorycurrent': 422805504,
                'service_devstack@s-account.service_memorycurrent': 62246912,
                'service_devstack@s-container-sync.service_memorycurrent':
                45375488,
                'service_devstack@s-container.service_memorycurrent': 64376832,
                'service_devstack@s-object.service_memorycurrent': 64589824,
                'service_devstack@s-proxy.service_memorycurrent': 81174528,
                'tenant': 'openstack',
                'voting': 1,
                'zuul_executor': 'ze07.opendev.org'},
            }

        logsender.send_to_es(build_file, es_fields, es_client, args.index,
                             args.chunk_size, args.skip_debug,
                             args.performance_index_prefix,
                             args.subunit_index_prefix)
        self.assertEqual(es_doc, list(mock_bulk.call_args.args[1])[0])
        self.assertEqual(1, mock_bulk.call_count)

    @mock.patch('logscraper.logsender.get_file_info')
    @mock.patch('logscraper.logsender.doc_iter')
    @mock.patch('logscraper.logsender.logline_iter')
    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('logscraper.logsender.open_file')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, config='test.yaml', skip_debug=True,
                performance_index_prefix="perf",
                subunit_index_prefix="subunit"))
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
                'zuul_executor': 'ze07.opendev.org'}
            }]
        mock_doc_iter.return_value = es_doc
        logsender.send_to_es(build_file, es_fields, es_client, args.index,
                             args.chunk_size, args.skip_debug,
                             args.performance_index_prefix,
                             args.subunit_index_prefix)
        self.assertEqual(es_doc, list(mock_bulk.call_args.args[1]))
        self.assertEqual(1, mock_bulk.call_count)

    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch.object(Path, 'stat')
    def test_remove_old_dir(self, mock_stat, mock_rm):
        mock_stat.return_value.st_mtime = 1685575754.860575
        logsender.remove_old_dir("Somedir", "someBuildUuid", ["someFile"])
        self.assertEqual(1, mock_rm.call_count)

    @mock.patch('logscraper.logsender.remove_directory')
    @mock.patch.object(Path, 'stat')
    def test_remove_old_dir_keep(self, mock_stat, mock_rm):
        now = datetime.datetime.utcnow().timestamp()
        mock_stat.return_value.st_mtime = now
        logsender.remove_old_dir("Somedir", "someBuildUuid", ["someFile"])
        self.assertEqual(0, mock_rm.call_count)

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
            }
        }, {
            '_index': 'someindex',
            '_source': {
                '@timestamp': '2022-02-28T09:39:09.610000',
                'field': 'test',
                'message': 'Updating repositories'
            }
        }]
        chunk_text = list(logsender.doc_iter(
            text, 'someindex', {'field': 'test'}))
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
            'api_compute_get': 17,
            'api_compute_largest': 2568,
            'api_compute_post': 20,
            'api_identity_get': 1174,
            'api_identity_largest': 3856,
            'api_identity_post': 283,
            'api_identity_put': 34,
            'api_image_get': 2,
            'api_image_largest': 1410,
            'api_image_post': 1,
            'api_image_put': 1,
            'api_info_get': 4,
            'api_info_largest': 1659,
            'api_placement_get': 9,
            'api_placement_largest': 1609,
            'api_placement_post': 1,
            'api_placement_put': 2,
            'api_v2.0_get': 19,
            'api_v2.0_largest': 10862,
            'api_v2.0_post': 9,
            'api_v2.0_put': 3,
            'api_volume_get': 2,
            'api_volume_largest': 758,
            'api_volume_post': 2,
            'db_cinder_delete': 1,
            'db_cinder_insert': 1,
            'db_cinder_select': 52,
            'db_cinder_update': 7,
            'db_keystone_select': 59,
            'db_neutron_delete': 1,
            'db_neutron_select': 10,
            'db_neutron_update': 1,
            'db_nova_cell0_select': 33,
            'db_nova_cell0_update': 12,
            'db_nova_cell1_select': 32,
            'db_nova_cell1_update': 12,
            'db_placement_select': 4,
            'hostname': 'ubuntu-focal-ovh-gra1-0029678038',
            'service_devstack@c-api.service_memorycurrent': 256569344,
            'service_devstack@c-bak.service_memorycurrent': 135827456,
            'service_devstack@c-sch.service_memorycurrent': 112668672,
            'service_devstack@c-vol.service_memorycurrent': 150151168,
            'service_devstack@etcd.service_memorycurrent': 80420864,
            'service_devstack@g-api.service_memorycurrent': 241049600,
            'service_devstack@keystone.service_memorycurrent': 260157440,
            'service_devstack@memory_tracker.service_memorycurrent': 5562368,
            'service_devstack@n-api-meta.service_memorycurrent': 223076352,
            'service_devstack@n-api.service_memorycurrent': 261332992,
            'service_devstack@n-cond-cell1.service_memorycurrent': 171405312,
            'service_devstack@n-cpu.service_memorycurrent': 138313728,
            'service_devstack@n-novnc-cell1.service_memorycurrent': 110931968,
            'service_devstack@n-sch.service_memorycurrent': 162050048,
            'service_devstack@n-super-cond.service_memorycurrent': 162463744,
            'service_devstack@placement-api.service_memorycurrent': 166539264,
            'service_devstack@q-ovn-metadata-agent.service_memorycurrent':
            222007296,
            'service_devstack@q-svc.service_memorycurrent': 422805504,
            'service_devstack@s-account.service_memorycurrent': 62246912,
            'service_devstack@s-container-sync.service_memorycurrent':
            45375488,
            'service_devstack@s-container.service_memorycurrent': 64376832,
            'service_devstack@s-object.service_memorycurrent': 64589824,
            'service_devstack@s-proxy.service_memorycurrent': 81174528}

        fields = logsender.makeJsonFields(performance_json)
        self.assertEqual(expected_fields, fields)

    def test_makeJsonFields_incorrect_values(self):
        expected_fields = {
            'api_placement_largest': 2151,
            'hostname': 'ubuntu-focal-rax-iad-0030685864',
            'service_apache2.service_memorycurrent': 0
        }
        expected_fields_alt = {
            'hostname': 'np0033916789',
            'service_apache2.service_memorycurrent': 0
        }

        json_content = {
            "services": [
                {"service": "apache2.service", "MemoryCurrent": "[not set]"}],
            "db": [{"db": "glance", "op": "DELETE", "count": "[not set]"}],
            "api": [{
                "service": "placement",
                "largest": 2151,
                "nova-scheduler-GET": "[not set]"
            }],
            "report": {
                "timestamp": "2022-08-10T13:51:50.928521",
                "hostname": "ubuntu-focal-rax-iad-0030685864",
                "version": 2
            }
        }

        json_content_alt = {
            "services": [
                {
                    "service": "apache2.service",
                    "MemoryCurrent": 18446744073709551615
                }
            ],
            "db": [],
            "processes": [],
            "api": [],
            "report": {
                "timestamp": "2023-05-02T15:40:49.770732",
                "hostname": "np0033916789",
                "version": 2
            }
        }

        fields = logsender.makeJsonFields(json.dumps(json_content))
        fields_alt = logsender.makeJsonFields(json.dumps(json_content_alt))
        self.assertEqual(expected_fields, fields)
        self.assertEqual(expected_fields_alt, fields_alt)

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
             datetime.datetime(datetime.date.today().year, 3, 31, 4, 50, 23,
                               795700)),
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
        self.assertEqual((expected_index, None, None), index)

    @mock.patch('logscraper.logsender.send')
    @mock.patch('logscraper.logsender.get_index')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", workers=2, index='myindex',
                performance_index_prefix="perf",
                subunit_index_prefix="subunit"))
    def test_prepare_and_send(self, mock_args, mock_index, mock_send):
        args = logsender.get_arguments()
        ready_directories = {'builduuid': ['job-result.txt']}
        mock_index.return_value = (args.index, args.performance_index_prefix,
                                   args.subunit_index_prefix)
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
                                          args.performance_index_prefix,
                                          args.subunit_index_prefix))


class TestSubunit(base.TestCase):
    def setUp(self):
        super().setUp()

        subunit_parsed_fields_1 = copy.deepcopy(parsed_fields)
        subunit_parsed_fields_1.update({
            'test_name':
                'setUpClass (neutron_tempest_plugin.scenario.'
                'test_dns_integration.'
                'DNSIntegrationDomainPerProjectTests)',
            'test_duration': 0.0,
            'test_status': 'skip',
            '@timestamp': '2022-09-21T08:10:06Z'
        })

        subunit_parsed_fields_2 = copy.deepcopy(parsed_fields)
        subunit_parsed_fields_2.update({
            'test_name':
                'neutron_tempest_plugin.scenario.test_dns_integration.'
                'DNSIntegrationAdminTests.'
                'test_fip_admin_delete',
            'test_duration': 7.103220,
            'test_status': 'success',
            '@timestamp': '2022-09-21T08:10:20Z'
        })

        subunit_parsed_fields_3 = copy.deepcopy(parsed_fields)
        subunit_parsed_fields_3.update({
            'test_name':
                'neutron_tempest_plugin.scenario.test_dns_integration.'
                'DNSIntegrationExtraTests.'
                'test_port_with_publishing_subnet',
            'test_duration': 9.188214,
            'test_status': 'success',
            '@timestamp': '2022-09-21T08:10:20Z'
        })

        subunit_parsed_fields_4 = copy.deepcopy(parsed_fields)
        subunit_parsed_fields_4.update({
            'test_name':
                'neutron_tempest_plugin.scenario.test_dns_integration.'
                'DNSIntegrationTests.'
                'test_fip',
            'test_duration': 6.738004,
            'test_status': 'success',
            '@timestamp': '2022-09-21T08:10:23Z'
        })

        subunit_parsed_fields_5 = copy.deepcopy(parsed_fields)
        subunit_parsed_fields_5.update({
            'test_name':
                'neutron_tempest_plugin.scenario.test_dns_integration.'
                'DNSIntegrationAdminTests.'
                'test_port_on_special_network',
            'test_duration': 6.611149,
            'test_status': 'success',
            '@timestamp': '2022-09-21T08:10:27Z'
        })

        subunit_parsed_fields_6 = copy.deepcopy(parsed_fields)
        subunit_parsed_fields_6.update({
            'test_name':
                'neutron_tempest_plugin.scenario.test_dns_integration.'
                'DNSIntegrationTests.'
                'test_server_with_fip',
            'test_duration': 30.278503,
            'test_status': 'success',
            '@timestamp': '2022-09-21T08:10:30Z'
        })

        self.subunit_docs = [
            {
                '_index': 'subunit',
                '_source': subunit_parsed_fields_1
            },
            {
                '_index': 'subunit',
                '_source': subunit_parsed_fields_2
            },
            {
                '_index': 'subunit',
                '_source': subunit_parsed_fields_3
            },
            {
                '_index': 'subunit',
                '_source': subunit_parsed_fields_4
            },
            {
                '_index': 'subunit',
                '_source': subunit_parsed_fields_5
            },
            {
                '_index': 'subunit',
                '_source': subunit_parsed_fields_6
            }
        ]

    def test_subunit_iter(self):
        subunit_file_name = os.path.join(os.path.dirname(__file__),
                                         "testrepository.subunit")
        subunit_index_name = "subunit"

        result = list(logsender.subunit_iter(file_name=subunit_file_name,
                                             index=subunit_index_name,
                                             es_fields=parsed_fields))
        self.assertEqual(result, self.subunit_docs)

    @mock.patch('opensearchpy.helpers.bulk')
    @mock.patch('argparse.ArgumentParser.parse_args', return_value=FakeArgs(
                directory="/tmp/testdir", index="myindex", workers=1,
                chunk_size=1000, config='test.yaml', skip_debug=False,
                performance_index_prefix="perf",
                subunit_index_prefix="subunit"))
    def test_send_to_es_subunit(self, mock_args, mock_bulk):
        build_file = os.path.join(os.path.dirname(__file__),
                                  "testrepository.subunit")
        es_fields = parsed_fields
        es_client = mock.Mock()
        args = logsender.get_arguments()
        logsender.send_to_es(build_file, es_fields, es_client, args.index,
                             args.chunk_size, args.skip_debug,
                             args.performance_index_prefix,
                             args.subunit_index_prefix)

        bulk_arg_docs = list(mock_bulk.call_args.args[1])
        self.assertEqual(bulk_arg_docs, self.subunit_docs)
