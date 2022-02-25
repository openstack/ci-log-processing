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

import json

from logscraper import logscraper
from logscraper.tests import base
from unittest import mock


builds_result = [{
    'uuid': 'a0f8968bf8534409bb998e079b41d658',
    'job_name': 'openstack-tox-py38',
    'result': 'SUCCESS',
    'held': False,
    'start_time': '2021-11-04T08:21:19',
    'end_time': '2021-11-04T08:26:26',
    'duration': 307.0,
    'voting': True,
    'log_url': 'https://t.com/openstack/a0f8968/',
    'nodeset': 'ubuntu-focal',
    'error_detail': None,
    'final': True,
    'artifacts': [],
    'provides': [],
    'project': 'openstack/tempest',
    'branch': 'master',
    'pipeline': 'check',
    'change': 806255,
    'patchset': '9',
    'ref': 'refs/changes/55/806255/9',
    'newrev': None,
    'ref_url': 'https://review.opendev.org/806255',
    'event_id': 'cfa1a0a471f3447ca9b81b20132234bd',
    'buildset': {
        'uuid': 'bf11828235c649ff859ad87d7c4aa525'
    }
}, {
    'uuid': '39828646e9b847b6b8560df93838c405',
    'job_name': 'tripleo-centos-8',
    'result': 'FAILURE',
    'held': False,
    'start_time': '2021-11-04T08:17:46',
    'end_time': '2021-11-04T08:27:49',
    'duration': 603.0,
    'voting': True,
    'log_url': 'https://t.com/tripleo-8/3982864/',
    'nodeset': 'centos-8-stream',
    'error_detail': None,
    'final': True,
    'artifacts': [],
    'provides': [],
    'project': 'openstack/tripleo-ansible',
    'branch': 'master',
    'pipeline': 'check',
    'change': 816445,
    'patchset': '1',
    'ref': 'refs/changes/45/816445/1',
    'newrev': None,
    'ref_url': 'https://review.opendev.org/816445',
    'event_id': '0b8a45988023464fba508d72e51e23ad',
    'buildset': {
        'uuid': '4a0ffebe30a94efe819fffc03cf33ea4'
    }
}, {
    'uuid': 'a3fbc73ce599466e9ae1645f6b708f1b',
    'job_name': 'openstack-tox-lower-constraints',
    'result': 'ABORTED',
    'held': False,
    'start_time': '2021-11-04T08:04:34',
    'end_time': '2021-11-04T08:04:52',
    'duration': 18,
    'voting': True,
    'log_url': None,
    'nodeset': 'ubuntu-bionic',
    'error_detail': None,
    'final': True,
    'artifacts': [],
    'provides': [],
    'project': 'openstack/nova',
    'branch': 'stable/victoria',
    'pipeline': 'check',
    'change': 816486,
    'patchset': '1',
    'ref': 'refs/changes/86/816486/1',
    'newrev': None,
    'ref_url': 'https://review.opendev.org/816486',
    'event_id': '7be89d6aae0944949c3e1b7c811794b0',
    'buildset': {'uuid': 'bd044dfe3ecc484fbbf74fdeb7fb56aa'}
}]


class _MockedPoolMapResult:
    def __init__(self, func, iterable):
        self.func = func
        self.iterable = iterable

        # mocked results
        self._value = [self.func(i) for i in iterable]

    def get(self, timeout=0):
        return self._value


class FakeArgs(object):
    def __init__(self, zuul_api_url=None, gearman_server=None,
                 gearman_port=None, follow=False, insecure=False,
                 checkpoint_file=None, ignore_checkpoint=None,
                 logstash_url=None, workers=None, max_skipped=None,
                 job_name=None, download=None, directory=None):

        self.zuul_api_url = zuul_api_url
        self.gearman_server = gearman_server
        self.gearman_port = gearman_port
        self.follow = follow
        self.insecure = insecure
        self.checkpoint_file = checkpoint_file
        self.ignore_checkpoint = ignore_checkpoint
        self.logstash_url = logstash_url
        self.workers = workers
        self.max_skipped = max_skipped
        self.job_name = job_name
        self.download = download
        self.directory = directory


class TestScraper(base.TestCase):
    def test_parse_version(self):
        ver1 = logscraper.parse_version('4.6.0-1.el7')
        ver2 = logscraper.parse_version('4.10.2.dev6-22f04be1')
        ver3 = logscraper.parse_version('4.10.2.dev6 22f04be1')
        self.assertEqual('4.6', ver1)
        self.assertEqual('4.10.2', ver2)
        self.assertEqual('4.10.2', ver3)
        self.assertRaises(ValueError,
                          logscraper.parse_version, '123412test123')

    @mock.patch('requests.get')
    def test_filter_available_jobs(self, mock_requests):
        # defined jobs: https://zuul.opendev.org/api/tenant/openstack/jobs
        example_jobs = [{
            "name": "openstack-tox-py38",
            "description": "Some description",
            "variants": [{
                "parent": "zuul-tox"
            }]
        }, {
            "name": "openstack-tox-py27",
            "description": "Some other description",
            "variants": [{
                "parent": "zuul-tox"
            }]
        }]
        mock_requests.raise_for_status = mock.Mock()
        mock_requests.return_value.json.return_value = example_jobs
        job_names = ['openstack-tox-py38']
        result = logscraper.filter_available_jobs(
            'http://somehost.com/api/tenant/tenant1', job_names, False)
        self.assertEqual(['openstack-tox-py38'], result)

    @mock.patch('logscraper.logscraper.filter_available_jobs',
                side_effect=[['testjob1', 'testjob2'], [], []])
    @mock.patch('logscraper.logscraper.run_scraping')
    def test_run_with_jobs(self, mock_scraping, mock_jobs):
        # when multiple job name provied, its iterate on zuul jobs
        # if such job is available.
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url=['http://somehost.com/api/tenant/tenant1',
                              'http://somehost.com/api/tenant/tenant2',
                              'http://somehost.com/api/tenant/tenant3'],
                gearman_server='localhost',
                job_name=['testjob1', 'testjob2'])
            args = logscraper.get_arguments()
            logscraper.run(args)
            self.assertEqual(2, mock_scraping.call_count)

    @mock.patch('socket.socket')
    def test_check_connection(self, mock_socket):
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='somehost.com',
                gearman_server='localhost',
                logstash_url='localhost:9999')
            args = logscraper.get_arguments()
            logscraper.check_connection(args.logstash_url)
            self.assertTrue(mock_socket.called)

    @mock.patch('socket.socket')
    def test_check_connection_wrong_host(self, mock_socket):
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='somehost.com',
                gearman_server='localhost',
                logstash_url='localhost')
            args = logscraper.get_arguments()
            self.assertRaises(ValueError, logscraper.check_connection,
                              args.logstash_url)

    @mock.patch('logscraper.logscraper.get_builds',
                return_value=iter([{'uuid': '1234'}]))
    def test_get_last_job_results(self, mock_get_builds):
        job_result = logscraper.get_last_job_results(
            'http://somehost.com/api/tenant/tenant1', False, '1234',
            'someuuid', None)
        self.assertEqual([{'uuid': '1234'}], list(job_result))
        self.assertEqual(1, mock_get_builds.call_count)

    @mock.patch('logscraper.logscraper.get_builds',
                return_value=iter([{'uuid': '1234'}]))
    def test_get_last_job_results_wrong_max_skipped(self, mock_get_builds):
        def make_fake_list(x):
            return list(x)

        job_result = logscraper.get_last_job_results(
            'http://somehost.com/api/tenant/tenant1', False, 'somevalue',
            'someuuid', None)
        self.assertRaises(ValueError, make_fake_list, job_result)

    @mock.patch('logscraper.logscraper.save_build_info')
    @mock.patch('logscraper.logscraper.check_specified_files')
    @mock.patch('builtins.open', new_callable=mock.mock_open())
    @mock.patch('os.path.isfile')
    @mock.patch('logscraper.logscraper.check_specified_files',
                return_value=['job-output.txt'])
    @mock.patch('logscraper.logscraper.LogMatcher.submitJobs')
    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=FakeArgs(
                    zuul_api_url=['http://somehost.com/api/tenant/tenant1'],
                    gearman_server='localhost',
                    gearman_port=4731,
                    workers=1))
    def test_run_scraping(self, mock_args, mock_submit, mock_files,
                          mock_isfile, mock_readfile, mock_specified_files,
                          mock_save_buildinfo):
        with mock.patch('logscraper.logscraper.get_last_job_results'
                        ) as mock_job_results:
            with mock.patch('multiprocessing.pool.Pool.map',
                            lambda self, func, iterable, chunksize=None,
                            callback=None, error_callback=None:
                            _MockedPoolMapResult(func, iterable)):
                args = logscraper.get_arguments()
                mock_job_results.return_value = [builds_result[0]]
                logscraper.run_scraping(
                    args, 'http://somehost.com/api/tenant/tenant1')
                self.assertEqual(builds_result[0]['uuid'],
                                 mock_submit.call_args.args[2]['uuid'])
                self.assertTrue(mock_submit.called)
                self.assertEqual(builds_result[0],
                                 mock_specified_files.call_args.args[0])
                self.assertFalse(mock_save_buildinfo.called)

    @mock.patch('logscraper.logscraper.run_scraping')
    def test_run(self, mock_scraping):
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url=['http://somehost.com/api/tenant/tenant1',
                              'http://somehost.com/api/tenant/tenant2',
                              'http://somehost.com/api/tenant/tenant3'],
                gearman_server='localhost')
            args = logscraper.get_arguments()
            logscraper.run(args)
            self.assertEqual(3, mock_scraping.call_count)

    @mock.patch('logscraper.logscraper.save_build_info')
    @mock.patch('logscraper.logscraper.check_specified_files')
    @mock.patch('builtins.open', new_callable=mock.mock_open())
    @mock.patch('os.path.isfile')
    @mock.patch('logscraper.logscraper.check_specified_files',
                return_value=['job-output.txt'])
    @mock.patch('logscraper.logscraper.LogMatcher.submitJobs')
    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=FakeArgs(
                    zuul_api_url=['http://somehost.com/api/tenant/tenant1'],
                    workers=1, download=True, directory="/tmp/testdir"))
    def test_run_scraping_download(self, mock_args, mock_submit, mock_files,
                                   mock_isfile, mock_readfile,
                                   mock_specified_files, mock_save_buildinfo):
        with mock.patch('logscraper.logscraper.get_last_job_results'
                        ) as mock_job_results:
            with mock.patch(
                    'multiprocessing.pool.Pool.map',
                    lambda self, func, iterable, chunksize=None, callback=None,
                    error_callback=None: _MockedPoolMapResult(func, iterable),
            ):
                args = logscraper.get_arguments()
                mock_job_results.return_value = [builds_result[0]]
                logscraper.run_scraping(
                    args, 'http://somehost.com/api/tenant/tenant1')

            self.assertFalse(mock_submit.called)
            self.assertTrue(mock_specified_files.called)
            self.assertEqual(builds_result[0],
                             mock_specified_files.call_args.args[0])
            self.assertTrue(mock_save_buildinfo.called)


class TestConfig(base.TestCase):
    @mock.patch('sys.exit')
    def test_save(self, mock_sys):
        # Assume that url is wrong so it raise IndexError
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='somehost.com',
                gearman_server='localhost')
            args = logscraper.get_arguments()
            self.assertRaises(IndexError, logscraper.Config, args,
                              args.zuul_api_url)
        # url without tenant
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='https://somehost.com',
                gearman_server='localhost')
            args = logscraper.get_arguments()
            logscraper.Config(args, args.zuul_api_url)
            mock_sys.assert_called()

        # correct url without job name
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='http://somehost.com/api/tenant/sometenant',
                gearman_server='localhost',
                checkpoint_file='/tmp/testfile')
            args = logscraper.get_arguments()
            with mock.patch('builtins.open',
                            new_callable=mock.mock_open()
                            ) as mock_file:
                some_config = logscraper.Config(args, args.zuul_api_url)
                some_config.save('123412312341234')
                mock_file.assert_called_with('/tmp/testfile-sometenant', 'w')


class TestLogMatcher(base.TestCase):
    @mock.patch('gear.TextJob')
    @mock.patch('gear.Client.submitJob')
    @mock.patch('gear.BaseClient.waitForServer')
    def test_submitJobs(self, mock_gear, mock_gear_client, mock_gear_job):
        result = builds_result[0]
        result['files'] = ['job-output.txt']
        result['tenant'] = 'sometenant'
        parsed_job = {
            "build_branch": "master",
            "build_change": 806255,
            "build_name": "openstack-tox-py38",
            "build_node": "zuul-executor",
            "build_patchset": "9",
            "build_queue": "check",
            "build_ref": "refs/changes/55/806255/9",
            "build_set": {"uuid": "bf11828235c649ff859ad87d7c4aa525"},
            "build_status": "SUCCESS",
            "build_uuid": "bf11828235c649ff859ad87d7c4aa525",
            "build_zuul_url": "N/A",
            "filename": "job-output.txt",
            "log_url": "https://t.com/openstack/a0f8968/job-output.txt",
            "node_provider": "local",
            "project": "openstack/tempest",
            "tenant": "sometenant",
            "voting": 1}

        expected_gear_job = {"retry": False, "event": {
            "fields": parsed_job,
            "tags": ["job-output.txt", "console", "console.html"]},
            "source_url": "https://t.com/openstack/a0f8968/job-output.txt"}

        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='http://somehost.com/api/tenant/sometenant',
                gearman_server='localhost',
                gearman_port='4731')
            args = logscraper.get_arguments()
            lmc = logscraper.LogMatcher(args.gearman_server, args.gearman_port,
                                        result['result'], result['log_url'],
                                        {})
            lmc.submitJobs('push-log', result['files'], result)
            mock_gear_client.assert_called_once()
            self.assertEqual(
                expected_gear_job,
                json.loads(mock_gear_job.call_args.args[1].decode('utf-8'))
            )

    @mock.patch('gear.TextJob')
    @mock.patch('gear.Client.submitJob')
    @mock.patch('gear.BaseClient.waitForServer')
    def test_submitJobs_failure(self, mock_gear, mock_gear_client,
                                mock_gear_job):
        # Take job result that build_status is "ABORTED"
        result = builds_result[1]
        result['files'] = ['job-output.txt']
        result['tenant'] = 'sometenant'
        parsed_job = {
            'build_branch': 'master',
            'build_change': 816445,
            'build_name': 'tripleo-centos-8',
            'build_node': 'zuul-executor',
            'build_patchset': '1',
            'build_queue': 'check',
            'build_ref': 'refs/changes/45/816445/1',
            'build_set': {'uuid': '4a0ffebe30a94efe819fffc03cf33ea4'},
            'build_status': 'FAILURE',
            'build_uuid': '4a0ffebe30a94efe819fffc03cf33ea4',
            'build_zuul_url': 'N/A',
            'filename': 'job-output.txt',
            'log_url': 'https://t.com/tripleo-8/3982864/job-output.txt',
            'node_provider': 'local',
            'project': 'openstack/tripleo-ansible',
            'tenant': 'sometenant',
            'voting': 1}

        expected_gear_job = {"retry": False, "event": {
            "fields": parsed_job,
            "tags": ["job-output.txt", "console", "console.html"]},
            "source_url": "https://t.com/tripleo-8/3982864/job-output.txt"}

        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='http://somehost.com/api/tenant/sometenant',
                gearman_server='localhost',
                gearman_port='4731')
            args = logscraper.get_arguments()
            lmc = logscraper.LogMatcher(args.gearman_server, args.gearman_port,
                                        result['result'], result['log_url'],
                                        {})
            lmc.submitJobs('push-log', result['files'], result)
            mock_gear_client.assert_called_once()
            self.assertEqual(
                expected_gear_job,
                json.loads(mock_gear_job.call_args.args[1].decode('utf-8'))
            )

    @mock.patch('gear.TextJob')
    @mock.patch('gear.Client.submitJob')
    @mock.patch('gear.BaseClient.waitForServer')
    def test_submitJobs_aborted(self, mock_gear, mock_gear_client,
                                mock_gear_job):
        # Take job result that build_status is "ABORTED"
        result = builds_result[2]
        result['files'] = ['job-output.txt']
        result['tenant'] = 'sometenant'
        parsed_job = {
            'build_branch': 'stable/victoria',
            'build_change': 816486,
            'build_name': 'openstack-tox-lower-constraints',
            'build_node': 'zuul-executor',
            'build_patchset': '1',
            'build_queue': 'check',
            'build_ref': 'refs/changes/86/816486/1',
            'build_set': {'uuid': 'bd044dfe3ecc484fbbf74fdeb7fb56aa'},
            'build_status': 'FAILURE',
            'build_uuid': 'bd044dfe3ecc484fbbf74fdeb7fb56aa',
            'build_zuul_url': 'N/A',
            'filename': 'job-output.txt',
            'log_url': 'job-output.txt',
            'node_provider': 'local',
            'project': 'openstack/nova',
            'tenant': 'sometenant',
            'voting': 1}

        # NOTE: normally ABORTED jobs does not provide log_url,
        # so source_url will be just a file to iterate.
        # In the logscraper, aborted jobs are just skipped.
        expected_gear_job = {"retry": False, "event": {
            "fields": parsed_job,
            "tags": ["job-output.txt", "console", "console.html"]},
            "source_url": "job-output.txt"}

        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='http://somehost.com/api/tenant/sometenant',
                gearman_server='localhost',
                gearman_port='4731')
            args = logscraper.get_arguments()
            lmc = logscraper.LogMatcher(args.gearman_server, args.gearman_port,
                                        result['result'], result['log_url'],
                                        {})
            lmc.submitJobs('push-log', result['files'], result)
            mock_gear_client.assert_called_once()
            self.assertEqual(
                expected_gear_job,
                json.loads(mock_gear_job.call_args.args[1].decode('utf-8'))
            )
