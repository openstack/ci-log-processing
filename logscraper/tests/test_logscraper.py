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

import datetime
import tempfile

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
}, {
    'uuid': '123473ce599466e9ae1645f6b123412',
    'job_name': 'openstack-tox-lower-constraints',
    'result': 'NODE_FAILURE',
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
    def __init__(self, zuul_api_url=None, follow=False, insecure=False,
                 checkpoint_file=None, ignore_checkpoint=None,
                 logstash_url=None, workers=None, max_skipped=None,
                 job_name=None, download=None, directory=None,
                 config=None, wait_time=None, ca_file=None,
                 file_list=None, monitoring_port=None, debug=None,
                 timeout=None):

        self.zuul_api_url = zuul_api_url
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
        self.config = config
        self.wait_time = wait_time
        self.ca_file = ca_file
        self.file_list = file_list
        self.monitoring_port = monitoring_port
        self.debug = debug
        self.timeout = timeout


class TestScraper(base.TestCase):

    def setUp(self):
        super(TestScraper, self).setUp()
        self.config_file = {
            'files': [{
                'name': 'job-output.txt',
                'tags': ['console', 'console.html']
            }]
        }

    @mock.patch('argparse.ArgumentParser.parse_args')
    def test_get_arguments(self, mock_args):
        mock_args.return_value = FakeArgs(
            zuul_api_url='somehost.com',
            debug=True,
            insecure=False,
            config='/tmp/somefile.conf'
        )
        m = mock.mock_open(read_data="[DEFAULT]\ndebug: False\n"
                           "insecure: True")
        with mock.patch('builtins.open', m) as mocked_open:
            args = logscraper.get_arguments()
            self.assertEqual(True, args.debug)
            self.assertEqual(False, args.insecure)
            mocked_open.assert_called_once()

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
            'http://somehost.com/api/tenant/tenant1', job_names, False, 10)
        self.assertEqual(['openstack-tox-py38'], result)

    @mock.patch('requests.get')
    @mock.patch('logscraper.logscraper.Monitoring')
    @mock.patch('logscraper.logscraper.filter_available_jobs',
                side_effect=[['testjob1', 'testjob2'], [], []])
    @mock.patch('logscraper.logscraper.run_scraping')
    def test_run_with_jobs(self, mock_scraping, mock_jobs, mock_monitoring,
                           mock_zuul):
        mock_zuul.side_effect = mock.PropertyMock(
            return_value=mock.Mock(status_code=200))
        # when multiple job name provied, its iterate on zuul jobs
        # if such job is available.
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url=['http://somehost.com/api/tenant/tenant1',
                              'http://somehost.com/api/tenant/tenant2',
                              'http://somehost.com/api/tenant/tenant3'],
                job_name=['testjob1', 'testjob2'])
            args = logscraper.get_arguments()
            logscraper.run(args, mock_monitoring)
            self.assertEqual(2, mock_scraping.call_count)

    @mock.patch('logscraper.logscraper.get_builds',
                return_value=iter([{'_id': '1234'}]))
    @mock.patch('argparse.ArgumentParser.parse_args')
    def test_get_last_job_results(self, mock_args, mock_get_builds):
        mock_args.return_value = FakeArgs(
            zuul_api_url='http://somehost.com/api/tenant/sometenant',
            checkpoint_file='/tmp/testfile')
        args = logscraper.get_arguments()
        some_config = logscraper.Config(args, args.zuul_api_url)
        job_result = logscraper.get_last_job_results(
            'http://somehost.com/api/tenant/tenant1', False, '1234',
            some_config.build_cache, None, 10)
        self.assertEqual([{'_id': '1234'}], list(job_result))
        self.assertEqual(1, mock_get_builds.call_count)

    @mock.patch('logscraper.logscraper.get_builds',
                return_value=iter([{'uuid': '1234'}]))
    def test_get_last_job_results_wrong_max_skipped(self, mock_get_builds):
        def make_fake_list(x):
            return list(x)

        job_result = logscraper.get_last_job_results(
            'http://somehost.com/api/tenant/tenant1', False, 'somevalue',
            'someuuid', None, 10)
        self.assertRaises(ValueError, make_fake_list, job_result)

    @mock.patch('sqlite3.connect', return_value=mock.MagicMock())
    @mock.patch('logscraper.logscraper.load_config')
    @mock.patch('logscraper.logscraper.save_build_info')
    @mock.patch('logscraper.logscraper.check_specified_files')
    @mock.patch('builtins.open', new_callable=mock.mock_open())
    @mock.patch('os.path.isfile')
    @mock.patch('logscraper.logscraper.check_specified_files',
                return_value=['job-output.txt'])
    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=FakeArgs(
                    zuul_api_url=['http://somehost.com/api/tenant/tenant1'],
                    workers=1))
    def test_run_scraping(self, mock_args,  mock_files,
                          mock_isfile, mock_readfile, mock_specified_files,
                          mock_save_buildinfo, mock_config, mock_sqlite):
        with mock.patch('logscraper.logscraper.get_last_job_results'
                        ) as mock_job_results:
            with mock.patch('multiprocessing.pool.Pool.map_async',
                            lambda self, func, iterable, chunksize=None,
                            callback=None, error_callback=None:
                            _MockedPoolMapAsyncResult(func, iterable)):
                args = logscraper.get_arguments()
                mock_job_results.return_value = [builds_result[0]]
                logscraper.run_scraping(
                    args, 'http://somehost.com/api/tenant/tenant1')
                self.assertEqual(builds_result[0],
                                 mock_specified_files.call_args.args[0])
                self.assertTrue(mock_save_buildinfo.called)

    @mock.patch('requests.get')
    @mock.patch('logscraper.logscraper.Monitoring')
    @mock.patch('logscraper.logscraper.run_scraping')
    def test_run(self, mock_scraping, mock_monitoring, mock_zuul):
        mock_zuul.side_effect = mock.PropertyMock(
            return_value=mock.Mock(status_code=200))
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url=['http://somehost.com/api/tenant/tenant1',
                              'http://somehost.com/api/tenant/tenant2',
                              'http://somehost.com/api/tenant/tenant3'],
            )
            args = logscraper.get_arguments()
            logscraper.run(args, mock_monitoring)
            self.assertEqual(3, mock_scraping.call_count)

    @mock.patch('sqlite3.connect', return_value=mock.MagicMock())
    @mock.patch('logscraper.logscraper.load_config')
    @mock.patch('logscraper.logscraper.save_build_info')
    @mock.patch('logscraper.logscraper.check_specified_files')
    @mock.patch('builtins.open', new_callable=mock.mock_open())
    @mock.patch('os.path.isfile')
    @mock.patch('logscraper.logscraper.check_specified_files',
                return_value=['job-output.txt'])
    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=FakeArgs(
                    zuul_api_url=['http://somehost.com/api/tenant/tenant1'],
                    workers=1, download=True, directory="/tmp/testdir"))
    def test_run_scraping_download(self, mock_args, mock_files,
                                   mock_isfile, mock_readfile,
                                   mock_specified_files, mock_save_buildinfo,
                                   mock_config, mock_sqlite):
        with mock.patch('logscraper.logscraper.get_last_job_results'
                        ) as mock_job_results:
            with mock.patch(
                    'multiprocessing.pool.Pool.map_async',
                    lambda self, func, iterable, chunksize=None, callback=None,
                    error_callback=None: _MockedPoolMapAsyncResult(
                        func, iterable),
            ):
                args = logscraper.get_arguments()
                mock_job_results.return_value = [builds_result[0]]
                logscraper.run_scraping(
                    args, 'http://somehost.com/api/tenant/tenant1')

            self.assertTrue(mock_specified_files.called)
            self.assertEqual(builds_result[0],
                             mock_specified_files.call_args.args[0])
            self.assertTrue(mock_save_buildinfo.called)

    @mock.patch('sqlite3.connect', return_value=mock.MagicMock())
    @mock.patch('logscraper.logscraper.load_config')
    @mock.patch('logscraper.logscraper.save_build_info')
    @mock.patch('logscraper.logscraper.check_specified_files')
    @mock.patch('builtins.open', new_callable=mock.mock_open())
    @mock.patch('os.path.isfile')
    @mock.patch('logscraper.logscraper.check_specified_files',
                return_value=['job-output.txt'])
    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=FakeArgs(
                    zuul_api_url=['http://somehost.com/api/tenant/tenant1'],
                    workers=1, download=True, directory="/tmp/testdir"))
    def test_run_scraping_monitoring(self, mock_args, mock_files,
                                     mock_isfile, mock_readfile,
                                     mock_specified_files, mock_save_buildinfo,
                                     mock_config, mock_sqlite):
        with mock.patch('logscraper.logscraper.get_last_job_results'
                        ) as mock_job_results:
            with mock.patch(
                    'multiprocessing.pool.Pool.map_async',
                    lambda self, func, iterable, chunksize=None, callback=None,
                    error_callback=None: _MockedPoolMapAsyncResult(
                        func, iterable),
            ):
                args = logscraper.get_arguments()
                mock_job_results.return_value = [builds_result[0]]
                monitoring = logscraper.Monitoring()
                logscraper.run_scraping(
                    args, 'http://somehost.com/api/tenant/tenant1',
                    monitoring=monitoring)

            self.assertEqual('job_name', monitoring.job_count._labelnames[0])
            self.assertEqual(2, len(monitoring.job_count._metrics))
            self.assertTrue(mock_specified_files.called)
            self.assertEqual(builds_result[0],
                             mock_specified_files.call_args.args[0])
            self.assertTrue(mock_save_buildinfo.called)

    @mock.patch('logscraper.logscraper.create_custom_result')
    @mock.patch('logscraper.logscraper.check_specified_files')
    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=FakeArgs(
                    zuul_api_url=['http://somehost.com/api/tenant/tenant1'],
                    workers=1, download=True, directory="/tmp/testdir"))
    def test_run_aborted_download(self, mock_args, mock_check_files,
                                  mock_custom_result):
        # Take job result that log_url is empty.
        result = builds_result[2]
        result['files'] = ['job-output.txt']
        result['tenant'] = 'sometenant'
        result['build_args'] = logscraper.get_arguments()
        result['config_file'] = self.config_file
        result_node_fail = builds_result[3]
        result_node_fail['files'] = ['job-output.txt']
        result_node_fail['tenant'] = 'sometenant'
        result_node_fail['build_args'] = logscraper.get_arguments()
        result_node_fail['config_file'] = self.config_file

        logscraper.run_build(result)
        logscraper.run_build(result_node_fail)
        self.assertFalse(mock_check_files.called)
        self.assertTrue(mock_custom_result.called)

    @mock.patch('logscraper.logscraper.create_custom_result')
    @mock.patch('logscraper.logscraper.check_specified_files')
    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=FakeArgs(
                    zuul_api_url=['http://somehost.com/api/tenant/tenant1'],
                    workers=1))
    def test_run_aborted(self, mock_args, mock_check_files,
                         mock_custom_result):
        # Take job result that build_status is "ABORTED" or "NODE_FAILURE"
        result = builds_result[2]
        result['files'] = ['job-output.txt']
        result['tenant'] = 'sometenant'
        result['build_args'] = logscraper.get_arguments()
        result['config_file'] = self.config_file
        result_node_fail = builds_result[3]
        result_node_fail['files'] = ['job-output.txt']
        result_node_fail['tenant'] = 'sometenant'
        result_node_fail['build_args'] = logscraper.get_arguments()
        result_node_fail['config_file'] = self.config_file

        logscraper.run_build(result)
        logscraper.run_build(result_node_fail)
        self.assertFalse(mock_check_files.called)
        self.assertTrue(mock_custom_result.called)

    @mock.patch('requests.get')
    @mock.patch('logscraper.logscraper.Monitoring')
    @mock.patch('logscraper.logscraper.run_scraping')
    def test_run_zuul_down(self, mock_scraping, mock_monitoring, mock_zuul):
        mock_zuul.side_effect = mock.PropertyMock(
            return_value=mock.Mock(status_code=400))

        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url=['http://somehost.com/api/tenant/tenant1',
                              'http://somehost.com/api/tenant/tenant2',
                              'http://somehost.com/api/tenant/tenant3'],
            )
            args = logscraper.get_arguments()

            logscraper.run(args, mock_monitoring)
            self.assertEqual(0, mock_scraping.call_count)

    def test_create_custom_result(self):
        build = builds_result[2]
        directory = '/tmp/'
        with mock.patch('builtins.open',
                        new_callable=mock.mock_open()
                        ) as mock_file:
            logscraper.create_custom_result(build, directory)
            self.assertTrue(mock_file.called)

    @mock.patch('requests.head')
    def test_cleanup_logs_to_check(self, mock_requests):
        # job-results.txt will be skipped as dir, so the file will be not
        # checked.
        mock_requests.side_effect = [mock.Mock(status_code=200),
                                     mock.Mock(status_code=200)]
        log_url = 'http://somefakeurl/'
        config_files = ['job-results.txt',
                        'zuul/logs/zuul/logs/compute/text.txt',
                        'zuul/logs/test.txt']
        files = logscraper.cleanup_logs_to_check(config_files, log_url, False,
                                                 10)
        self.assertListEqual(config_files, files)

    @mock.patch('requests.head')
    def test_cleanup_logs_to_check_not_found(self, mock_requests):
        mock_requests.side_effect = [mock.Mock(ok=False),
                                     mock.Mock(ok=False)]
        log_url = 'http://somefakeurl/'
        config_files = ['job-results.txt',
                        'zuul/logs/zuul/logs/compute/text.txt',
                        'zuul/logs/test.txt']
        files = logscraper.cleanup_logs_to_check(config_files, log_url, False,
                                                 10)
        self.assertListEqual(['job-results.txt'], files)

    @mock.patch('requests.head')
    def test_cleanup_logs_to_check_no_dir(self, mock_requests):
        mock_requests.side_effect = [mock.Mock(ok=True),
                                     mock.Mock(ok=False)]
        log_url = 'http://somefakeurl/'
        config_files = ['job-results.txt',
                        'compute/logs/atest.txt',
                        'zuul/logs/test.txt']
        files = logscraper.cleanup_logs_to_check(config_files, log_url, False,
                                                 10)
        self.assertEqual(2, len(files))

    @mock.patch('yaml.safe_load')
    @mock.patch('builtins.open', new_callable=mock.mock_open())
    def test_load_config(self, mock_open, mock_yaml):
        config_path = ['/tmp/config_1', '/tmp/config_2']
        config_1 = {'files': [{
            'name': 'job-output.txt',
            'tags': ['console', 'console.html']
        }, {'name': 'logs/undercloud/var/log/extra/logstash.txt',
            'tags': ['console', 'postpci']}]}
        config_2 = {'files': [{
            'name': 'new-job.txt',
            'tags': ['new-console']
        }, {'name': 'logs/some-file.log',
            'tags': ['postpci']}]}
        final_config = {'files': [{
            'name': 'job-output.txt',
            'tags': ['console', 'console.html']
        }, {
            'name': 'logs/undercloud/var/log/extra/logstash.txt',
            'tags': ['console', 'postpci']
        }, {
            'name': 'new-job.txt', 'tags': ['new-console']
        }, {
            'name': 'logs/some-file.log', 'tags': ['postpci']}]}
        mock_yaml.side_effect = [config_1, config_2]
        parsed_config = logscraper.load_config(config_path)
        self.assertEqual(final_config, parsed_config)

    @mock.patch('yaml.safe_load')
    @mock.patch('builtins.open', new_callable=mock.mock_open())
    def test_load_config_different_keys(self, mock_open, mock_yaml):
        config_path = ['/tmp/config_1', '/tmp/config_2']
        config_1 = {'files': [{
            'name': 'job-output.txt',
            'tags': ['console', 'console.html']
        }, {'name': 'logs/undercloud/var/log/extra/logstash.txt',
            'tags': ['console', 'postpci']}]}
        config_2 = {'files2': [{
            'name': 'new-job.txt',
            'tags': ['new-console']
        }, {'name': 'logs/some-file.log',
            'tags': ['postpci']}]}
        final_config = {'files': [{
            'name': 'job-output.txt',
            'tags': ['console', 'console.html']
        }, {'name': 'logs/undercloud/var/log/extra/logstash.txt',
            'tags': ['console', 'postpci']}
        ], 'files2': [{
            'name': 'new-job.txt',
            'tags': ['new-console']
        }, {'name': 'logs/some-file.log', 'tags': ['postpci']}]}
        mock_yaml.side_effect = [config_1, config_2]
        parsed_config = logscraper.load_config(config_path)
        self.assertEqual(final_config, parsed_config)


class TestConfig(base.TestCase):
    @mock.patch('sqlite3.connect', return_value=mock.MagicMock())
    @mock.patch('logscraper.logscraper.load_config')
    @mock.patch('sys.exit')
    def test_config_object(self, mock_sys, mock_config, mock_sqlite):
        # Assume that url is wrong so it raise IndexError
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='somehost.com',
            )
            args = logscraper.get_arguments()
            self.assertRaises(IndexError, logscraper.Config, args,
                              args.zuul_api_url)
        # url without tenant
        with mock.patch('argparse.ArgumentParser.parse_args') as mock_args:
            mock_args.return_value = FakeArgs(
                zuul_api_url='https://somehost.com',
            )
            args = logscraper.get_arguments()
            logscraper.Config(args, args.zuul_api_url)
            mock_sys.assert_called()

    @mock.patch('logscraper.logscraper.BuildCache.save')
    @mock.patch('logscraper.logscraper.BuildCache.clean')
    @mock.patch('argparse.ArgumentParser.parse_args')
    def test_save(self, mock_args, mock_clean, mock_save):
        # correct url without job name
        mock_args.return_value = FakeArgs(
            zuul_api_url='http://somehost.com/api/tenant/sometenant',
            checkpoint_file='/tmp/testfile')
        args = logscraper.get_arguments()
        some_config = logscraper.Config(args, args.zuul_api_url)
        some_config.save()
        mock_clean.assert_called_once()
        mock_save.assert_called_once()


class TestLogMatcher(base.TestCase):

    def setUp(self):
        super(TestLogMatcher, self).setUp()
        self.config_file = {
            'files': [{
                'name': 'job-output.txt',
                'tags': ['console', 'console.html']
            }]
        }

    @mock.patch('builtins.open', new_callable=mock.mock_open())
    @mock.patch('os.path.isfile')
    @mock.patch('requests.get')
    def test_ensure_file_downloaded(self, mock_requests, mock_is_file,
                                    mock_open):
        url = 'http://someurl.com'
        directory = '/tmp/logscraper'
        mock_is_file.return_value = False
        logscraper.ensure_file_downloaded(url, directory, False, 10)
        assert mock_requests.called

    @mock.patch('os.path.isfile')
    @mock.patch('requests.get')
    def test_ensure_file_downloaded_file_exists(self, mock_requests,
                                                mock_is_file):
        url = 'http://someurl.com'
        directory = '/tmp/logscraper'
        mock_is_file.return_value = True
        logscraper.ensure_file_downloaded(url, directory, False, 10)
        assert not mock_requests.called


class TestBuildCache(base.TestCase):

    @mock.patch('sqlite3.connect', return_value=mock.MagicMock())
    def test_create_db(self, mock_connect):
        filename = '/tmp/somefile'
        logscraper.BuildCache(filename)
        mock_connect.assert_called_with(filename)
        mock_connect.return_value.cursor.assert_called_once()

    @mock.patch('sqlite3.connect')
    def test_create_table(self, mock_connect):
        tmp_dir = tempfile.mkdtemp()
        filename = '%s/testfile' % tmp_dir
        logscraper.BuildCache(filename)
        mock_execute = mock_connect.return_value.cursor.return_value.execute
        mock_execute.assert_called()
        self.assertEqual('CREATE TABLE IF NOT EXISTS logscraper (uid INTEGER, '
                         'timestamp INTEGER)',
                         mock_execute.call_args_list[0].args[0])

    @mock.patch('sqlite3.connect')
    def test_fetch_data(self, mock_connect):
        tmp_dir = tempfile.mkdtemp()
        filename = '%s/testfile' % tmp_dir
        logscraper.BuildCache(filename)
        mock_execute = mock_connect.return_value.cursor.return_value.execute
        mock_execute.assert_called()
        self.assertEqual('SELECT uid, timestamp FROM logscraper',
                         mock_execute.call_args_list[3].args[0])

    def test_clean(self):
        # add old data
        tmp_dir = tempfile.mkdtemp()
        filename = '%s/testfile' % tmp_dir
        cache = logscraper.BuildCache(filename)
        current_build = {'ffeeddccbbaa': datetime.datetime.now().timestamp()}
        cache.builds['aabbccddeeff'] = 1647131633
        cache.builds.update(current_build)
        cache.save()
        # check cleanup
        cache = logscraper.BuildCache(filename)
        cache.clean()
        self.assertEqual(current_build, cache.builds)

    @mock.patch('sqlite3.connect')
    def test_save(self, mock_connect):
        tmp_dir = tempfile.mkdtemp()
        filename = '%s/testfile' % tmp_dir
        cache = logscraper.BuildCache(filename)
        cache.builds = {'ffeeddccbbaa': datetime.datetime.now().timestamp()}
        cache.save()
        mock_many = mock_connect.return_value.cursor.return_value.executemany
        mock_many.assert_called()
        expected_call = ('INSERT INTO logscraper VALUES (?,?)',
                         list(cache.builds.items()))
        self.assertEqual(expected_call, mock_many.call_args_list[0].args)
