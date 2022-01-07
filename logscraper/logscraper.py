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
"""


import argparse
import gear
import json
import logging
import multiprocessing
import requests
import socket
import sys
import time
import urllib
import yaml

from distutils.version import StrictVersion as s_version
import tenacity


file_to_check = [
    "job-output.txt.gz",
    "job-output.txt",
    "postci.txt",
    "postci.txt.gz",
    "var/log/extra/logstash.txt",
    "var/log/extra/logstash.txt.gz",
    "var/log/extra/errors.txt",
    "var/log/extra/errors.txt.gz",
]

# From: https://opendev.org/opendev/base-jobs/src/branch/master/roles/submit-logstash-jobs/defaults/main.yaml # noqa
logstash_processor_config = """
files:
  - name: job-output.txt
    tags:
      - console
      - console.html
  - name: grenade.sh.txt
    tags:
      - console
      - console.html
  - name: devstacklog.txt(?!.*summary)
    tags:
      - console
      - console.html
  - name: apache/keystone.txt
    tags:
      - screen
      - oslofmt
  - name: apache/horizon_error.txt
    tags:
      - apacheerror
  # TODO(clarkb) Add swift proxy logs here.
  - name: syslog.txt
    tags:
      - syslog
  - name: tempest.txt
    tags:
      - screen
      - oslofmt
  - name: javelin.txt
    tags:
      - screen
      - oslofmt
  # Neutron index log files (files with messages from all test cases)
  - name: dsvm-functional-index.txt
    tags:
      - oslofmt
  - name: dsvm-fullstack-index.txt
    tags:
      - oslofmt
  - name: screen-s-account.txt
    tags:
      - screen
      - apachecombined
  - name: screen-s-container.txt
    tags:
      - screen
      - apachecombined
  - name: screen-s-object.txt
    tags:
      - screen
      - apachecombined
  # tripleo logs
  - name: postci.txt
    tags:
      - console
      - postci
  - name: var/log/extra/logstash.txt
    tags:
      - console
      - postci
  - name: var/log/extra/errors.txt
    tags:
      - console
      - errors
  # wildcard logs
  - name: devstack-gate-.*.txt
    tags:
      - console
      - console.html
  # NOTE(mriedem): Logs that are known logstash index OOM killers are
  # blacklisted here until fixed.
  # screen-monasca-persister.txt: https://storyboard.openstack.org/#!/story/2003911
  # screen-ovn-northd.txt: https://bugs.launchpad.net/networking-ovn/+bug/1795069
  - name: screen-(?!(peakmem_tracker|dstat|karaf|kubelet|mistral-engine|monasca-persister|monasca-api|ovn-northd|q-svc)).*.txt
    tags:
      - screen
      - oslofmt
"""  # noqa


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


###############################################################################
#                                    CLI                                      #
###############################################################################
def get_arguments():
    parser = argparse.ArgumentParser(description="Fetch and push last Zuul "
                                     "CI job logs into gearman.")
    parser.add_argument("--zuul-api-url", help="URL(s) for Zuul API. Parameter"
                        " can be set multiple times.",
                        required=True,
                        action='append')
    parser.add_argument("--gearman-server", help="Gearman host addresss",
                        required=True)
    parser.add_argument("--gearman-port", help="Gearman listen port. "
                        "Defaults to 4730.",
                        default=4730)
    parser.add_argument("--follow", help="Keep polling zuul builds",
                        action="store_true")
    parser.add_argument("--insecure", help="Skip validating SSL cert",
                        action="store_false")
    parser.add_argument("--checkpoint-file", help="File that will keep "
                        "information about last uuid timestamp for a job.")
    parser.add_argument("--logstash-url", help="When provided, script will "
                        "check connection to Logstash service before sending "
                        "to log processing system. For example: "
                        "logstash.local:9999")
    parser.add_argument("--workers", help="Worker processes for logscraper",
                        default=1)
    parser.add_argument("--max-skipped", help="How many job results should be "
                        "checked until last uuid written in checkpoint file "
                        "is founded",
                        default=500)
    parser.add_argument("--debug", help="Print more information",
                        action="store_true")
    args = parser.parse_args()
    return args


###############################################################################
#                      Configuration of this process                          #
###############################################################################
class Config:
    def __init__(self, args, zuul_api_url):
        self.checkpoint = None
        url_path = zuul_api_url.split("/")
        if url_path[-3] != "api" and url_path[-2] != "tenant":
            print(
                "ERROR: zuul-api-url needs to be in the form "
                "of: https://<fqdn>/api/tenant/<tenant-name>"
            )
            sys.exit(1)
        self.tenant = url_path[-1]

        self.filename = "%s-%s" % (args.checkpoint_file, self.tenant)
        try:
            with open(self.filename) as f:
                self.checkpoint = f.readline()
        except Exception:
            logging.exception("Can't load the checkpoint. Creating file")

    def save(self, job_uuid):
        try:
            with open(self.filename, 'w') as f:
                f.write(job_uuid)
        except Exception as e:
            raise("Can not write status to the checkpoint file %s" % e)


###############################################################################
#                             Log Processing                                  #
###############################################################################
class LogMatcher(object):
    def __init__(self, server, port, success, log_url, host_vars):
        self.client = gear.Client()
        self.client.addServer(server, port)
        self.hosts = host_vars
        self.success = success
        self.log_url = log_url

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
        config_files = yaml.safe_load(logstash_processor_config)
        for f in config_files["files"]:
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

        if "change" in result:
            fields["build_change"] = result["change"]
            fields["build_patchset"] = result["patchset"]
        elif "newrev" in result:
            fields["build_newrev"] = result.get("newrev", "UNKNOWN")

        fields["node_provider"] = "local"
        log_url = urllib.parse.urljoin(result["log_url"], filename)
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


def get_builds(zuul_url, insecure):
    """Yield builds dictionary."""
    pos, size = 0, 100
    zuul_url = zuul_url.rstrip("/")
    zuul_complete = _zuul_complete_available(zuul_url, insecure)
    if zuul_complete:
        extra = "" + zuul_complete
    base_url = zuul_url + "/builds?limit=" + str(size) + extra

    known_builds = set()
    while True:
        url = base_url + "&skip=" + str(pos)
        logging.info("Getting job results %s", url)
        jobs_result = requests_get_json(url, verify=insecure)

        for job in jobs_result:
            # It is important here to check we didn't yield builds twice,
            # as this can happen when using skip if new build get reported
            # between the two requests.
            if job["uuid"] not in known_builds:
                yield job
            known_builds.add(job["uuid"])
            pos += 1


def get_last_job_results(zuul_url, insecure, max_skipped, last_uuid):
    """Yield builds until we find the last uuid."""
    count = 0
    for build in get_builds(zuul_url, insecure):
        if count > int(max_skipped):
            break
        if build["uuid"] == last_uuid:
            break
        yield build
        count += 1


###############################################################################
#                              Log scraper                                    #
###############################################################################
def check_specified_files(job_result, insecure):
    """Return list of specified files if they exists on logserver. """
    available_files = []
    for f in file_to_check:
        if not job_result["log_url"]:
            continue
        response = requests_get("%s%s" % (job_result["log_url"], f),
                                insecure)
        if response.status_code == 200:
            available_files.append(f)
    return available_files


def setup_logging(debug):
    if debug:
        logging.basicConfig(format="%(asctime)s %(message)s",
                            level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.debug("Zuul Job Scraper is starting...")


def run_build(build):
    """Submit job informations into log processing system. """
    args = build.pop("build_args")

    logging.info(
        "Processing logs for %s | %s | %s | %s",
        build["job_name"],
        build["end_time"],
        build["result"],
        build["uuid"],
    )

    results = dict(files=[], jobs=[], invocation={})

    lmc = LogMatcher(
        args.gearman_server,
        args.gearman_port,
        build["result"],
        build["log_url"],
        {},
    )
    results["files"] = check_specified_files(build, args.insecure)

    lmc.submitJobs("push-log", results["files"], build)


def check_connection(logstash_url):
    """Return True when Logstash service is reachable

    Check if service is up before pushing results.
    """
    host, port = logstash_url.split(':')
    logging.debug("Checking connection to %s on port %s" % (host, port))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


def run_scraping(args, zuul_api_url):
    """Get latest job results and push them into log processing service.

    On the end, write newest uuid into checkpoint file, so in the future
    script will not push log duplication.
    """
    config = Config(args, zuul_api_url)

    builds = []
    for build in get_last_job_results(zuul_api_url, args.insecure,
                                      args.max_skipped, config.checkpoint):
        logging.debug("Working on build %s" % build['uuid'])
        # add missing informations
        build["tenant"] = config.tenant
        build["build_args"] = args
        builds.append(build)

    logging.info("Processing %d builds", len(builds))

    if args.logstash_url and not check_connection(args.logstash_url):
        logging.critical("Can not connect to logstash %s. "
                         "Is it up?" % args.logstash_url)
        return

    if builds:
        pool = multiprocessing.Pool(int(args.workers))
        try:
            pool.map(run_build, builds)
        finally:
            config.save(builds[0]['uuid'])


def run(args):
    for zuul_api_url in args.zuul_api_url:
        logging.info("Starting checking logs for %s" % zuul_api_url)
        run_scraping(args, zuul_api_url)


def main():
    args = get_arguments()
    setup_logging(args.debug)
    while True:
        run(args)
        if not args.follow:
            break
        time.sleep(120)


if __name__ == "__main__":
    main()