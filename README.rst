OpenStack CI log processing
===========================

The goal of this repository is to provide and check
functionality of new log processing system base on
zuul log scraper tool.

Zuul Log Scraper
----------------

The Zuul Log Scraper tool is responsible for periodical
check by using Zuul CI API if there are new builds available
and if there are some, it would push the informations to
the log processing system.


Zuul Log Sender
---------------

The Zuul Log Sender tool is responsible for periodical check
directory, if there are some files that should be send to the
Elasticsearch service.
NOTE: build directories that does not provide files `buildinfo`
and `inventory.yaml` file are skipped.


Testing
-------

The part of OpenStack CI log processing runs a complete testing and
continuous-integration environment, powered by `Zuul
<https://zuul-ci.org/>`__.

Any changes to logscraper script or tests will trigger jobs to
thoroughly test those changes.


Benchmarking
------------

The large Zuul CI deployments requires many CI log processing resources.
In that case, we can do a benchmark with two log processing deployments.
All tests will do same:

  - send 100 log builds to Elasticsearch that is running on same host
  - logscraper will be using 4 workers
  - VM will have 8 vcpus, 16 GB of RAM

Testing workflows:

* loggearman and logstash

This workflow will spawn 3 additional loggearman workers because it this
service is a bottleneck in that log ci workflow.

You can do it with command:

.. code-block:: shell

   for i in {1..3}; do \
     podman run --network host -d --name loggearman-worker-$i \
      --volume /etc/loggearman:/etc/loggearman:z \
      --volume /var/log/loggearman:/var/log/loggearman:z \
      quay.rdoproject.org/software-factory/loggearman:latest \
      log-gearman-worker -c /etc/loggearman/worker.yml --foreground  -d /var/log/loggearman/worker.log

To remove:

.. code-block:: shell

   for i in {1..3}; do \
     podman stop loggearman-worker-$i ; podman rm loggearman-worker-$i


On the end, basic calucations:

.. code-block:: python

   import datetime
   start = datetime.datetime.fromisoformat("2022-02-28 16:44:59")
   stop = datetime.datetime.fromisoformat("2022-02-28 16:46:01")
   print((stop-start).total_seconds())


Time spend to run logscraper and wait for finish all loggearman workers took: 62 seconds and
it takes 680MB of RAM.


* logsender workflow

This workflow will only use logsender tool and it will push the logs
directly to the Elasticsearch service. Same as in previous test,
it will be executed on 4 processes.

To download logs:

.. code-block:: shell

   logscraper \
    --zuul-api-url https://zuul.opendev.org/api/tenant/openstack \
    --checkpoint-file /tmp/results-checkpoint \
    --worker 8 \
    --max-skipped 100 \
    --download \
    --directory /tmp/logscraper

This operation took: 30 seconds and it uses 130 MB of RAM.

.. code-block:: shell

   logsender --username admin --password mypassword --host localhost --port 9200 --insecure --workers 4


Time spend to run logscraper and wait for finish all loggearman workers took: 35 second and
it takes 520 MB of RAM.

Conclusion:

The logsender way seems to use less memory (on Opendev deployment, logstash
service is on different host, but 4096 MB of RAM is not enough) and it is faster,
but the logscraper and logsender process was executed one by one - on the
beginning logscraper download logs, then logsender send them to
Elasticsearch.

Continuous Deployment
---------------------
Once changes are reviewed and committed, they will be applied
automatically to the production hosts.

Contributing
============
Contributions are welcome!

Currently only unit tests are available. In the future,
functional tests would be added.

Documentation
=============
The latest documentation is available at
http://docs.openstack.org/infra/ci-log-processing

That documentation is generated from this repository. You can generate
it yourself with ``tox -e docs``.
