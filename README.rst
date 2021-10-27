Openstack CI log processing
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

Testing
-------

The part of Openstack CI log processing runs a complete testing and
continuous-integration environment, powered by `Zuul
<https://zuul-ci.org/>`__.

Any changes to logscraper script or tests will trigger jobs to
thoroughly test those changes.

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
