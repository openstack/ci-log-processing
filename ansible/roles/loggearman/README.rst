Openstack Log Processor Tools
=============================

The goal of this role is to setup and configure service related
to `log-gearman-client` and `log-gearman-worker` scripts, that
were ported to this project repository from `puppet-log_processor repository
<https://opendev.org/opendev/puppet-log_processor/src/branch/master/files>`__.

Configuration
-------------

The role is automatically deploying services:

* log-gearman-client
* log-gearman-worker

inside the container.

Example playbook setup
----------------------

.. code-block:: yaml

   - name: Configure loggearman tool
     hosts: localhost
     become: true
     vars:
       source_url: https://localhost
       output_hosts: mylogstashhost.com
       log_cert_verify: True
     roles:
       - loggearman
