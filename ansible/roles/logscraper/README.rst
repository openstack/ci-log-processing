Logscraper ansible role
=======================

The goal of this role is to setup and configure service related
to logscraper script which is responsible to to push recent
zuul builds into log gearman processor.

Requirements
------------

None

Role Variables
--------------

The role is automatically deploying service related to the
log scrape service. Depends of what is set to the `tenant_builds` var,
it can start multiple services on same host with different name,
for example:

.. code-block:: yaml

  vars:
    tenant_builds:
      - tenant: openstack
        gearman_port: 4731
        gearman_server: logstash.openstack.org
        zuul_api_url:
          - https://zuul.opendev.org/api/tenant/openstack
        insecure: false
        file_list: ['/etc/logscraper/download-list-TENANT.yaml']

will deploy service with name: `logscraper@openstack.service`.
It is because on one service we are able to deploy multiple instances
of logscraper and each of them will be responsible for checking
and pushing logs for own tenant.

Dependencies
------------

None

Example Playbook
----------------

Playbook responsible for deploying service can look like:

Below is a playbook example, responsible for deploying two logscraper
services, where one will responsible to get logs from `openstack` tenant
and second one for getting logs from `sometenant` tenant.

.. code-block:: yaml

  - name: Configure Logscraper tool
    hosts: localhost
    become: true
    vars:
      tenant_builds:
        - tenant: openstack
          gearman_port: 4731
          gearman_server: logstash.openstack.org
          zuul_api_url:
            - https://zuul.opendev.org/api/tenant/openstack
          insecure: False
        - tenant: sometenant
          zuul_api_url:
            - https://zuul.opendev.org/api/tenant/sometenant
          insecure: True
          download: true
          download_dir: /mnt/logscraper
          file_list:
            - /etc/logscraper/my-downloadlist.yaml
    roles:
      - logscraper

License
-------

Apache

Author Information
------------------

Author: OpenStack Contributors
Author email: openstack-discuss@lists.openstack.org
Home page: http://docs.openstack.org/infra/ci-log-processing
