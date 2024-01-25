Logsender ansible role
======================

The goal of this role is to setup and configure service related
to logsender script which is responsible to parse log content,
attach required information that are available in `buildlog` and
`inventory.yaml` file and send it to Elasticsearch service.

Requirements
------------

None

Role Variables
--------------

The role is automatically deploying service related to the
log sender service.
Example Ansible variables that are configuring service:

.. code-block:: yaml

  vars:
    tenant_builds:
      - tenant: openstack
        es_username: admin
        es_password: admin
        es_host: localhost
        es_port: 9200
        es_insecure: true
        es_index: logstash-logscraper
        download_dir: /mnt/logscraper/sometenant
        file_list: ['/etc/logsender/download-list-TENANT.yaml']


That configuration will will deploy service with name: `logsender-openstack.service`.
It is because there can be multiple instances of logsender service - each
will be configured to other tenant.

Dependencies
------------

None

Example Playbook
----------------

Playbook responsible for deploying service can look like:

Below is a playbook example, responsible for deploying two logsender
services, where one will responsible to get logs from `openstack` tenant
and second one for getting logs from `sometenant` tenant.

.. code-block:: yaml

  - name: Configure Logscraper tool
    hosts: localhost
    become: true
    vars:
      tenant_builds:
        - tenant: openstack
          es_username: logstash
          es_password: logstash
          es_host: localhost
          es_port: 9200
          es_insecure: false
          es_index: ""
          es_index_prefix: ""
          download_dir: /mnt/logscraper/openstack
        - tenant: sometenant
          es_username: logstash
          es_password: logstash
          es_host: otherhost
          es_port: 9200
          es_insecure: false
          es_index: ""
          es_index_prefix: ""
          download_dir: /mnt/logscraper/sometenant
          file_list:
            - /etc/logscraper/my-downloadlist.yaml
    roles:
      - logsender

License
-------

Apache

Author Information
------------------

Author: OpenStack Contributors
Author email: openstack-discuss@lists.openstack.org
Home page: http://docs.openstack.org/infra/ci-log-processing
