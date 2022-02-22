Logsender
=========

The logscraper tool is parsing log files that are available
in the directory, attach important data that are provided in `buildlog` and
`inventory.yaml` files and send it directly to the Opensearch service.

Available arguments for logsender are:

.. code-block::

   logsender --help

   Check log directories and push to the Opensearch service

   options:
     -h, --help            show this help message and exit
     --directory DIRECTORY
                           Directory, where the logs will be stored. Defaults to: /tmp/logscraper
     --host HOST           Opensearch host
     --port PORT           Opensearch port
     --username USERNAME   Opensearch username
     --password PASSWORD   Opensearch user password
     --index-prefix INDEX_PREFIX
                           Prefix for the index. Defaults to logstash-
     --index INDEX         Opensearch index. Defaults to: <index-prefix>-YYYY-DD
     --insecure            Skip validating SSL cert
     --follow              Keep sending CI logs
     --workers WORKERS     Worker processes for logsender
     --chunk-size CHUNK_SIZE
                           The bulk chunk size
     --keep                Do not remove log directory after
     --ignore-es-status    Ignore Opensearch bulk
     --debug DEBUG         Be more verbose


Basic usage
-----------

Base on the use case, we can run logsender.

Example:

* Send logs to  that is running on localhost, skip TLS cert verification

.. code-block::

  logsender --username logstash --password logstashpassword --host localhost --port 9200 --insecure


* Send logs to  service, use 8 workers and ignore Opensearch bulk update status. WARNING: --ignore-es-status should not be used on production environment!

.. code-block::

  logsender --username logstash --password logstashpassword --host localhost --port 9200 --insecure --workers 8 --ignore-es-status


* Send logs to elasticsaerch service, provide own index name "myindex" and keep log files (they will be not deleted):

.. code-block::

  logsender --username logstash --password logstashpassword --index myindex --keep


Containerize tool
-----------------

Instead of using `pip` tool, you can build your own container image
that contains logscraper tool, for example:

.. code-block::

   docker build -t logscraper -f Dockerfile

NOTE: the logsender tool will be included in logscraper container image.

Then you can execute commands that are described above.

NOTE: The directory where you store log files should be mounted to the container.
For example:

.. code-block::

   podman run \
    --network host \
    -d \
    --name logsender-openstack \
    --volume /mnt/logscraper/openstack:/mnt/logscraper/openstack:z \
    logscraper \
    /usr/local/bin/logsender \
    --username admin \
    --password admin \
    --host localhost \
    --port 9200 \
    --directory /mnt/logscraper/openstack \
    --follow
