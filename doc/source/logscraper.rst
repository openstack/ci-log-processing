Logscraper
==========

The logscraper tool can be running as a one-shot log scrape or
as periodical check, if some new log jobs are available.

The tool have help function, that is showing available options for it.
It is available by typing:

.. code-block::

   logscraper --help


Basic usage
-----------

Base on the use case, we can run logscraper.

Example:

* periodical check if there are some new logs for `openstack` tenant:

.. code-block::

  logscraper --gearman-server somehost --zuul-api-url https://zuul.opendev.org/api/tenant/openstack --checkpoint-file /tmp/results-checkpoint.txt --follow

* one shot on getting logs from `zuul` tenant:

.. code-block::

  logscraper --gearman-server localhost --zuul-api-url https://zuul.opendev.org/api/tenant/zuul --checkpoint-file /tmp/zuul-result-timestamp.txt

* periodically scrape logs from tenants: `openstack`, `zuul` and `local`

.. code-block::

  logscraper --gearman-server localhost --zuul-api-url https://zuul.opendev.org/api/tenant/openstack --zuul-api-url https://zuul.opendev.org/api/tenant/zuul --zuul-api-url https://zuul.opendev.org/api/tenant/local --checkpoint-file /tmp/someresults.txt --follow


Containerize tool
-----------------

Instead of using `pip` tool, you can build your own container image
that contains logscraper tool, for example:

.. code-block::

   docker build -t logscraper -f Dockerfile

Then you can execute commands that are described above.

NOTE: if you want to use parameter `--checkpoint-file`, you need to mount a volume
to the container, for example:

.. code-block::

   docker run -v $(pwd):/checkpoint-dir:z -d logscraper logscraper --gearman-server somehost --zuul-api-url https://zuul.opendev.org/api/tenant/openstack --checkpoint-file /checkpoint-dir/checkpoint.txt --follow
