Logscraper
==========

The logscraper tool can be running as a one-shot log scrape or
as periodical check, if some new log jobs are available.

The tool have help function, that is showing available options for it.
It is available by typing:

.. code-block::

   logscraper --help

   Fetch and push last Zuul CI job logs:

   optional arguments:
     -h, --help            show this help message and exit
     --zuul-api-url ZUUL_API_URL
                           URL(s) for Zuul API. Parameter can be set multiple
                           times.
     --job-name JOB_NAME   CI job name(s). Parameter can be set multiple times.
                           If not set it would scrape every latest builds.
     --follow              Keep polling zuul builds
     --insecure            Skip validating SSL cert
     --checkpoint-file CHECKPOINT_FILE
                           File that will keep information about last uuid
                           timestamp for a job.
     --workers WORKERS     Worker processes for logscraper
     --max-skipped MAX_SKIPPED
                           How many job results should be checked until last uuid
                           written in checkpoint file is founded
     --debug               Print more information
     --directory DIRECTORY
                           Directory, where the logs will be stored. Defaults to:
                           /tmp/logscraper


Basic usage
-----------

Base on the use case, we can run logscraper.

Example:

* download logs to /mnt/logscraper. NOTE: if you are using container service, this directory needs to be mounted!

.. code-block::

  logscraper --zuul-api-url https://zuul.opendev.org/api/tenant/openstack --directory /mnt/logscraper --download


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

   docker run -v $(pwd):/checkpoint-dir:z -v /mnt/logscraper:/mnt/logscraper:z -d logscraper logscraper --zuul-api-url https://zuul.opendev.org/api/tenant/openstack --checkpoint-file /checkpoint-dir/checkpoint --directory /mnt/logscraper --download --follow
