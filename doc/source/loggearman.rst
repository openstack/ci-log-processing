Loggearman
==========

The Loggearman tools are responsible for listening events,
parse them, get logs from log server and push them to
the Logstash service.


Loggearman Client
-----------------

The Loggearman Client is responsible for listening events that
comes on port 4730 (by default), parse them and redirect them to
German server, that later will be processed by loggearman worker.


Loggearman Worker
-----------------

The Loggearman Worker is responsible to get log files from the
log server, parse them and send line by line to the Logstash service
with necessary fields like: build_uuid, build_name, etc.
