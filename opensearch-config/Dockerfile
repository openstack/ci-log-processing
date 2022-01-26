# Based on these instructions: https://opensearch.org/docs/latest/clients/logstash/index/#docker

# Once Log4J vulnerability is fixed in this OpenSearch Docker repo, upgrade to 7.16.1 or later:
#.    FROM opensearchproject/logstash-oss-with-opensearch-output-plugin:7.13.2
# See:
#     https://github.com/opensearch-project/logstash-output-opensearch/issues/107
#     https://github.com/opensearch-project/logstash-output-opensearch/issues/108
# In the meantime, we will start with Logstash 7.16.1 and add the logstash-output-opensearch plugin manually:
FROM docker.elastic.co/logstash/logstash-oss:7.16.1
RUN bin/logstash-plugin install logstash-output-opensearch

RUN rm -f /usr/share/logstash/config/*.conf
RUN /usr/share/logstash/bin/logstash-plugin install logstash-input-sqs
RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-json
RUN /usr/share/logstash/bin/logstash-plugin install logstash-filter-multiline

# ADD config/logstash.yml /usr/share/logstash/config/logstash.yml

ADD config/input.conf /usr/share/logstash/config/00-input.conf
ADD config/openstack-filters.conf /usr/share/logstash/config/50-openstack-logstash-filters.conf
ADD config/output.conf /usr/share/logstash/config/99-output.conf

RUN cat /usr/share/logstash/config/00-input.conf > /usr/share/logstash/config/pipeline.conf
RUN echo "" >> /usr/share/logstash/config/pipeline.conf
RUN cat /usr/share/logstash/config/50-openstack-logstash-filters.conf >> /usr/share/logstash/config/pipeline.conf
RUN echo "" >> /usr/share/logstash/config/pipeline.conf
RUN cat /usr/share/logstash/config/99-output.conf >> /usr/share/logstash/config/pipeline.conf

# ADD config/pipeline.conf /usr/share/logstash/config/pipeline.conf

# ADD config/ /usr/share/logstash/config/
# To start Logstash:
CMD bin/logstash --log.level debug -f config/pipeline.conf --config.reload.automatic
