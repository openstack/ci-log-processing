# Copyright (C) 2021 Red Hat
# Copyright (C) 2022 Red Hat
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

FROM quay.io/centos/centos:stream9 as logscraper

ENV PATH=/workspace/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LANG=en_US.UTF-8

RUN groupadd logscraper --gid 1000 && \
    useradd --home-dir /home/logscraper --gid 1000 --uid 1000 logscraper

RUN dnf update -y && \
    dnf install -y python python-setuptools \
                   python-devel python-pip git

COPY . /tmp/src
RUN cd /tmp/src && \
    pip3 install -r requirements.txt && \
    python3 setup.py install && \
    rm -rf /tmp/src

RUN dnf remove -y python3-devel git && \
    dnf autoremove -y && \
    dnf clean all && \
    rm -rf ~/.cache/pip

USER logscraper
