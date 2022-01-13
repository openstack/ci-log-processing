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

FROM quay.io/centos/centos:stream8

ENV OSLO_PACKAGE_VERSION='0.0.1'
ENV PATH=~/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN groupadd loggearman && \
    useradd --home-dir /home/loggearman -g loggearman loggearman

RUN dnf update -y && \
    dnf install -y python3 python3-setuptools \
                   python3-devel python3-wheel \
                   python3-pip git

COPY . /tmp/src
RUN cd /tmp/src && \
    pip3 install -r requirements.txt && \
    python3 setup.py install && \
    rm -rf /tmp/src

RUN dnf remove -y python3-devel git && \
    dnf autoremove -y && \
    dnf clean all && \
    rm -rf ~/.cache/pip

USER loggearman
