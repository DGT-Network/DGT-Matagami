# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# docker build -f engine/Dockerfile -t sawtooth-poet-engine-local .

# -------------=== pbft engine build ===-------------

FROM ubuntu:xenial
ARG BGX_TOP
RUN echo "deb [arch=amd64] http://repo.sawtooth.me/ubuntu/nightly xenial universe" >> /etc/apt/sources.list \
 && (apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 44FC67F19B2466EA \
 || apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 44FC67F19B2466EA) \
 && apt-get update \
 && apt-get install -y -q --allow-downgrades \
    python3 \
    python3-setuptools

RUN apt-get install -y -q --allow-downgrades \
    python3-cbor \
    python3-cryptography>-1.7.1 \
    python3-grpcio \
    python3-grpcio-tools \
    python3-lmdb \
    python3-protobuf \
    python3-requests \
    python3-sawtooth-sdk \
    python3-toml \
    python3-yaml iputils-ping netcat net-tools

RUN mkdir -p /var/log/sawtooth

ENV PATH=$PATH:/project/$BGX_TOP/bgx/bin:/project/$BGX_TOP/bin 

WORKDIR /project/$BGX_TOP

CMD echo "\033[0;32m--- Building pbft engine ---\n\033[0m" \
 && cd bgx/consensus/pbft_python \
 && python3 setup.py clean --all \
 && python3 setup.py build
