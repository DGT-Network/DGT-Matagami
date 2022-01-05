# Copyright 2020 DGT NETWORK INC © Stanislav Parsov
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
# ------------------------------------------------------------------------------

from __future__ import print_function

import os
import subprocess

from setuptools import setup, find_packages


data_files = []

if os.path.exists("/etc/default"):
    data_files.append(
        ('/etc/default', ['packaging/systemd/sawtooth-bgt-tp-python']))

if os.path.exists("/lib/systemd/system"):
    data_files.append(
        ('/lib/systemd/system',
         ['packaging/systemd/sawtooth-bgt-tp-python.service']))

setup(
    name='dgt-xcert',
    version=subprocess.check_output(
        ['../../bin/get_version']).decode('utf-8').strip(),
    description='DGT xcert Python ',
    author='DGT NETWORK INC © Stanislav Parsov',
    url='https://github.com/hyperledger/sawtooth-core',
    packages=find_packages(),
    install_requires=[
        "cbor",
        "colorlog",
        "dgt-sdk",
        "dgt-signing",
        "secp256k1"
    ],
    data_files=data_files,
    entry_points={
        'console_scripts': [
            'xcert = x509_cert.client_cli.bgt_cli:main_wrapper',
            'xcert-tp = x509_cert.processor.main:main'
        ]
    })
