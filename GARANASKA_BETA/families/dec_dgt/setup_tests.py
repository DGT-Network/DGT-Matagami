# Copyright 2022 DGT NETWORK INC © Stanislav Parsov
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

if os.path.exists("tests"):
    data_files.append(('/data/tests/bgt', ['tests/test_tp_dec.py']))

setup(
    name='dec-dgt-tests',
    version=subprocess.check_output(
        ['../../../bin/get_version']).decode('utf-8').strip(),
    description='Sawtooth Intkey Python Test',
    author='Hyperledger Sawtooth',
    url='https://github.com/DGT-Network/DGT-Matagami',
    packages=find_packages(),
    install_requires=[
        "cbor",
        "colorlog",
        "dgt-sdk",
        "dgt-signing",
    ],
    data_files=data_files,
    entry_points={
        'console_scripts': [
            'dec = dec_dgt.client_cli.bgt_cli:main_wrapper',
            'dec-tp-dgt = dec_dgt.processor.main:main'
        ]
    })
