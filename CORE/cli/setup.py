# Copyright 2020 NTRLab
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

import subprocess

from setuptools import setup, find_packages

conf_dir = "/etc/dgt"

data_files = [
    (conf_dir, ['cli.toml.example'])
]

setup(
    name='bgx-cli',
    version=subprocess.check_output(
        ['../bin/get_version']).decode('utf-8').strip(),
    description='DGT CLI',
    author='NTRLab',
    url='http://gitlab.ntrlab.ru:83/ntrlab/bgx',
    packages=find_packages(),
    install_requires=[
        'colorlog', 'protobuf', 'sawtooth-signing', 'toml', 'PyYAML',
        'requests'
    ],
    data_files=data_files,
    entry_points={
        'console_scripts': [
            'dgtadm = dgt_cli.bgxadm:main_wrapper',
            'dgtnet = dgt_cli.bgxnet:main_wrapper',
            'dgtset = dgt_cli.bgxset:main_wrapper',
            'dgt = dgt_cli.main:main_wrapper'
        ]
    })
