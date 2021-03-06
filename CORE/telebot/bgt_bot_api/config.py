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

import collections
import logging
import os
import toml

from bgt_bot_api.exceptions import BotApiConfigurationError


LOGGER = logging.getLogger(__name__)


def load_default_bot_api_config():
    return BotApiConfig(
        bind=["127.0.0.1:8008"],
        connect="tcp://localhost:4004",
        timeout=300,
        client_max_size=10485760)


def load_toml_bot_api_config(filename):
    """Returns a BotApiConfig created by loading a TOML file from the
    filesystem.
    """
    if not os.path.exists(filename):
        LOGGER.info(
            "Skipping rest api loading from non-existent config file: %s",
            filename)
        return BotApiConfig()

    LOGGER.info("Loading rest api information from config: %s", filename)

    try:
        with open(filename) as fd:
            raw_config = fd.read()
    except IOError as e:
        raise BotApiConfigurationError(
            "Unable to load rest api configuration file: {}".format(str(e)))

    toml_config = toml.loads(raw_config)

    invalid_keys = set(toml_config.keys()).difference(
        ['bind', 'connect', 'timeout', 'opentsdb_db', 'opentsdb_url',
         'opentsdb_username', 'opentsdb_password', 'client_max_size'])
    if invalid_keys:
        raise BotApiConfigurationError(
            "Invalid keys in rest api config: {}".format(
                ", ".join(sorted(list(invalid_keys)))))
    config = BotApiConfig(
        bind=toml_config.get("bind", None),
        connect=toml_config.get('connect', None),
        timeout=toml_config.get('timeout', None),
        opentsdb_url=toml_config.get('opentsdb_url', None),
        opentsdb_db=toml_config.get('opentsdb_db', None),
        opentsdb_username=toml_config.get('opentsdb_username', None),
        opentsdb_password=toml_config.get('opentsdb_password', None),
        client_max_size=toml_config.get('client_max_size', None)
    )

    return config


def merge_bot_api_config(configs):
    """
    Given a list of PathConfig objects, merges them into a single PathConfig,
    giving priority in the order of the configs (first has highest priority).
    """
    bind = None
    connect = None
    timeout = None
    opentsdb_url = None
    opentsdb_db = None
    opentsdb_username = None
    opentsdb_password = None
    client_max_size = None

    for config in reversed(configs):
        if config.bind is not None:
            bind = config.bind
        if config.connect is not None:
            connect = config.connect
        if config.timeout is not None:
            timeout = config.timeout
        if config.opentsdb_url is not None:
            opentsdb_url = config.opentsdb_url
        if config.opentsdb_db is not None:
            opentsdb_db = config.opentsdb_db
        if config.opentsdb_username is not None:
            opentsdb_username = config.opentsdb_username
        if config.opentsdb_password is not None:
            opentsdb_password = config.opentsdb_password
        if config.client_max_size is not None:
            client_max_size = config.client_max_size

    return BotApiConfig(
        bind=bind,
        connect=connect,
        timeout=timeout,
        opentsdb_url=opentsdb_url,
        opentsdb_db=opentsdb_db,
        opentsdb_username=opentsdb_username,
        opentsdb_password=opentsdb_password,
        client_max_size=client_max_size)


class BotApiConfig:
    def __init__(
            self,
            bind=None,
            connect=None,
            timeout=None,
            opentsdb_url=None,
            opentsdb_db=None,
            opentsdb_username=None,
            opentsdb_password=None,
            client_max_size=None):
        self._bind = bind
        self._connect = connect
        self._timeout = timeout
        self._opentsdb_url = opentsdb_url
        self._opentsdb_db = opentsdb_db
        self._opentsdb_username = opentsdb_username
        self._opentsdb_password = opentsdb_password
        self._client_max_size = client_max_size

    @property
    def bind(self):
        return self._bind

    @property
    def connect(self):
        return self._connect

    @property
    def timeout(self):
        return self._timeout

    @property
    def opentsdb_url(self):
        return self._opentsdb_url

    @property
    def opentsdb_db(self):
        return self._opentsdb_db

    @property
    def opentsdb_username(self):
        return self._opentsdb_username

    @property
    def opentsdb_password(self):
        return self._opentsdb_password

    @property
    def client_max_size(self):
        return self._client_max_size

    def __repr__(self):
        # skip opentsdb_db password
        return \
            "{}(bind={}, connect={}, timeout={}," \
            "opentsdb_url={}, opentsdb_db={}, opentsdb_username={}," \
            "client_max_size={})" \
            .format(
                self.__class__.__name__,
                repr(self._bind),
                repr(self._connect),
                repr(self._timeout),
                repr(self._opentsdb_url),
                repr(self._opentsdb_db),
                repr(self._opentsdb_username),
                repr(self._client_max_size))

    def to_dict(self):
        return collections.OrderedDict([
            ('bind', self._bind),
            ('connect', self._connect),
            ('timeout', self._timeout),
            ('opentsdb_url', self._opentsdb_url),
            ('opentsdb_db', self._opentsdb_db),
            ('opentsdb_username', self._opentsdb_username),
            ('opentsdb_password', self._opentsdb_password),
            ('client_max_size', self._client_max_size)
        ])

    def to_toml_string(self):
        return str(toml.dumps(self.to_dict())).strip().split('\n')
