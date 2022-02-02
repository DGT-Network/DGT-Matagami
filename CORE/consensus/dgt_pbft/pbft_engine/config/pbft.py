# Copyright 2018 DGT NETWORK INC © Stanislav Parsov
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

from dgt_sdk.processor.exceptions import LocalConfigurationError

LOGGER = logging.getLogger(__name__)


def load_default_pbft_config():
    """
    Returns the default PbftConfig
    """
    return PbftConfig(
        node='plink',
    )


def load_toml_pbft_config(filename):
    """Returns a PbftConfig created by loading a TOML file from the
    filesystem.

    Args:
        filename (string): The name of the file to load the config from

    Returns:
        config (PbftConfig): The PbftConfig created from the stored
            toml file.

    Raises:
        LocalConfigurationError
    """
    if not os.path.exists(filename):
        LOGGER.info(
            "Skipping transaction proccesor config loading from non-existent"
            " config file: %s", filename)
        return PbftConfig()

    LOGGER.info("Loading transaction processor information from config: %s",
                filename)

    try:
        with open(filename) as fd:
            raw_config = fd.read()
    except IOError as e:
        raise LocalConfigurationError(
            "Unable to load transaction processor configuration file:"
            " {}".format(str(e)))

    toml_config = toml.loads(raw_config)
    invalid_keys = set(toml_config.keys()).difference(
        ['node'])
    if invalid_keys:
        raise LocalConfigurationError(
            "Invalid keys in transaction processor config: "
            "{}".format(", ".join(sorted(list(invalid_keys)))))

    config = PbftConfig(
        node=toml_config.get("node", None)
    )

    return config


def merge_pbft_config(configs):
    """
    Given a list of PbftConfig objects, merges them into a single
    PbftConfig, giving priority in the order of the configs
    (first has highest priority).

    Args:
        config (list of PbftConfig): The list of xo configs that
            must be merged together

    Returns:
        config (PbftConfig): One PbftConfig that combines all of the
            passed in configs.
    """
    node = None

    for config in reversed(configs):
        if config.node is not None:
            node = config.node

    return PbftConfig(
        node=node
    )


class PbftConfig:
    def __init__(self, node=None):
        self._node = node

    @property
    def node(self):
        return self._node

    def __repr__(self):
        # not including  password for opentsdb
        return \
            "{}(node={})".format(
                self.__class__.__name__,
                repr(self._node),
            )

    def to_dict(self):
        return collections.OrderedDict([
            ('node', self._node),
        ])

    def to_toml_string(self):
        return str(toml.dumps(self.to_dict())).strip().split('\n')
