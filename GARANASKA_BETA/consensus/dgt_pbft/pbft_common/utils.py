# Copyright 2016, 2018 DGT NETWORK INC © Stanislav Parsov
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
"""
Utility methods .
"""

import json
import hashlib
from collections import OrderedDict

SETTINGS_NAMESPACE = '000000'
_VREG_ = False
_MIN_PRINT_WIDTH = 15
_MAX_KEY_PARTS = 4
_ADDRESS_PART_SIZE = 16

def _short_hash(in_str):
    return hashlib.sha256(in_str.encode()).hexdigest()[:_ADDRESS_PART_SIZE]

def _key_to_address(key):
    """Creates the state address for a given setting key.
    """
    key_parts = key.split('.', maxsplit=_MAX_KEY_PARTS - 1)
    key_parts.extend([''] * (_MAX_KEY_PARTS - len(key_parts)))

    return SETTINGS_NAMESPACE + ''.join(_short_hash(x) for x in key_parts)

def _config_inputs(key,nmap):
    """Creates the list of inputs for a sawtooth_settings transaction, for a
    given setting key.
    """
    return [
        _key_to_address('sawtooth.settings.vote.proposals'),
        _key_to_address('sawtooth.settings.vote.authorized_keys'),
        _key_to_address('sawtooth.settings.vote.approval_threshold'),
        #_key_to_address(nmap),
        _key_to_address(key)
    ]


def _config_outputs(key,nmap):
    """Creates the list of outputs for a sawtooth_settings transaction, for a
    given setting key.
    """
    return [
        _key_to_address('sawtooth.settings.vote.proposals'),
        #_key_to_address(nmap),
        _key_to_address(key)
    ]


def _short_id(id):
    return '{}..{}'.format(id[:4],id[-5:]) # '/' + id[:8] + '..' + id[-8:] + '/'

def _SID_(id):
    return '{}..{}'.format(id[:4],id[-5:]) 


def pretty_print_dict(dictionary):
    """Generates a pretty-print formatted version of the input JSON.

    Args:
        dictionary (str): the JSON string to format.

    Returns:
        str: pretty-print formatted string.
    """
    return \
        json.dumps(_ascii_encode_dict(dictionary), indent=2, sort_keys=True)


def json2dict(dictionary):
    """Deserializes JSON into a dictionary.

    Args:
        dictionary (str): the JSON string to deserialize.

    Returns:
        dict: a dictionary object reflecting the structure of the JSON.
    """
    return _ascii_encode_dict(json.loads(dictionary))


def dict2json(dictionary):
    """Serializes a dictionary into JSON.

    Args:
        dictionary (dict): a dictionary object to serialize into JSON.

    Returns:
        str: a JSON string reflecting the structure of the input dict.
    """
    return json.dumps(_ascii_encode_dict(dictionary))


def _ascii_encode_dict(item):
    """
    Support method to ensure that JSON is converted to ascii since unicode
    identifiers, in particular, can cause problems
    """
    if isinstance(item, dict):
        return OrderedDict(
            (_ascii_encode_dict(key), _ascii_encode_dict(item[key]))
            for key in sorted(item.keys()))

    if isinstance(item, list):
        return [_ascii_encode_dict(element) for element in item]

    if isinstance(item, str):
        return item

    return item
