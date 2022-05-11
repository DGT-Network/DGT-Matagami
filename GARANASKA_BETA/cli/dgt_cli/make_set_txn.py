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

#import argparse
from base64 import b64decode
import hashlib
import logging
import os
import sys
import random
import time

from dgt_sdk.protobuf.settings_pb2 import SettingsPayload
from dgt_sdk.protobuf.settings_pb2 import SettingProposal
from dgt_sdk.protobuf.settings_pb2 import SettingVote
from dgt_sdk.protobuf.settings_pb2 import SettingCandidates
from dgt_sdk.protobuf.settings_pb2 import SettingTopology
#from dgt_cli.protobuf.setting_pb2 import Setting
#from dgt_validator.protobuf.setting_pb2 import Setting

from dgt_validator.protobuf.transaction_pb2 import TransactionHeader,Transaction
from dgt_validator.protobuf.batch_pb2 import BatchHeader,Batch,BatchList
from dgt_validator.gossip.fbft_topology import DGT_TOPOLOGY_MAP_NM
#from dgt_cli.protobuf.transaction_pb2 import TransactionHeader,Transaction
#from dgt_cli.protobuf.batch_pb2 import BatchHeader,Batch,BatchList




SETTINGS_NAMESPACE = '000000'


_MAX_KEY_PARTS = 4
_ADDRESS_PART_SIZE = 16



def _create_batch(signer, transactions):
    """Creates a batch from a list of transactions and a public key, and signs
    the resulting batch with the given signing key.

    Args:
        signer (:obj:`Signer`): The cryptographic signer
        transactions (list of `Transaction`): The transactions to add to the
            batch.

    Returns:
        `Batch`: The constructed and signed batch.
    """
    txn_ids = [txn.header_signature for txn in transactions]
    batch_header = BatchHeader(
        signer_public_key=signer.get_public_key().as_hex(),
        transaction_ids=txn_ids).SerializeToString()

    return Batch(
        header=batch_header,
        header_signature=signer.sign(batch_header),
        transactions=transactions,
        timestamp=int(time.time()))


def _create_propose_txn(signer, setting_key_value):
    """Creates an individual sawtooth_settings transaction for the given
    key and value.
    """
    setting_key, setting_value = setting_key_value
    nonce = hex(random.randint(0, 2**64))
    proposal = SettingProposal(
        setting=setting_key,
        value=setting_value,
        nonce=nonce)
    payload = SettingsPayload(data=proposal.SerializeToString(),
                              action=SettingsPayload.PROPOSE)

    return _make_txn(signer, setting_key, payload)


def _create_topology_txn(signer, setting_key_value):
    """Creates an individual topology dgt_settings transaction for the given
    key and value.
    """
    setting_key, setting_value = setting_key_value
    nonce = hex(random.randint(0, 2**64))
    topology = SettingTopology(
        setting=setting_key,
        value=setting_value,
        nonce=nonce)
    payload = SettingsPayload(data=topology.SerializeToString(),action=SettingsPayload.TOPOLOGY)

    return _make_txn(signer, setting_key, payload)


def _create_vote_txn(signer, proposal_id, setting_key, vote_value):
    """Creates an individual sawtooth_settings transaction for voting on a
    proposal for a particular setting key.
    """
    if vote_value == 'accept':
        vote_id = SettingVote.ACCEPT
    else:
        vote_id = SettingVote.REJECT

    vote = SettingVote(proposal_id=proposal_id, vote=vote_id)
    payload = SettingsPayload(data=vote.SerializeToString(),
                              action=SettingsPayload.VOTE)

    return _make_txn(signer, setting_key, payload)


def _make_txn(signer, setting_key, payload):
    """Creates and signs a dgt_settings transaction with with a payload.
    """
    serialized_payload = payload.SerializeToString()
    header = TransactionHeader(
        signer_public_key=signer.get_public_key().as_hex(),
        family_name='dgt_settings', 
        family_version='1.0',
        inputs=_config_inputs(setting_key),
        outputs=_config_outputs(setting_key),
        dependencies=[],
        payload_sha512=hashlib.sha512(serialized_payload).hexdigest(),
        batcher_public_key=signer.get_public_key().as_hex()
    ).SerializeToString()

    return Transaction(
        header=header,
        header_signature=signer.sign(header),
        payload=serialized_payload)


def _config_inputs(key):
    """Creates the list of inputs for a sawtooth_settings transaction, for a
    given setting key.
    """
    return [
        _key_to_address('sawtooth.settings.vote.proposals'),
        _key_to_address('sawtooth.settings.vote.authorized_keys'),
        _key_to_address('sawtooth.settings.vote.approval_threshold'),
        #_key_to_address(DGT_TOPOLOGY_MAP_NM),
        _key_to_address(key)
    ]


def _config_outputs(key):
    """Creates the list of outputs for a sawtooth_settings transaction, for a
    given setting key.
    """
    return [
        _key_to_address('sawtooth.settings.vote.proposals'),
        #_key_to_address(DGT_TOPOLOGY_MAP_NM),
        _key_to_address(key)
    ]


def _short_hash(in_str):
    return hashlib.sha256(in_str.encode()).hexdigest()[:_ADDRESS_PART_SIZE]


def _key_to_address(key):
    """Creates the state address for a given setting key.
    """
    key_parts = key.split('.', maxsplit=_MAX_KEY_PARTS - 1)
    key_parts.extend([''] * (_MAX_KEY_PARTS - len(key_parts)))

    return SETTINGS_NAMESPACE + ''.join(_short_hash(x) for x in key_parts)






