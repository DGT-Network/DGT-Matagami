# Copyright 2018 NTRlab
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

import json
import logging

from pbft.journal.block_wrapper import NULL_BLOCK_IDENTIFIER

#from pbft.consensus.wait_certificate import WaitCertificate

LOGGER = logging.getLogger(__name__)


def block_id_is_genesis(block_id):
    """Determines if the block ID represents the genesis block.

    Args:
        block_id (str): The block ID to check

    Returns:
        True if this ID represents the block ID, or False otherwise.
    """
    return block_id == NULL_BLOCK_IDENTIFIER


def deserialize_wait_certificate(block, pbft_enclave_module):
    """Deserializes the wait certificate associated with the block.

    Args:
        block (Block or BlockWrapper): The block that has the wait certificate
        pbft_enclave_module (module): The PBFT enclave module

    Returns:
        WaitCertificate: The reconstituted wait certificate associated
            with the block or None if cannot deserialize
    """
    # The wait certificate is a JSON string placed in the consensus
    # field/property of the block header.  Parse the JSON and then use the
    # serialized wait certificate and signature to create a
    # WaitCertificate object.
    wait_certificate = None
    """
    if block is not None:
        try:
            wait_certificate_dict = \
                json.loads(block.header.consensus.decode())
            wait_certificate = \
                WaitCertificate.wait_certificate_from_serialized(
                    pbft_enclave_module=None,#pbft_enclave_module=pbft_enclave_module,
                    serialized=wait_certificate_dict['SerializedCertificate'],
                    signature=wait_certificate_dict['Signature'])
        except (json.decoder.JSONDecodeError, KeyError):
            pass
    """
    return wait_certificate


def get_previous_certificate_id(block_header,
                                block_cache,
                                pbft_enclave_module):
    """Returns the wait certificate ID for the block immediately preceding the
    block represented by block_header.

    Args:
        block_header (BlockHeader): The header for the block
        block_cache (BlockCache): The cache of blocks that are predecessors
            to the block represented by block_header
        pbft_enclave_module (module): The PBFT enclave module

    Returns:
        str: The ID of the wait certificate for the block immediately
        preceding the block represented by block_header
    """
    wait_certificate = None

    if not block_id_is_genesis(block_header.previous_block_id):
        wait_certificate = deserialize_wait_certificate(
                block=block_cache[block_header.previous_block_id],pbft_enclave_module=None) 

    return \
        NULL_BLOCK_IDENTIFIER if wait_certificate is None \
        else wait_certificate.identifier
