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

import logging

from pbft.journal.block_wrapper import BlockWrapper
from pbft.journal.consensus.consensus import BlockVerifierInterface

from pbft.consensus.consensus_state import ConsensusState
from pbft.consensus.consensus_state_store import ConsensusStateStore
from pbft.consensus.pbft_settings_view import PbftSettingsView
from pbft.consensus import utils

from pbft_common.validator_registry_view.validator_registry_view import ValidatorRegistryView

LOGGER = logging.getLogger(__name__)

_VREG_ = False
class PbftBlockVerifier(BlockVerifierInterface):
    """BlockVerifier provides services for the Journal(ChainController) to
    determine if a block is valid (for the consensus rules) to be
    considered as part of the fork being evaluated. BlockVerifier must be
    independent of block publishing activities.
    """

    def __init__(self,
                 block_cache,
                 state_view_factory,
                 data_dir,
                 config_dir,
                 validator_id):
        """Initialize the object, is passed (read-only) state access objects.
            Args:
                block_cache (BlockCache): Dict interface to the block cache.
                    Any predecessor block to blocks handed to this object will
                    be present in this dict.
                state_view_factory (StateViewFactory): A factory that can be
                    used to create read-only views of state for a particular
                    merkle root, in particular the state as it existed when a
                    particular block was the chain head.
                data_dir (str): path to location where persistent data for the
                    consensus module can be stored.
                config_dir (str): path to location where configuration for the
                    consensus module can be found.
                validator_id (str): A unique ID for this validator
            Returns:
                none.
        """
        super().__init__(
            block_cache,
            state_view_factory,
            data_dir,
            config_dir,
            validator_id)

        self._block_cache = block_cache
        self._state_view_factory = state_view_factory
        self._data_dir = data_dir
        self._config_dir = config_dir
        self._validator_id = validator_id
        LOGGER.debug('PbftBlockVerifier:: ConsensusStateStore')
        self._consensus_state_store = ConsensusStateStore(data_dir=self._data_dir,validator_id=self._validator_id)

    def verify_block(self, block_wrapper):
        """Check that the block received conforms to the consensus rules.

        Args:
            block_wrapper (BlockWrapper): The block to validate.
        Returns:
            Boolean: True if the Block is valid, False if the block is invalid.
        """
        # Get the state view for the previous block in the chain so we can
        # create a PBFT enclave and validator registry view
        previous_block = None
        try:
            previous_block = self._block_cache[block_wrapper.previous_block_id]
        except KeyError:
            pass

        state_view = BlockWrapper.state_view_for_block(
                block_wrapper=previous_block,
                state_view_factory=self._state_view_factory)
        if _VREG_:
            validator_registry_view = ValidatorRegistryView(state_view)
            # Grab the validator info based upon the block signer's public
            # key
            try:
                validator_info = validator_registry_view.get_validator_info(block_wrapper.header.signer_public_key)
                LOGGER.debug('Block Signer Name=%s, ID=%s...%s PBFT',validator_info.name,validator_info.id[:8],validator_info.id[-8:])
            except KeyError:
                LOGGER.error(
                    'Block %s rejected: Received block from an unregistered validator %s...%s num_transactions=%s',
                    block_wrapper.identifier[:8],
                    block_wrapper.header.signer_public_key[:8],
                    block_wrapper.header.signer_public_key[-8:],
                        block_wrapper.num_transactions)
                    #return False

        

        # Get the consensus state and PBFT configuration view for the block
        # that is being built upon
        consensus_state = ConsensusState.consensus_state_for_block_id(
                block_id=block_wrapper.previous_block_id,
                block_cache=self._block_cache,
                state_view_factory=self._state_view_factory,
                consensus_state_store=self._consensus_state_store,
                )
        LOGGER.debug('PbftBlockVerifier:: consensus_state=%s block_wrapper=(%s)',consensus_state,block_wrapper)
        pbft_settings_view = PbftSettingsView(state_view=state_view)
        LOGGER.debug('PbftBlockVerifier:: pbft_settings_view=%s',pbft_settings_view)
        return block_wrapper.header.consensus == b"pbft"
    
        
