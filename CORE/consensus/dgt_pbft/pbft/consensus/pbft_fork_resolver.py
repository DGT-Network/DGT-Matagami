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
from pbft.consensus.consensus_state import ConsensusState
from pbft.consensus.consensus_state_store import ConsensusStateStore
from pbft.consensus import utils
from pbft.consensus.pbft_settings_view import PbftSettingsView
from pbft.journal.block_wrapper import BlockWrapper
from pbft.journal.consensus.consensus import ForkResolverInterface

from pbft_common.validator_registry_view.validator_registry_view import ValidatorRegistryView


LOGGER = logging.getLogger(__name__)


class PbftForkResolver(ForkResolverInterface):
    # Provides the fork resolution interface for the BlockValidator to use
    # when deciding between 2 forks.
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
                config_dir (str): path to location where config data for the
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
        LOGGER.debug('PbftForkResolver:: ConsensusStateStore')
        self._consensus_state_store = ConsensusStateStore(data_dir=self._data_dir,validator_id=self._validator_id)

    def compare_forks(self, cur_fork_head, new_fork_head):
        """Given the head of two forks, return which should be the fork that
        the validator chooses.  When this is called both forks consist of
        only valid blocks.

        Args:
            cur_fork_head (Block): The current head of the block chain.
            new_fork_head (Block): The head of the fork that is being
            evaluated.
        Returns:
            Boolean: True if the new chain should replace the current chain.
            False if the new chain should be discarded.
        """
        # If the new fork head is not DevMode consensus, bail out.  This should
        # never happen, but we need to protect against it.
        LOGGER.debug('PbftForkResolver:: compare_forks new_fork_head.consensus=%s',new_fork_head.consensus)
        if new_fork_head.consensus != b"pbft":
            raise \
                TypeError(
                    'New fork head {} is not a Pbft block'.format(
                        new_fork_head.identifier[:8]))

        # If the current fork head is not DevMode consensus, check the new fork
        # head to see if its immediate predecessor is the current fork head. If
        # so that means that consensus mode is changing.  If not, we are again
        # in a situation that should never happen, but we need to guard
        # against.
        if cur_fork_head.consensus != b"pbft":
            if new_fork_head.previous_block_id == cur_fork_head.identifier:
                LOGGER.info(
                    'PbftForkResolver::Choose new fork %s: New fork head switches consensus to '
                    'Pbft',
                    new_fork_head.identifier[:8])
                return True

            raise \
                TypeError(
                    'Trying to compare a Pbft block {} to a non-Pbft '
                    'block {} that is not the direct predecessor'.format(
                        new_fork_head.identifier[:8],
                        cur_fork_head.identifier[:8]))

        if new_fork_head.block_num == cur_fork_head.block_num:
            cur_fork_hash =self.hash_signer_public_key(
                cur_fork_head.header.signer_public_key,
                cur_fork_head.header.previous_block_id)
            new_fork_hash = self.hash_signer_public_key(
                new_fork_head.header.signer_public_key,
                new_fork_head.header.previous_block_id)

            result = new_fork_hash < cur_fork_hash

        else:
            result = new_fork_head.block_num > cur_fork_head.block_num
        LOGGER.debug('PbftForkResolver:: compare_forks result=%s',result)
        return result

