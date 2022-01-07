# Copyright 2019 DGT NETWORK INC 
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

# pylint: disable=inconsistent-return-statements

import time
import random
import hashlib
import logging

from dgt_validator.journal.block_wrapper import BlockWrapper
from dgt_validator.journal.consensus.consensus \
    import BlockPublisherInterface
from dgt_validator.journal.consensus.consensus \
    import BlockVerifierInterface
from dgt_validator.journal.consensus.consensus \
    import ForkResolverInterface

from dgt_validator.state.settings_view import SettingsView
# for proxy engine
from threading import Condition

LOGGER = logging.getLogger(__name__)

_CONSENSUS_NAME_ = None
_consensus_notifier = None

class BlockPublisher(BlockPublisherInterface):
    """DevMode consensus uses genesis utility to configure Min/MaxWaitTime
     to determine when to claim a block.
     Default MinWaitTime to zero and MaxWaitTime is 0 or unset,
     ValidBlockPublishers default to None or an empty list.
     DevMode Consensus (BlockPublisher) will read these settings
     from the StateView when Constructed.
    """

    def __init__(self,
                 block_cache,
                 state_view_factory,
                 batch_publisher,
                 data_dir,
                 config_dir,
                 validator_id):
        super().__init__(
            block_cache,
            state_view_factory,
            batch_publisher,
            data_dir,
            config_dir,
            validator_id)

        self._block_cache = block_cache
        self._state_view_factory = state_view_factory

        self._start_time = 0
        self._wait_time = 0

        # Set these to default values right now, when we asked to initialize
        # a block, we will go ahead and check real configuration
        self._min_wait_time = 0.01
        self._max_wait_time = 0.06
        self._valid_block_publishers = None # list of validator which can participate into consensus
        self._consensus = None
        self._condition = Condition()
        self._is_finalize_complete = None

    def set_consensus_name(self,name):
        self._consensus = bytes(name, 'utf-8')
        LOGGER.debug("PROXY:set_consensus_name=%s->%s",name,self._consensus)

    def set_publisher(self,publisher):
        self._publisher = publisher
        LOGGER.debug("PROXY:set_publisher=%s",publisher)

    def initialize_block(self, block_header):
        """Do initialization necessary for the consensus to claim a block,
        this may include initiating voting activates, starting proof of work
        hash generation, or create a PoET wait timer.

        Args:
            block_header (BlockHeader): the BlockHeader to initialize.
        Returns:
            True
        """
        if not self._consensus:
            LOGGER.debug("initialize_block: external consensus not regitered\n")
            return False
        # Using the current chain head, we need to create a state view so we
        # can get our config values.
        state_view = BlockWrapper.state_view_for_block(
                self._block_cache.block_store.chain_head,
                self._state_view_factory)

        settings_view = SettingsView(state_view)
        self._min_wait_time = settings_view.get_setting("bgx.consensus.min_wait_time", self._min_wait_time, float)
        self._max_wait_time = settings_view.get_setting("bgx.consensus.max_wait_time", self._max_wait_time, float)
        self._valid_block_publishers = settings_view.get_setting("bgx.consensus.valid_block_publishers",self._valid_block_publishers,list)
        if block_header.consensus is None:
            block_header.consensus = self._consensus # b"Devmode"
        self._start_time = time.time()
        self._wait_time = random.uniform(self._min_wait_time, self._max_wait_time)
        LOGGER.debug("PROXY:initialize_block min_wait_time=%s max_wait_time=%s",self._min_wait_time,self._max_wait_time)
        return True

    def check_publish_block(self, block_header):
        """
        Check if a candidate block is ready to be claimed.
        For many peers we should control block's content .
        If this peer is not owner of batch we must wait until all batches which were putted into block for peer owner of batch 
        will be putted into block for this peer too.  

        block_header (BlockHeader): the block_header to be checked if it
            should be claimed
        Returns:
            Boolean: True if the candidate block_header should be claimed.
        """
        if self._valid_block_publishers and block_header.signer_public_key not in self._valid_block_publishers:
            return False
        elif self._min_wait_time == 0:
            return True
        elif self._min_wait_time > 0 and self._max_wait_time <= 0:
            if self._start_time + self._min_wait_time <= time.time():
                return True
        elif self._min_wait_time > 0 and self._max_wait_time > self._min_wait_time:
            if self._start_time + self._wait_time <= time.time():
                return True
        else:
            return False

    def finalize_block_complete(self,consensus):
        with self._condition:
            self._is_finalize_complete = consensus
            self._condition.notify()
        

    def _finalize_complete(self):
        return self._is_finalize_complete is not None

    def finalize_block(self, block_header):
        """Finalize a block to be claimed. Provide any signatures and
        data updates that need to be applied to the block before it is
        signed and broadcast to the network.

        Args:
            block_header (BlockHeader): The candidate block that needs to be
            finalized.
        Returns:
            True
        """
        LOGGER.debug("PROXY:finalize_block inform consensus engine header=%s is_complete=%s",block_header,self._is_finalize_complete)
        self._publisher.on_finalize_block(block_header)
        self._is_finalize_complete = None
        """
        after that consensus engine should be informed that block could be finalized and engine can say finalize for this candidate
        FIXME - for DAG we can say for all ready candidate that his block's could be finalized and only after that wait engine's reply
        """
        LOGGER.debug("PROXY:finalize_block wait proxy reply via finalize_block_complete...\n")
        with self._condition:
            return self._condition.wait_for(self._finalize_complete)
        return True


class BlockVerifier(BlockVerifierInterface):
    """PROXY BlockVerifier implementation
    """

    # pylint: disable=useless-super-delegation

    def __init__(self,
                 block_cache,
                 state_view_factory,
                 data_dir,
                 config_dir,
                 validator_id):
        super().__init__(
            block_cache,
            state_view_factory,
            data_dir,
            config_dir,
            validator_id)

        self._consensus = bytes(_CONSENSUS_NAME_, 'utf-8')
        self._condition = Condition()

    def verify_block_invalid(self,blkw):
        # send message to external consensus
        blk = blkw.get_block()
        LOGGER.debug("PROXY:verify_block_invalid blk=%s\n",blk.header_signature[:8])
        _consensus_notifier.notify_block_invalid(blk.header_signature)

    def verify_block_complete(self,verify):
        LOGGER.debug("PROXY:verify_block_complete %s",verify)
        with self._condition:
            self._is_verify_complete = verify
            self._condition.notify()

    def _verify_complete(self):
        return self._is_verify_complete is not None

    def verify_block(self, block_wrapper):
        LOGGER.debug("PROXY:verify_block %s",self._consensus)
        # send message new block
        self._is_verify_complete = None
        _consensus_notifier.notify_block_new(block_wrapper.get_block())
        LOGGER.debug("PROXY:verify_block waiting consensus reply for BLOCK=%s.%s\n",block_wrapper.block_num,block_wrapper.identifier[:8])
        with self._condition:
            if self._condition.wait_for(self._verify_complete):
                return self._is_verify_complete

        return block_wrapper.header.consensus == self._consensus


class ForkResolver(ForkResolverInterface):
    """Provides the fork resolution interface for the BlockValidator to use
    when deciding between 2 forks.
    """

    # pylint: disable=useless-super-delegation

    def __init__(self,
                 block_cache,
                 state_view_factory,
                 data_dir,
                 config_dir,
                 validator_id):
        super().__init__(
            block_cache,
            state_view_factory,
            data_dir,
            config_dir,
            validator_id)
        self._consensus = bytes(_CONSENSUS_NAME_, 'utf-8')
        self._condition = Condition()

    @staticmethod
    def hash_signer_public_key(signer_public_key, header_signature):
        m = hashlib.sha256()
        m.update(signer_public_key.encode())
        m.update(header_signature.encode())
        digest = m.hexdigest()
        number = int(digest, 16)
        return number

    def _compare_forks_complete(self):
        return self._is_compare_forks is not None

    def compare_forks_complete(self,result):
        LOGGER.debug("PROXY:compare_forks_complete result=%s",result)
        with self._condition:
            self._is_compare_forks = result
            self._condition.notify()

    def compare_forks(self, cur_fork_head, new_fork_head):
        """The longest chain is selected. If they are equal, then the hash
        value of the previous block id and publisher signature is computed.
        The lowest result value is the winning block.
        Args:
            cur_fork_head: The current head of the block chain.
            new_fork_head: The head of the fork that is being evaluated.
        Returns:
            bool: True if choosing the new chain head, False if choosing
            the current chain head.
        """
        LOGGER.debug("PROXY:compare_forks cur~new=%s~%s new fork consensus=%s~%s",cur_fork_head.identifier[:8],new_fork_head.identifier[:8],new_fork_head.consensus,self._consensus)
        # If the new fork head is not DevMode consensus, bail out.  This should
        # never happen, but we need to protect against it.
        if new_fork_head.consensus != self._consensus and new_fork_head.consensus != b"Genesis":
            LOGGER.debug('New fork head {} is not a {} block'.format(new_fork_head.identifier[:8],_CONSENSUS_NAME_))
            #raise TypeError('New fork head {} is not a {} block'.format(new_fork_head.identifier[:8],_CONSENSUS_NAME_))

        self._is_compare_forks = None
        _consensus_notifier.notify_block_valid(new_fork_head.identifier)
        LOGGER.debug("PROXY:compare_forks waiting consensus reply for new head=%s\n",new_fork_head.identifier[:8])
        with self._condition:
            if self._condition.wait_for(self._compare_forks_complete) :
                if self._is_compare_forks:
                    # send message to external consensus
                    _consensus_notifier.notify_block_commit(new_fork_head.identifier)    
                return self._is_compare_forks

        # If the current fork head is not DevMode consensus, check the new fork
        # head to see if its immediate predecessor is the current fork head. If
        # so that means that consensus mode is changing.  If not, we are again
        # in a situation that should never happen, but we need to guard
        # against.
        """
        if cur_fork_head.consensus != self._consensus:
            if new_fork_head.previous_block_id == cur_fork_head.identifier:
                LOGGER.info('Choose new fork {}: New fork head switches consensus to {}'.format(new_fork_head.identifier[:8],_CONSENSUS_NAME_))
                return True

            raise \
                TypeError(
                    'Trying to compare a {} block {} to a non-{} '
                    'block {} that is not the direct predecessor'.format(
                        _CONSENSUS_NAME_,
                        new_fork_head.identifier[:8],
                        _CONSENSUS_NAME_,
                        cur_fork_head.identifier[:8]))

        if new_fork_head.block_num == cur_fork_head.block_num:
            cur_fork_hash = self.hash_signer_public_key(
                cur_fork_head.header.signer_public_key,
                cur_fork_head.header.previous_block_id)
            new_fork_hash = self.hash_signer_public_key(
                new_fork_head.header.signer_public_key,
                new_fork_head.header.previous_block_id)

            result = new_fork_hash < cur_fork_hash

        else:
            result = new_fork_head.block_num > cur_fork_head.block_num

        return result
        """
