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


from collections import namedtuple

from dgt_validator.protobuf.block_pb2 import BlockHeader
from dgt_validator.journal.block_wrapper import BlockWrapper
from dgt_validator.journal.block_wrapper import BlockStatus
from dgt_validator.protobuf.consensus_pb2 import ConsensusPeerMessage,ConsensusPeerMessageNew,ConsensusPeerMessageHeader
from dgt_validator.protobuf.pbft_consensus_pb2 import PbftMessage,PbftMessageInfo,PbftBlockMessage,PbftSeal

import logging
LOGGER = logging.getLogger(__name__)

class UnknownBlock(Exception):
    """The given block could not be found."""

class TooManyBranch(Exception):
    """Ask too many branch for DAG."""

class BlockIsProcessedNow(Exception):  
    pass            


StartupInfo = namedtuple(
    'SignupInfo',
    ['chain_head', 'peers', 'local_peer_info','peering_mode'])


class ConsensusProxy:
    """
    Receives requests from the consensus engine handlers and delegates them
    to the appropriate components.
    """

    def __init__(self, block_manager, block_publisher,chain_controller, gossip, identity_signer,settings_view_factory, state_view_factory,signed_consensus=False):

        self._block_manager = block_manager
        self._chain_controller = chain_controller
        self._block_publisher = block_publisher
        self._gossip = gossip
        self._identity_signer = identity_signer
        self._public_key = self._identity_signer.get_public_key().as_bytes()
        self._settings_view_factory = settings_view_factory
        self._state_view_factory = state_view_factory
        self._signed_consensus = signed_consensus
        if self._signed_consensus:
            LOGGER.debug("ConsensusProxy: SIGNED CONSENSUS MODE")

    def register(self):
        """
        for restore without making Genesis block
        take real head from store 
        """
        chain_head = self._chain_controller.store_chain_head
        if chain_head is None:
            return None

        return StartupInfo(
            chain_head=chain_head,
            peers=[
                self._gossip.peer_to_public_key(peer)
                for peer in self._gossip.get_peers()
            ],
            local_peer_info=self._public_key,
            peering_mode = self._gossip.peering_mode) # add marker for dynamic

    @property
    def is_recovery(self):
        return self._chain_controller.is_recovery

    def unpack_consensus_peer_message(self,message):
        if self._signed_consensus:
            # signed message
            peer_message = ConsensusPeerMessageNew()
            peer_message.ParseFromString(message)
            header = ConsensusPeerMessageHeader()
            header.ParseFromString(peer_message.header)
            return header.name,header.message_type,peer_message.content

        peer_message = ConsensusPeerMessage()
        peer_message.ParseFromString(message)
        return peer_message.name,peer_message.message_type,peer_message.content

    def unpack_pbft_message(self,content):
        payload = PbftMessage()                   
        payload.ParseFromString(content) 
        if payload.info.msg_type == PbftMessageInfo.ARBITRATION_DONE_MSG :
            seal = PbftSeal()
            seal.ParseFromString(payload.content)   
            block = seal.block
        else:
            block = PbftBlockMessage()                
            block.ParseFromString(payload.content)    
        return block


    # Using network service
    def send_to(self, peer_id, message):
        """
        send to peer consensus message 
        it could be Arbitration - in than case we can send block to peer too
        we can see on this code as expanded consensus API
        """
        #LOGGER.debug("ConsensusProxy:send_to peer=%s message=%s",peer_id.hex()[:8],message)
        name,message_type,content = self.unpack_consensus_peer_message(message)
        #peer_message = ConsensusPeerMessage()
        #peer_message.ParseFromString(message)
        LOGGER.debug("ConsensusProxy:send_to peer=%s",peer_id.hex()[:8])
        if message_type == 'ArbitrationDone':
            """
            inform peer about this block
            """
            block = self.unpack_pbft_message(content)
            block_id = block.block_id.hex()
            LOGGER.debug("Consensus '%s' ask %s from peer=%s for block=%s",name,message_type,peer_id.hex()[:8],block_id[:8])
            

        self._gossip.send_consensus_message(
            peer_id=peer_id.hex(),
            message=message,
            public_key=self._public_key)

    def broadcast(self, message):
        self._gossip.broadcast_consensus_message(
            message=message,
            public_key=self._public_key)

    def broadcast2arbiter(self,message):
        #peer_message = ConsensusPeerMessage()
        #peer_message.ParseFromString(message)
        name,message_type,content = self.unpack_consensus_peer_message(message)
        """
        inform peer about this block
        """

        block = self.unpack_pbft_message(content)
        block_id = block.block_id.hex()
        LOGGER.debug("broadcast2arbiter '%s' ask %s from arbiters for block=%s",name,message_type,block_id[:8])
        if message_type == 'Arbitration' : 
            try:
                block = next(self._block_manager.get([block_id]))
                LOGGER.debug("ARBITRATION:contains in block manager ID=%s",block.header_signature[:8])
                self._block_publisher.arbitrate_block(block)
            except StopIteration:
                LOGGER.debug("ARBITRATION: for UNDEFINED block=%s",block_id[:8])

        self._gossip.broadcast_arbiter_consensus_message(
            message=message,
            public_key=self._public_key)

    def broadcast2cluster(self,message):
        # ARBITER DONE = send to cluster
        name,message_type,content = self.unpack_consensus_peer_message(message)
        #peer_message = ConsensusPeerMessage()
        #peer_message.ParseFromString(message)
        block = self.unpack_pbft_message(content)
        block_id = block.block_id.hex()
        LOGGER.debug("broadcast2cluster '%s' ask %s from arbiters for block=%s",name,message_type,block_id[:8])
        if message_type == 'ArbitrationDone' :
            try:
                block = next(self._block_manager.get([block_id]))
                LOGGER.debug("ARBITRATION DONE: SEND BLOCK=%s TO OWN CLUSTER",block.header_signature[:8])
                self._block_publisher.arbitrate_block(block,False)
            except StopIteration:
                LOGGER.debug("ARBITRATION: for UNDEFINED block=%s",block_id[:8])

        self._gossip.broadcast_cluster_consensus_message(
            message=message,
            public_key=self._public_key)

    # Using block publisher
    def initialize_block(self, previous_id,nest_colour=''):
        if previous_id:
            try:
                
                LOGGER.debug("ConsensusProxy:initialize_block head=%s",previous_id.hex()[:8])
                #has = self._chain_controller.has_block(previous_id.hex())
                #previous_block1 = self._chain_controller.get_block_from_cache(previous_id.hex()) if has else None
                block = next(self._block_manager.get([previous_id.hex()])) 
                previous_block = BlockWrapper(block=block, status=BlockStatus.Unknown)
                #LOGGER.debug("ConsensusProxy:initialize_block previous_block=(%s~%s)",type(previous_block),type(previous_block1))
                
            except StopIteration:
                raise UnknownBlock()
            
            self._block_publisher.initialize_block(previous_block,nest_colour)
            LOGGER.debug("ConsensusProxy:initialize_block DONE for head=%s ",previous_id.hex()[:8])
        else:
            self._block_publisher.initialize_block(self._chain_controller.chain_head,nest_colour)

    def summarize_block(self):
        return self._block_publisher.summarize_block()

    def finalize_block(self, consensus_data,block_id):
        return bytes.fromhex(self._block_publisher.finalize_block(consensus=consensus_data,block_id=block_id))

    def cancel_block(self,branch_id):
        self._block_publisher.cancel_block(branch_id)

    def reset_max_batches_per_block(self):
        self._block_publisher.reset_max_batches_per_block()

    def check_blocks(self, block_ids):
        for block_id in block_ids:
            if block_id.hex() not in self._block_manager:
                raise UnknownBlock(block_id.hex())
            # say chain controller 
            self._chain_controller.on_check_block(block_id)

    def get_block_statuses(self, block_ids):
        """Returns a list of tuples of (block id, BlockStatus) pairs.
        """
        try:
            return [
                (block_id.hex(),
                 self._chain_controller.block_validation_result(
                     block_id.hex()))
                for block_id in block_ids
            ]
        except KeyError as key_error:
            raise UnknownBlock(key_error.args[0])

    def commit_block(self, block_id,seal=None):
        """
        for version with seal we should receive consensus seal here

        """
        LOGGER.debug("ConsensusProxy:COMMIT BLOCK %s",block_id.hex()[:8])
        self._block_publisher.commit_block(block_id,seal)
        # we can use block manager but we can get this block from _blocks_processing by id
        """
        try:
            block = next(self._block_manager.get([block_id.hex()]))
        except StopIteration as stop_iteration:
            raise UnknownBlock(stop_iteration.args[0])
        """
        self._chain_controller.commit_block(block_id) # (block)

    def ignore_block(self, block_id):
        # we can use block manager but we can get this block from _blocks_processing by id
        # in case of external block _chain_controller does not contain external block
        
        try:
            block = next(self._block_manager.get([block_id.hex()]))
            LOGGER.debug("ignore_block:contains in block manager ID=%s",block.header_signature[:10])
        except StopIteration:
            raise UnknownBlock()
        
        self._chain_controller.ignore_block(block_id) # (block)

    def fail_block(self, block_id):
        # we can use block manager but we can get this block from _blocks_processing by id
        """
        try:
            block = next(self._block_manager.get([block_id.hex()]))
        except StopIteration:
            raise UnknownBlock()
        """
        self._chain_controller.fail_block(block_id) # (block)

    # Using blockstore and state database
    def blocks_get(self, block_ids):
        '''Returns a list of blocks.'''
        return self._get_blocks([block_id.hex() for block_id in block_ids])

    def chain_head_get(self,parent_id=None,new_parent_id=None,is_new=False):
        """
        Returns the main chain head in case parent_id == None.
        and branch head in case parent_id is not None 
        if parent_id undefined create new chain head 
        """
        
        chain_head = self._chain_controller.get_chain_head(parent_id.hex() if parent_id != b'' else None,new_parent_id.hex() if new_parent_id != b'' else None,is_new)
        LOGGER.debug("ConsensusProxy:chain_head_get head=%s\n",chain_head)
        if chain_head is None:
            raise UnknownBlock()

        return chain_head

    def settings_get(self, block_id, settings):
        '''Returns a list of key/value pairs (str, str).'''

        block = self._get_blocks([block_id.hex()])[0]

        block_header = BlockHeader()
        block_header.ParseFromString(block.header)

        settings_view = self._settings_view_factory.create_settings_view(
            block_header.state_root_hash)

        result = []
        for setting in settings:
            try:
                value = settings_view.get_setting(setting)
            except KeyError:
                # if the key is missing, leave it out of the response
                continue

            result.append((setting, value))

        return result

    def state_get(self, block_id, addresses):
        '''Returns a list of address/data pairs (str, bytes)'''
        bid = block_id.hex()
        if self._chain_controller.is_block_processed_now(bid):
            # state of this block is not fixed yet 
            raise BlockIsProcessedNow()

        block = self._get_blocks([bid])[0]
        block_header = BlockHeader()
        block_header.ParseFromString(block.header)

        state_view = self._state_view_factory.create_view(block_header.state_root_hash)

        result = []

        for address in addresses:
            # a fully specified address
            if len(address) == 70:
                try:
                    value = state_view.get(address)
                except Exception as err:
                    LOGGER.debug(f"state_get: SKIP ADDRESS={address} ERROR={err}\n")
                    continue
                except KeyError:
                    # if the key is missing, leave it out of the response
                    continue

                result.append((address, value))
                continue

            # an address prefix
            leaves = state_view.leaves(address)

            for leaf in leaves:
                result.append(leaf)

        return result

    def _get_blocks(self, block_ids):
        LOGGER.debug("ConsensusProxy:_get_blocks %s\n",[bid[:8] for bid in block_ids])
        block_iter = self._block_manager.get(block_ids)
        blocks = [b for b in block_iter]
        #blocks = self._chain_controller.get_blocks_validation(block_ids)
        if len(blocks) != len(block_ids): 
            # FIXME !!! check what kind of exception throw function get_block_from_cache
            try:
                block = self._chain_controller.get_block_from_cache(block_ids[0])
                LOGGER.debug("ConsensusProxy:_get_blocks UnknownBlock blocks=%s",type(block))
                return [block.get_block()]
            except Exception:
                raise UnknownBlock()

        return blocks
