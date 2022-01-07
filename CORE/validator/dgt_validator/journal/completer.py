# Copyright 2017 DGT NETWORK INC 
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
from threading import RLock
from collections import deque

from dgt_validator.journal.block_cache import BlockCache
from dgt_validator.journal.block_wrapper import BlockWrapper
from dgt_validator.journal.block_wrapper import NULL_BLOCK_IDENTIFIER
from dgt_validator.journal.timed_cache import TimedCache
from dgt_validator.journal.block_store import Federation
from dgt_validator.protobuf.batch_pb2 import Batch,BatchList
from dgt_validator.protobuf.block_pb2 import Block
from dgt_validator.protobuf.transaction_pb2 import TransactionHeader
from dgt_validator.protobuf.client_batch_submit_pb2 import ClientBatchSubmitRequest
from dgt_validator.protobuf import network_pb2
from dgt_validator.networking.dispatch import Handler
from dgt_validator.networking.dispatch import HandlerResult
from dgt_validator.networking.dispatch import HandlerStatus

LOGGER = logging.getLogger(__name__)


class Completer(object):
    """
    The Completer is responsible for making sure blocks are formally
    complete before they are delivered to the chain controller. A formally
    complete block is a block whose predecessor is in the block cache and all
    the batches are present in the batch list and in the order specified by the
    block header. If the predecessor or a batch is missing, a request message
    is sent sent out over the gossip network. It also checks that all batches
    have their dependencies satisifed, otherwise it will request the batch that
    has the missing transaction.
    """

    def __init__(self,
                 block_store,
                 gossip,
                 cache_keep_time=300,
                 cache_purge_frequency=30,
                 requested_keep_time=1200):
        """
        :param block_store (dictionary) The block store shared with the journal
        :param gossip (gossip.Gossip) Broadcasts block and batch request to
                peers
        :param cache_keep_time (float) Time in seconds to keep values in
            TimedCaches.
        :param cache_purge_frequency (float) Time between purging the
            TimedCaches.
        """
        self.gossip = gossip
        
        self.batch_cache = TimedCache(cache_keep_time, cache_purge_frequency)
        self.block_cache = BlockCache(block_store,
                                      cache_keep_time,
                                      cache_purge_frequency)
        self._block_store = block_store
        # avoid throwing away the genesis block
        self.block_cache[NULL_BLOCK_IDENTIFIER] = None
        self._seen_txns = TimedCache(cache_keep_time, cache_purge_frequency)
        self._incomplete_batches = TimedCache(cache_keep_time,cache_purge_frequency)
        self._incomplete_blocks = TimedCache(cache_keep_time,cache_purge_frequency)
        self._requested = TimedCache(requested_keep_time,cache_purge_frequency)
        self._pending_heads = {}
        self._on_block_received = None
        self._on_batch_received = None
        self._has_block = None
        self._has_genesis_federation_block = None
        self._is_nests_ready = None
        self._incomplete_loop = False
        self.lock = RLock()
        self.gossip.set_add_batch(self.add_batch)

    @property
    def incomplete_blocks(self):
        return ["{}({})".format(bid[:8],len(blks)) for bid,blks in self._incomplete_blocks.items()]
    @property
    def requested(self):
        return ["{}".format(bid[:8]) for bid in self._requested.keys()]

    def _complete_block(self, block,nest=False):
        """ Check the block to see if it is complete and if it can be passed to
            the journal. If the block's predecessor is not in the block_cache
            the predecessor is requested and the current block is added to the
            the incomplete_block cache. If the block.batches and
            block.header.batch_ids are not the same length, the batch_id list
            is checked against the batch_cache to see if the batch_list can be
            built. If any batches are missing from the block and we do not have
            the batches in the batch_cache, they are requested. The block is
            then added to the incomplete_block cache. If we can complete the
            block, a new batch list is created in the correct order and added
            to the block. The block is now considered complete and is returned.
            If block.batches and block.header.batch_ids are the same length,
            the block's batch list needs to be in the same order as the
            block.header.batch_ids list. If the block has all of its expected
            batches but are not in the correct order, the batch list is rebuilt
            and added to the block. Once a block has the correct batch list it
            is added to the block_cache and is returned.

        """
        
        def insert_lost_block(block):
            for pid,blocks in self._incomplete_blocks.items():
                LOGGER.debug("CHECK INSER LOST for=%s blocks=%s",pid[:8],["{}.{}".format(blk.block_num,blk.header_signature[:8]) for blk in blocks])
                for i,blk in enumerate(blocks):
                    if blk.block_num == block.block_num+1:
                        blocks.insert(i,block)
                        LOGGER.debug("INSER LOST for=%s blocks=%s",pid[:8],["{}.{}".format(blk.block_num,blk.header_signature[:8]) for blk in blocks])
                        return

        def check_missing_predecessor(previous_block_id,previous_block_num):
            # we should take all chain of predecessors
            if previous_block_id not in self.block_cache :
                if self._has_block(block.previous_block_id) :
                    return False
                return True
            else:
                # check num
                
                blk = self.block_cache[previous_block_id]
                LOGGER.debug("Check in cache block: %s", blk)
                if blk is not None and Federation.is_diff_feder(previous_block_num,blk.block_num):
                    LOGGER.debug("Check in cache num=%s~%s block: %s", previous_block_num,blk.block_num,previous_block_id[:8])
                    try:
                        self._block_store.get_block_by_number(int(previous_block_num))
                    except KeyError:
                        return True
                    return False
                return False
                #return blk is not None and blk.block_num != previous_block_num 

        if block.header_signature in self.block_cache:
            LOGGER.debug("Drop duplicate block: %s", block)
            return None
        """
        check federation of block and corresponding nest 
        in case nest is absent keep this block until nest appeared

        """
        if nest and not self._has_genesis_federation(block.block_num):
            LOGGER.debug("Keep until get federation nest for block: %s", block)
            if block.block_num not in self._pending_heads:
                self._pending_heads[block.block_num] = block
            return None
        #LOGGER.debug("complete block=%s",block)
        previous_block_num = Federation.dec_feder_num(block.block_num)
        if check_missing_predecessor(block.previous_block_id,previous_block_num):
            if True : #not self._has_block(block.previous_block_id):
                """
                block incompleted ask missing block
                """
                LOGGER.debug("Incomplete block=%s.%s incompletes=%s",block.block_num,block.header_signature[:8],len(self.incomplete_blocks))
                #previous_block_num = Federation.dec_feder_num(block.block_num)
                if previous_block_num not in self._incomplete_blocks:
                    self._incomplete_blocks[previous_block_num] = [block]
                if block.previous_block_id not in self._incomplete_blocks:
                    self._incomplete_blocks[block.previous_block_id] = [block]
                elif block not in self._incomplete_blocks[block.previous_block_id]:
                    # insert before block with more number
                    self._incomplete_blocks[block.previous_block_id] += [block]
                    """
                    for i, blk in enumerate(self._incomplete_blocks[block.previous_block_id]):
                        if blk.block_num == block.block_num:
                            break
                        if blk.block_num >  block.block_num:
                            # insert before
                            self._incomplete_blocks[block.previous_block_id].insert(i,block)
                            LOGGER.debug("incomplete_blocks key=%s  blocks=%s",block.previous_block_id[:8],[blk.header_signature[:8] for blk in self._incomplete_blocks[block.previous_block_id]])
                            break
                    """
                # We have already requested the block, do not do so again
                if block.previous_block_id in self._requested:
                    LOGGER.debug("Missing predecessor=%s already requested=%s",block.previous_block_id[:8],self.requested)
                    return None
                #if block.header_signature not in self._incomplete_blocks:
                # it could be block from others branch try to find 
                #insert_lost_block(block)
                    

                LOGGER.debug("Request missing predecessor: %s.%s IS=%s num=%s",block.block_num,block.previous_block_id[:8],block.header_signature in self._incomplete_blocks,len(self._incomplete_blocks))
                self._requested[block.previous_block_id] = None
                self.gossip.broadcast_block_request(block.previous_block_id,block.block_num)
                return None

        # Check for same number of batch_ids and batches
        # If different starting building batch list, Otherwise there is a batch
        # that does not belong, block should be dropped.
        if len(block.batches) > len(block.header.batch_ids):
            LOGGER.debug("Block has extra batches. Dropping %s", block)
            return None

        # used to supplement batch_cache, contains batches already in block
        temp_batches = {}
        for batch in block.batches:
            temp_batches[batch.header_signature] = batch

        # The block is missing batches. Check to see if we can complete it.
        if len(block.batches) != len(block.header.batch_ids):
            building = True
            for batch_id in block.header.batch_ids:
                if batch_id not in self.batch_cache and \
                        batch_id not in temp_batches:
                    # Request all missing batches
                    if batch_id not in self._incomplete_blocks:
                        self._incomplete_blocks[batch_id] = [block]
                    elif block not in self._incomplete_blocks[batch_id]:
                        self._incomplete_blocks[batch_id] += [block]

                    # We have already requested the batch, do not do so again
                    if batch_id in self._requested:
                        return None
                    self._requested[batch_id] = None
                    self.gossip.broadcast_batch_by_batch_id_request(batch_id)
                    building = False

            if not building:
                # The block cannot be completed.
                return None

            batches = self._finalize_batch_list(block, temp_batches)
            del block.batches[:]
            # reset batches with full list batches
            block.batches.extend(batches)
            if block.header_signature in self._requested:
                del self._requested[block.header_signature]
            return block

        else:
            batch_id_list = [x.header_signature for x in block.batches]
            # Check to see if batchs are in the correct order.
            if batch_id_list == list(block.header.batch_ids):
                if block.header_signature in self._requested:
                    del self._requested[block.header_signature]
                LOGGER.debug("Block completed BLOCK=%s", block)
                return block
            # Check to see if the block has all batch_ids and they can be put
            # in the correct order
            elif sorted(batch_id_list) == sorted(list(block.header.batch_ids)):
                batches = self._finalize_batch_list(block, temp_batches)
                # Clear batches from block
                del block.batches[:]
                # reset batches with full list batches
                if batches is not None:
                    block.batches.extend(batches)
                else:
                    return None

                if block.header_signature in self._requested:
                    del self._requested[block.header_signature]

                return block
            else:
                LOGGER.debug("Block.header.batch_ids does not match set of batches in block.batches Dropping %s", block)
                return None

    def _finalize_batch_list(self, block, temp_batches):
        batches = []
        for batch_id in block.header.batch_ids:
            if batch_id in self.batch_cache:
                batches.append(self.batch_cache[batch_id])
            elif batch_id in temp_batches:
                batches.append(temp_batches[batch_id])
            else:
                return None

        return batches

    def _complete_batch(self, batch):
        valid = True
        dependencies = []
        for txn in batch.transactions:
            txn_header = TransactionHeader()
            txn_header.ParseFromString(txn.header)
            for dependency in txn_header.dependencies:
                # Check to see if the dependency has been seen or is in the
                # current chain (block_store)
                if dependency not in self._seen_txns and not \
                        self.block_cache.block_store.has_transaction(
                        dependency):
                    LOGGER.debug("Transaction %s in batch %s has unsatisfied dependency: %s",txn.header_signature,batch.header_signature,dependency)

                    # Check to see if the dependency has already been requested
                    if dependency not in self._requested:
                        dependencies.append(dependency)
                        self._requested[dependency] = None
                    if dependency not in self._incomplete_batches:
                        self._incomplete_batches[dependency] = [batch]
                    elif batch not in self._incomplete_batches[dependency]:
                        self._incomplete_batches[dependency] += [batch]
                    valid = False
        if not valid:
            self.gossip.broadcast_batch_by_transaction_id_request(dependencies)

        return valid

    def _add_seen_txns(self, batch):
        for txn in batch.transactions:
            self._seen_txns[txn.header_signature] = batch.header_signature

    def _process_incomplete_batches(self, key):
        # Keys are transaction_id
        if key in self._incomplete_batches:
            batches = self._incomplete_batches[key]
            for batch in batches:
                self.add_batch(batch)
            del self._incomplete_batches[key]

    def _process_incomplete_blocks(self, key,num_mode=False):
        # Keys are either a block_id or batch_id
        if key in self._incomplete_blocks:
            to_complete = deque()
            to_complete.append(key)
            LOGGER.debug("process_incomplete_blocks mode=%s KEY=%s blocks=%s",num_mode,key[:8],self.incomplete_blocks)
            while to_complete:
                my_key = to_complete.popleft()
                if my_key in self._incomplete_blocks:
                    inc_blocks = self._incomplete_blocks[my_key]
                    LOGGER.debug("process_incomplete_blocks MY_KEY=%s inc_blocks=%s",my_key[:8],["{}.{}".format(blk.block_num,blk.header_signature[:8]) for blk in inc_blocks])
                    for inc_block in inc_blocks:
                        if self._complete_block(inc_block):
                            self.block_cache[inc_block.header_signature] = inc_block
                            LOGGER.debug("ADD BLOCK=%s.%s INCOMP",inc_block.block_num,inc_block.header_signature[:8])
                            self._on_block_received(inc_block)
                            to_complete.append(inc_block.header_signature if not num_mode else str(inc_block.block_num))
                    del self._incomplete_blocks[my_key]

    def set_on_block_received(self, on_block_received_func):
        self._on_block_received = on_block_received_func

    def set_on_batch_received(self, on_batch_received_func):
        # this is func which send batch to publisher QUEUE block_publisher.queue_batch
        self._on_batch_received = on_batch_received_func

    def set_chain_has_block(self, set_chain_has_block,set_has_genesis_federation_block,set_is_nests_ready):
        self._has_block = set_chain_has_block
        self._has_genesis_federation_block = set_has_genesis_federation_block
        self._is_nests_ready = set_is_nests_ready

    @property
    def is_pending_head(self):
        mode = (len(self._pending_heads) > 0) or (not self._is_nests_ready()) or self._incomplete_loop
        LOGGER.debug("IS_PENDING_HEAD nest_ready=%s incomp=%s heads=%s mode=%s\n",self._is_nests_ready(),self._incomplete_loop,len(self._pending_heads),mode)
        return mode

    def recover_block(self,blkws):
        LOGGER.debug("RECOVER BLOCKS=%s",len(blkws))
        with self.lock:
            for blkw in blkws :
                self._on_block_received(blkw)

    def add_block(self, block,check_pending=False,nest=False):
        with self.lock:
            if check_pending:
                if len(self._pending_heads) == 0:
                    return
                #take from pending queue
                _,blkw = self._pending_heads.popitem()
            else:
                blkw = BlockWrapper(block)
            # new block from net
            
            while True:
                block = self._complete_block(blkw,nest)
                 
                if block is not None:
                    # completed block - in sync mode genesis block
                    self.block_cache[block.header_signature] = blkw
                    LOGGER.debug("ADD BLOCK=%s.%s PROCESS INCOMPLETED",block.block_num,block.header_signature[:8])
                    """
                    PUT BLOCK into chain controller queue
                    """
                    self._on_block_received(blkw)
                    # take all rest blocks 
                    #self._process_incomplete_blocks(block.header_signature)
                    self._incomplete_loop =True
                    self._process_incomplete_blocks(str(block.block_num),True)
                    self._incomplete_loop = False
                    LOGGER.debug("ADD INCOMPLETED BLOCKS DONE  nest_ready=%s pending=%s\n",self._is_nests_ready(),[bnum for bnum in self._pending_heads.keys()])
                    if len(self._pending_heads) == 0 :
                        break
                    if not self._is_nests_ready():
                        break
                    _,blkw = self._pending_heads.popitem()
                    
                else:
                    break

                

    def add_batch(self, batch,recomm=None):
        """
        candidate_id - use it for DAG version (id,block_num)
        """
        with self.lock:
            if batch.header_signature in self.batch_cache:
                return
            if self._complete_batch(batch):
                self.batch_cache[batch.header_signature] = batch
                self._add_seen_txns(batch)
                self._on_batch_received(batch,recomm) # send to publisher block_publisher.queue_batch
                self._process_incomplete_blocks(batch.header_signature)
                if batch.header_signature in self._requested:
                    del self._requested[batch.header_signature]
                # If there was a batch waiting on this transaction, process
                # that batch
                for txn in batch.transactions:
                    if txn.header_signature in self._incomplete_batches:
                        if txn.header_signature in self._requested:
                            del self._requested[txn.header_signature]
                        self._process_incomplete_batches(txn.header_signature)

    def get_chain_head(self):
        """Returns the block which is the current head of the chain.

        Returns:
            BlockWrapper: The head of the chain.
        """
        with self.lock:
            #LOGGER.debug("federation_heads=%s",[blk.header_signature[:8] for blk in self._block_store.federation_heads])
            return self._block_store.chain_head

    def _has_genesis_federation(self,block_num):
        """
        check for not genesis federation is genesis feder first block present or not 
        into block store or into queue
        """
        fnum,_ = Federation.feder_num_to_num(block_num)
        if fnum < 2:
            return True
        # not genesis - check genesis first block into chain queue or store
        return self._has_genesis_federation_block()

    def _has_federation_nest(self,block_num):
        with self.lock:
            return self._block_store.has_federation(block_num)

    def get_federation_heads(self,feder=None):
        #all heads or exactly feder
        with self.lock:
            return self._block_store.federation_heads
         
    def get_block(self, block_id):
        with self.lock:
            if block_id in self.block_cache:
                return self.block_cache[block_id]
            return None

    def get_block_by_num(self, block_num):
        with self.lock:
            return self._block_store.get_block_by_number(block_num)


    def get_batch(self, batch_id):
        with self.lock:
            if batch_id in self.batch_cache:
                return self.batch_cache[batch_id]

            else:
                block_store = self.block_cache.block_store
                try:
                    return block_store.get_batch(batch_id)
                except ValueError:
                    return None

    def get_batch_by_transaction(self, transaction_id):
        with self.lock:
            if transaction_id in self._seen_txns:
                batch_id = self._seen_txns[transaction_id]
                return self.get_batch(batch_id)

            else:
                block_store = self.block_cache.block_store
                try:
                    return block_store.get_batch_by_transaction(transaction_id)
                except ValueError:
                    return None


class CompleterBatchListBroadcastHandler(Handler):
    def __init__(self, completer, gossip):
        self._completer = completer
        self._gossip = gossip

    def handle(self, connection_id, message_content):
        request = ClientBatchSubmitRequest()
        request.ParseFromString(message_content)
        for batch in request.batches:
            if batch.trace:
                LOGGER.debug("TRACE %s: %s", batch.header_signature,self.__class__.__name__)
            # works in case own batch for node
            LOGGER.debug("CompleterBatchListBroadcastHandler: broadcast BATCH=%s", batch.header_signature[:8])
            self._completer.add_batch(batch,('',0,0))
            # send batch to peers - for DAG maybe good idea send batches to peers only after DAG branch will be chosen into publisher FIXME 
            LOGGER.debug("CompleterBatchListBroadcastHandler: broadcast BATCH DONE")
            # this is for old version with out DAG
            #self._gossip.broadcast_batch(batch)
        return HandlerResult(status=HandlerStatus.PASS)


class CompleterGossipHandler(Handler):
    def __init__(self, completer):
        self._completer = completer

    def handle(self, connection_id, message_content):
        gossip_message = network_pb2.GossipMessage()
        gossip_message.ParseFromString(message_content)
        if gossip_message.content_type == network_pb2.GossipMessage.BLOCK:
            block = Block()
            block.ParseFromString(gossip_message.content)
            LOGGER.debug("CompleterGossipHandler: BLOCK=%s",block.header_signature[:8])
            self._completer.add_block(block)
        elif gossip_message.content_type == network_pb2.GossipMessage.BATCH:
            batch = Batch()
            batch.ParseFromString(gossip_message.content)
            #candidate_id = gossip_message.candidate_id.hex()
            LOGGER.debug("CompleterGossipHandler: NEW BATCH=%s ", batch.header_signature[:8])
            # works in case batch from another node
            self._completer.add_batch(batch)

        elif gossip_message.content_type == network_pb2.GossipMessage.BATCHES:
            batches = BatchList()
            batches.ParseFromString(gossip_message.content)
            candidate_id = batches.candidate_id.hex()
            num = len(batches.batches)
            #LOGGER.debug("CompleterGossipHandler: NEW BATCHES=%s candidate_id=%s", batches,candidate_id[:8])
            
            block_num = batches.block_num
            for batch in batches.batches:
                LOGGER.debug(" => NEW BATCH[%s]=%s candidate_id=%s.%s",num,batch.header_signature[:8],block_num,candidate_id[:8])
                self._completer.add_batch(batch,(candidate_id,block_num,num))
                


        return HandlerResult(status=HandlerStatus.PASS)


class CompleterGossipBlockResponseHandler(Handler):
    def __init__(self, completer):
        self._completer = completer

    def handle(self, connection_id, message_content):
        block_response_message = network_pb2.GossipBlockResponse()
        block_response_message.ParseFromString(message_content)

        block = Block()
        block.ParseFromString(block_response_message.content)
        LOGGER.debug("CompleterGossipBlockResponseHandler: BLOCK=%s nest=%s",block.header_signature[:8],block_response_message.nest)
        self._completer.add_block(block,nest=block_response_message.nest)

        return HandlerResult(status=HandlerStatus.PASS)


class CompleterGossipBatchResponseHandler(Handler):
    def __init__(self, completer):
        self._completer = completer

    def handle(self, connection_id, message_content):
        batch_response_message = network_pb2.GossipBatchResponse()
        batch_response_message.ParseFromString(message_content)

        batch = Batch()
        batch.ParseFromString(batch_response_message.content)
        self._completer.add_batch(batch)

        return HandlerResult(status=HandlerStatus.PASS)
