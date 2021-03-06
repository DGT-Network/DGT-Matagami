# Copyright 2017 DGT NETWORK INC © Stanislav Parsov 
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

from dgt_validator.networking.dispatch import Handler
from dgt_validator.networking.dispatch import HandlerResult
from dgt_validator.networking.dispatch import HandlerStatus
from dgt_validator.journal.timed_cache import TimedCache
from dgt_validator.journal.block_store import Federation
from dgt_validator.protobuf import network_pb2
from dgt_validator.protobuf import validator_pb2
from dgt_validator.protobuf import block_pb2
from dgt_validator.protobuf import batch_pb2

LOGGER = logging.getLogger(__name__)

CACHE_KEEP_TIME = 300


class Responder(object):
    def __init__(self,
                 completer,
                 cache_keep_time=300,
                 cache_purge_frequency=30):
        self.completer = completer
        self.pending_requests = TimedCache(cache_keep_time,cache_purge_frequency)
        self._lock = RLock()

    def check_for_block(self, block_id):
        # Ask Completer
        if block_id == "HEAD":
            block = self.completer.get_federation_heads()
            #block = self.completer.get_chain_head()
        else:
            block = self.completer.get_block(block_id)
        return block

    def get_block_by_num(self,block_num):
        return self.completer.get_block_by_num(block_num)

    def check_for_batch(self, batch_id):
        batch = self.completer.get_batch(batch_id)
        return batch

    def check_for_batch_by_transaction(self, transaction_id):
        batch = self.completer.get_batch_by_transaction(transaction_id)
        return batch

    def already_requested(self, requested_id):
        with self._lock:
            if requested_id in self.pending_requests:
                return True
            return False

    def add_request(self, requested_id, connection_id):
        LOGGER.debug("add_request [%s]=%s",requested_id[:8],connection_id[:8])
        with self._lock:
            if requested_id in self.pending_requests:
                if connection_id not in self.pending_requests[requested_id]:
                    self.pending_requests[requested_id] += [connection_id]

            else:
                self.pending_requests[requested_id] = [connection_id]

    def get_request(self, requested_id):
        with self._lock:
            return self.pending_requests.get(requested_id)

    def remove_request(self, requested_id):
        with self._lock:
            if requested_id in self.pending_requests:
                del self.pending_requests[requested_id]


class BlockResponderHandler(Handler):
    def __init__(self, responder, gossip):
        self._responder = responder
        self._gossip = gossip
        self._seen_requests = TimedCache(CACHE_KEEP_TIME)
        #self._pending = TimedCache(CACHE_KEEP_TIME) # block keeped because of gap

    def handle(self, connection_id, message_content):
        block_request_message = network_pb2.GossipBlockRequest()
        block_request_message.ParseFromString(message_content)
        if block_request_message.nonce in self._seen_requests:
            LOGGER.debug("Received repeat GossipBlockRequest from %s",connection_id)

            return HandlerResult(HandlerStatus.DROP)
        """
        block_id format - HEAD/ID/N<NUM>.ID
        """
        block_id = block_request_message.block_id
        block_num = None
        if block_id[0] == 'N':
            # contain block number
            parts = block_id.split('.')
            block_id = parts[1]
            block_num = parts[0][1:]

        block = self._responder.check_for_block(block_id)
        LOGGER.debug("BlockResponderHandler:ID=%s NUM=%s nonce=%s BLOCK=%s.",block_id if block_id == "HEAD" else block_id[:8],block_num,block_request_message.nonce,block)
        if block is None:
            # No block found, broadcast original message to other peers
            # and add to pending requests
            if block_id == "HEAD":
                LOGGER.debug("No chain head available. Cannot respond to block requests.")
            else:
                if not self._responder.already_requested(block_id):
                    if block_request_message.time_to_live > 0:
                        time_to_live = block_request_message.time_to_live
                        block_request_message.time_to_live = time_to_live - 1
                        self._gossip.broadcast(
                            block_request_message,
                            validator_pb2.Message.GOSSIP_BLOCK_REQUEST,
                            exclude=[connection_id])

                        self._seen_requests[block_request_message.nonce] = block_request_message.block_id

                        self._responder.add_request(block_id, connection_id)
                else:
                    LOGGER.debug("Block %s has already been requested",block_id[:8])

                    self._responder.add_request(block_id, connection_id)
        else:
            """
            check if there is a GAP between block_num and block.block_num send block block_num-1 instead block
            peer as block
            """ 
            if block_id != "HEAD":
                blocks = []
                nest = False
                gap = Federation.gap_feder_num(block_num,block.block_num) if block_num else 0  
                LOGGER.debug("Responding to block requests: BLOCK=%s GAP=%s",block.get_block().header_signature[:8],gap)
                if gap > 1 :
                    # get block by number
                    num = int(Federation.dec_feder_num(block_num))
                    # save request
                    self._responder.add_request(block_id, connection_id)
                    try:
                        block = self._responder.get_block_by_num(num)
                        blocks.append(block)
                        LOGGER.debug("Responding BLOCK=%s",block)
                    except KeyError:
                        LOGGER.debug("THERE IS NO Responding BLOCK=%s",num)

                else:
                    # check may be prev block already was asked
                    blocks.append(block)
                while True:
                    prev_num = int(Federation.dec_feder_num(block.block_num)) 
                    try:
                        block = self._responder.get_block_by_num(prev_num)
                    except KeyError:
                        LOGGER.debug("THERE IS NO Responding BLOCK=%s",prev_num)
                        break
                    prev_block_id = block.get_block().header_signature
                    if self._responder.already_requested(prev_block_id):
                        self._responder.remove_request(prev_block_id)
                        blocks.append(block)
                    else:
                        break
            else:
                blocks = block # list of heads
                nest = True
            
            for block in blocks:
                LOGGER.debug("Responding nest=%s SEND BLOCK=%s",nest,block)
                block_response = network_pb2.GossipBlockResponse(content=block.get_block().SerializeToString(),nest=nest)
                self._gossip.send(validator_pb2.Message.GOSSIP_BLOCK_RESPONSE,block_response.SerializeToString(),connection_id)

        return HandlerResult(HandlerStatus.PASS)


class ResponderBlockResponseHandler(Handler):
    def __init__(self, responder, gossip):
        self._responder = responder
        self._gossip = gossip

    def handle(self, connection_id, message_content):
        block_response = network_pb2.GossipBlockResponse()
        block_response.ParseFromString(message_content)
        block = block_pb2.Block()
        block.ParseFromString(block_response.content)
        open_request = self._responder.get_request(block.header_signature)

        if open_request is None:
            return HandlerResult(status=HandlerStatus.PASS)

        for connection in open_request:
            LOGGER.debug("Responding to block request: Send %s to %s",block.header_signature,connection)
            try:
                self._gossip.send(validator_pb2.Message.GOSSIP_BLOCK_RESPONSE,message_content,connection)
            except ValueError:
                LOGGER.debug("Can't send block response %s to closed "
                             "connection %s",
                             block.header_signature,
                             connection)

        self._responder.remove_request(block.header_signature)

        return HandlerResult(HandlerStatus.PASS)


class BatchByBatchIdResponderHandler(Handler):
    def __init__(self, responder, gossip):
        self._responder = responder
        self._gossip = gossip
        self._seen_requests = TimedCache(CACHE_KEEP_TIME)

    def handle(self, connection_id, message_content):
        batch_request_message = network_pb2.GossipBatchByBatchIdRequest()
        batch_request_message.ParseFromString(message_content)
        if batch_request_message.nonce in self._seen_requests:
            LOGGER.debug("Received repeat GossipBatchByBatchIdRequest from %s",
                         connection_id)
            return HandlerResult(HandlerStatus.DROP)

        batch = None
        batch = self._responder.check_for_batch(batch_request_message.id)

        if batch is None:
            # No batch found, broadcast original message to other peers
            # and add to pending requests
            if not self._responder.already_requested(batch_request_message.id):

                if batch_request_message.time_to_live > 0:
                    time_to_live = batch_request_message.time_to_live
                    batch_request_message.time_to_live = time_to_live - 1
                    self._gossip.broadcast(
                        batch_request_message,
                        validator_pb2.Message.GOSSIP_BATCH_BY_BATCH_ID_REQUEST,
                        exclude=[connection_id])

                    self._seen_requests[batch_request_message.nonce] = \
                        batch_request_message.id

                    self._responder.add_request(batch_request_message.id,
                                                connection_id)
            else:
                LOGGER.debug("Batch %s has already been requested",
                             batch_request_message.id)

                self._responder.add_request(batch_request_message.id,
                                            connection_id)
        else:
            LOGGER.debug("Responding to batch requests %s",
                         batch.header_signature)

            batch_response = network_pb2.GossipBatchResponse(
                content=batch.SerializeToString(),
            )

            self._gossip.send(validator_pb2.Message.GOSSIP_BATCH_RESPONSE,
                              batch_response.SerializeToString(),
                              connection_id)

        return HandlerResult(HandlerStatus.PASS)


class BatchByTransactionIdResponderHandler(Handler):
    def __init__(self, responder, gossip):
        self._responder = responder
        self._gossip = gossip
        self._seen_requests = TimedCache(CACHE_KEEP_TIME)

    def handle(self, connection_id, message_content):
        batch_request_message = network_pb2.GossipBatchByTransactionIdRequest()
        batch_request_message.ParseFromString(message_content)
        if batch_request_message.nonce in self._seen_requests:
            LOGGER.debug("Received repeat GossipBatchByTransactionIdRequest"
                         " from %s", connection_id)

            return HandlerResult(HandlerStatus.DROP)

        batch = None
        batches = []
        unfound_txn_ids = []
        not_requested = []
        for txn_id in batch_request_message.ids:
            batch = self._responder.check_for_batch_by_transaction(
                txn_id)

            # The txn_id was not found.
            if batch is None:
                unfound_txn_ids.append(txn_id)
                if not self._responder.already_requested(txn_id):
                    not_requested.append(txn_id)
                else:
                    LOGGER.debug("Batch containing Transaction %s has already "
                                 "been requested", txn_id)

            # Check to see if a previous txn was in the same batch.
            elif batch not in batches:
                batches.append(batch)

            batch = None

        if batches == [] and len(not_requested) == \
                len(batch_request_message.ids):

            if batch_request_message.time_to_live > 0:
                time_to_live = batch_request_message.time_to_live
                batch_request_message.time_to_live = time_to_live - 1
                self._gossip.broadcast(
                    batch_request_message,
                    validator_pb2.Message.
                    GOSSIP_BATCH_BY_TRANSACTION_ID_REQUEST,
                    exclude=[connection_id])

                self._seen_requests[batch_request_message.nonce] = \
                    batch_request_message.ids

                for txn_id in batch_request_message.ids:
                    self._responder.add_request(txn_id, connection_id)

        elif unfound_txn_ids != []:
            if not_requested != []:
                if batch_request_message.time_to_live > 0:
                    self._seen_requests[batch_request_message.nonce] = \
                        batch_request_message.ids
                    new_request = network_pb2.GossipBatchByTransactionIdRequest()
                    # only request batches we have not requested already
                    new_request.ids.extend(not_requested)
                    # Keep same nonce as original message
                    new_request.nonce = batch_request_message.nonce
                    time_to_live = batch_request_message.time_to_live
                    new_request.time_to_live = time_to_live - 1

                    self._gossip.broadcast(
                        new_request,
                        validator_pb2.Message.
                        GOSSIP_BATCH_BY_TRANSACTION_ID_REQUEST,
                        exclude=[connection_id])
                    # Add all requests to responder
                    for txn_id in unfound_txn_ids:
                        self._responder.add_request(txn_id, connection_id)
            else:
                # Add all requests to responder
                for txn_id in unfound_txn_ids:
                    self._responder.add_request(txn_id, connection_id)

        if batches != []:
            for batch in batches:
                LOGGER.debug("Responding to batch requests %s",
                             batch.header_signature)

                batch_response = network_pb2.GossipBatchResponse(
                    content=batch.SerializeToString(),
                )

                self._gossip.send(validator_pb2.Message.GOSSIP_BATCH_RESPONSE,
                                  batch_response.SerializeToString(),
                                  connection_id)

        return HandlerResult(HandlerStatus.PASS)


class ResponderBatchResponseHandler(Handler):
    def __init__(self, responder, gossip):
        self._responder = responder
        self._gossip = gossip

    def handle(self, connection_id, message_content):
        batch_response = network_pb2.GossipBatchResponse()
        batch_response.ParseFromString(message_content)
        batch = batch_pb2.Batch()
        batch.ParseFromString(batch_response.content)
        open_request = self._responder.get_request(batch.header_signature)

        if open_request is None:
            open_request = []

        requests_to_remove = [batch.header_signature]
        for txn in batch.transactions:
            requests_by_txn = self._responder.get_request(txn.header_signature)
            if requests_by_txn is not None:
                open_request += requests_by_txn
                requests_to_remove += [txn.header_signature]

        for connection in open_request:
            LOGGER.debug("Responding to batch requests: Send %s to %s",
                         batch.header_signature,
                         connection)
            try:
                self._gossip.send(validator_pb2.Message.GOSSIP_BATCH_RESPONSE,
                                  message_content,
                                  connection)
            except ValueError:
                LOGGER.debug("Can't send batch response %s to closed "
                             "connection %s",
                             batch.header_signature,
                             connection)

        for requested_id in requests_to_remove:
            self._responder.remove_request(requested_id)

        return HandlerResult(HandlerStatus.PASS)
