# Copyright 2016 DGT NETWORK INC © Stanislav Parsov 
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

from dgt_validator.networking.dispatch import Handler
from dgt_validator.networking.dispatch import HandlerResult
from dgt_validator.networking.dispatch import HandlerStatus
from dgt_validator.protobuf import validator_pb2
from dgt_validator.protobuf.batch_pb2 import Batch,BatchList
from dgt_validator.protobuf.block_pb2 import Block
from dgt_validator.protobuf.consensus_pb2 import ConsensusPeerMessage,ConsensusPeerMessageNew,ConsensusPeerMessageHeader
from dgt_validator.protobuf.network_pb2 import GossipMessage
from dgt_validator.protobuf.network_pb2 import GossipConsensusMessage
from dgt_validator.protobuf.network_pb2 import GossipBlockResponse
from dgt_validator.protobuf.network_pb2 import GossipBatchResponse
from dgt_validator.protobuf.network_pb2 import GetPeersRequest
from dgt_validator.protobuf.network_pb2 import GetPeersResponse
from dgt_validator.protobuf.network_pb2 import PeerRegisterRequest
from dgt_validator.protobuf.network_pb2 import PeerUnregisterRequest
from dgt_validator.protobuf.network_pb2 import NetworkAcknowledgement
from dgt_validator.protobuf.network_pb2 import EndpointItem,EndpointList
from dgt_validator.exceptions import PeeringException

LOGGER = logging.getLogger(__name__)


class GetPeersRequestHandler(Handler):
    def __init__(self, gossip):
        self._gossip = gossip

    def handle(self, connection_id, message_content):
        """
        Dynamic topology request
        """
        request = GetPeersRequest()
        request.ParseFromString(message_content)
        pid = request.peer_id.hex()
        LOGGER.debug("Got peers request message from %s peer_id=%s cluster='%s' KYC='%s' network=%s endpoint='%s'\n", connection_id[:8],pid[:8],request.cluster,request.KYC,request.network,request.endpoint)
        if request.endpoint == '':
            self._gossip.send_peers(connection_id)
        else:
            # fbft dynamic mode
            self._gossip.send_fbft_peers(connection_id,pid,request.endpoint,request.cluster,request.KYC,request.network,request.batch)

        ack = NetworkAcknowledgement()
        ack.status = ack.OK

        return HandlerResult(
            HandlerStatus.RETURN,
            message_out=ack,
            message_type=validator_pb2.Message.NETWORK_ACK)


class GetPeersResponseHandler(Handler):
    def __init__(self, gossip):
        self._gossip = gossip

    def handle(self, connection_id, message_content):
        """
        reply on my dynamic request about peers 
        """
        response = GetPeersResponse()
        response.ParseFromString(message_content)

        LOGGER.debug("Got peers topology response message from %s. Status=%s cluster=%s Endpoints: %s",connection_id[:8],response.status,response.cluster,response.peer_endpoints)

        self._gossip.add_candidate_peer_endpoints(response.peer_endpoints,response.status,response.cluster)

        return HandlerResult(HandlerStatus.PASS)


class PeerRegisterHandler(Handler):
    def __init__(self, gossip):
        self._gossip = gossip

    def handle(self, connection_id, message_content):
        request = PeerRegisterRequest()
        request.ParseFromString(message_content)

        #LOGGER.debug("Got peer register message MODE=%s from %s(%s)",request.mode,request.endpoint,connection_id[:10])

        ack = NetworkAcknowledgement()
        try:
            ack.pid = self._gossip.peer_id
            if request.mode == PeerRegisterRequest.REGISTER:
                """
                Other peer ask register - mark this peer unsync until sync request appeared
                """
                LOGGER.debug("Peer=%s(%s) ask REGISTER component=%s expoint=%s",request.endpoint,connection_id[:10],request.component,request.extpoint)
                sync = self._gossip.register_peer(connection_id,request.pid, request.endpoint,sync=None,component=request.component,extpoint=request.extpoint) # sync=(True if self._gossip.is_sync else None)
                # say asked peer about point of assemble
                ack.status = ack.OK
                ack.sync   = self._gossip.is_sync # FIXME sync
                LOGGER.debug("register peer sync=%s(%s) SYNC=%s DONE",sync,request.endpoint,self._gossip.is_sync)
            else:
                """
                Peer ask sync after his nests were builded  
                """
                LOGGER.debug("Peer=%s(%s) ask SYNC",request.endpoint,connection_id[:10])
                ack.status = ack.OK
                ack.sync   = self._gossip.sync_peer(connection_id,request.pid, request.endpoint,nests=request.hid)
                LOGGER.debug("SYNC request from peer=%s sync=%s hid=%s DONE\n",request.endpoint,ack.sync,request.hid)

        except PeeringException:
            ack.status = ack.ERROR
            LOGGER.debug("ERROR SYNC request from peer=%s\n",request.endpoint)

        return HandlerResult(
            HandlerStatus.RETURN,
            message_out=ack,
            message_type=validator_pb2.Message.NETWORK_ACK)


class PeerUnregisterHandler(Handler):
    def __init__(self, gossip):
        self._gossip = gossip

    def handle(self, connection_id, message_content):
        request = PeerUnregisterRequest()
        request.ParseFromString(message_content)

        LOGGER.debug("Got peer unregister message from %s", connection_id)

        self._gossip.unregister_peer(connection_id)
        ack = NetworkAcknowledgement()
        ack.status = ack.OK

        return HandlerResult(
            HandlerStatus.RETURN,
            message_out=ack,
            message_type=validator_pb2.Message.NETWORK_ACK)


class GossipMessageDuplicateHandler(Handler):
    def __init__(self, completer, has_block, has_batch):
        self._completer = completer
        self._has_block = has_block
        self._has_batch = has_batch

    def handle(self, connection_id, message_content):
        gossip_message = GossipMessage()
        gossip_message.ParseFromString(message_content)
        LOGGER.debug("GossipMessageDuplicateHandler: content_type=%s", gossip_message.content_type)
        if gossip_message.content_type == gossip_message.BLOCK:
            block = Block()
            block.ParseFromString(gossip_message.content)
            has_block = False
            if self._completer.get_block(block.header_signature) is not None:
                has_block = True

            if not has_block and self._has_block(block.header_signature):
                has_block = True

            if has_block:
                LOGGER.debug("GossipMessageDuplicateHandler: DROP BLOCK=%s", block.header_signature[:8])
                return HandlerResult(HandlerStatus.DROP)
            LOGGER.debug("GossipMessageDuplicateHandler: PASS BLOCK=%s", block.header_signature[:8])

        if gossip_message.content_type == gossip_message.BATCH:
            batch = Batch()
            batch.ParseFromString(gossip_message.content)
            has_batch = False
            if self._completer.get_batch(batch.header_signature) is not None:
                has_batch = True

            if not has_batch and self._has_batch(batch.header_signature):
                has_batch = True

            if has_batch:
                return HandlerResult(HandlerStatus.DROP)
        if gossip_message.content_type == gossip_message.BATCHES:
            # check batches FIXME
            LOGGER.debug("GossipMessageDuplicateHandler: check BATCHES")
            batches = BatchList()
            batches.ParseFromString(gossip_message.content)
            has_batch = False
            batch_sign = None
            LOGGER.debug("GossipMessageDuplicateHandler: check BATCHES=%s",len(batches.batches))
            for batch in batches.batches:
                if self._completer.get_batch(batch.header_signature) is not None or self._has_batch(batch.header_signature):
                    has_batch = True
                    batch_sign = batch.header_signature
                    break
            if has_batch:
                candidate_id = batches.candidate_id.hex()
                block_num = batches.block_num
                LOGGER.debug("GossipMessageDuplicateHandler: BATCHES dublicate batch=%s for branch=%s.%s IGNORE",batch_sign[:8],block_num,candidate_id[:8])
                return HandlerResult(HandlerStatus.DROP)
                
            

        return HandlerResult(HandlerStatus.PASS)


class GossipBlockResponseHandler(Handler):
    def __init__(self, completer, responder, chain_controller_has_block):
        self._completer = completer
        self._responder = responder
        self._chain_controller_has_block = chain_controller_has_block

    def handle(self, connection_id, message_content):
        block_response_message = GossipBlockResponse()
        block_response_message.ParseFromString(message_content)
        block = Block()
        block.ParseFromString(block_response_message.content)

        block_id = block.header_signature
        LOGGER.debug("GossipBlockResponseHandler: BLOCK=%s", block_id[:8])
        ack = NetworkAcknowledgement()
        ack.status = ack.OK

        if not self._has_open_requests(block_id) and self._has_block(block_id):
            LOGGER.debug("GossipBlockResponseHandler: ALREADY HAS BLOCK=%s\n", block_id[:8])
            return HandlerResult(
                HandlerStatus.RETURN,
                message_out=ack,
                message_type=validator_pb2.Message.NETWORK_ACK
            )

        return HandlerResult(
            HandlerStatus.RETURN_AND_PASS,
            message_out=ack,
            message_type=validator_pb2.Message.NETWORK_ACK)

    def _has_block(self, block_id):
        return (self._completer.get_block(block_id) is not None
                or self._chain_controller_has_block(block_id))

    def _has_open_requests(self, block_id):
        return self._responder.get_request(block_id)


class GossipBatchResponseHandler(Handler):
    def __init__(self, completer, responder, block_publisher_has_batch):
        self._completer = completer
        self._responder = responder
        self._block_publisher_has_batch = block_publisher_has_batch

    def handle(self, connection_id, message_content):
        batch_response_message = GossipBatchResponse()
        batch_response_message.ParseFromString(message_content)
        batch = Batch()
        batch.ParseFromString(batch_response_message.content)

        batch_id = batch.header_signature

        ack = NetworkAcknowledgement()
        ack.status = ack.OK

        if not self._has_open_requests(batch_id) and self._has_batch(batch_id):
            return HandlerResult(
                HandlerStatus.RETURN,
                message_out=ack,
                message_type=validator_pb2.Message.NETWORK_ACK
            )

        return HandlerResult(
            HandlerStatus.RETURN_AND_PASS,
            message_out=ack,
            message_type=validator_pb2.Message.NETWORK_ACK)

    def _has_batch(self, batch_id):
        return (self._completer.get_batch(batch_id) is not None
                or self._block_publisher_has_batch(batch_id))

    def _has_open_requests(self, batch_id):
        return self._responder.get_request(batch_id)


class GossipBroadcastHandler(Handler):
    def __init__(self, gossip, completer):
        self._gossip = gossip
        self._completer = completer

    def handle(self, connection_id, message_content):
        exclude = [connection_id]
        gossip_message = GossipMessage()
        gossip_message.ParseFromString(message_content)
        if gossip_message.time_to_live == 0:
            # Do not forward message if it has reached its time to live limit
            LOGGER.debug("GossipBroadcastHandler: Do not forward message if it has reached its time to live!\n")
            return HandlerResult(status=HandlerStatus.PASS)

        else:
            # decrement time_to_live
            time_to_live = gossip_message.time_to_live
            gossip_message.time_to_live = time_to_live - 1

        if gossip_message.content_type == GossipMessage.BATCH:
            """
            batch from others nodes 
            """
            batch = Batch()
            batch.ParseFromString(gossip_message.content)
            # If we already have this batch, don't forward it
            LOGGER.debug("GossipBroadcastHandler: check BATCH=%s !!!",batch.header_signature[:8])
            if not self._completer.get_batch(batch.header_signature):
                # this new batch for this node 
                LOGGER.debug("GossipBroadcastHandler: new BATCH=%s exclude=%s!!!",batch.header_signature[:8],[self._gossip._peers[cid] for cid in exclude])
                self._gossip.broadcast_batch(batch, exclude)

        elif gossip_message.content_type == GossipMessage.BATCHES:
            LOGGER.debug("GossipBroadcastHandler:handle BATCHES !!!")

        elif gossip_message.content_type == GossipMessage.BLOCK:
            
            block = Block()
            block.ParseFromString(gossip_message.content)
            LOGGER.debug("GossipBroadcastHandler:handle BLOCK=%s !!!",block.header_signature[:8])
            # If we already have this block, don't forward it
            if not self._completer.get_block(block.header_signature):
                # dont send block to others cluster
                cluster_exclude = self._gossip.get_exclude()
                if cluster_exclude:
                    cluster_exclude.append(connection_id)
                else:
                    cluster_exclude = [connection_id]
                LOGGER.debug("broadcast block=%s exclude=%s cid=%s!!!",block.header_signature[:8],[self._gossip._peers[cid] for cid in cluster_exclude if cid in self._gossip._peers],connection_id[:8])
                self._gossip.broadcast_block(block, cluster_exclude)
        elif gossip_message.content_type == GossipMessage.ENDPOINTS:
            endpoints = EndpointList()
            endpoints.ParseFromString(gossip_message.content)
            self._gossip.endpoint_list(endpoints)
        else:
            LOGGER.info("received %s, not BATCH or BLOCK",gossip_message.content_type)

        return HandlerResult(status=HandlerStatus.PASS)


class GossipConsensusMessageHandler(Handler):
    def __init__(self, notifier,signed_consensus=False):
        self._notifier = notifier
        self._signed_consensus = signed_consensus

    def handle(self, connection_id, message_content):
        gossip_message = GossipConsensusMessage()
        gossip_message.ParseFromString(message_content)
        if self._signed_consensus:
            # signed message we can check here is sign  right or not
            peer_message = ConsensusPeerMessageNew()
            peer_message.ParseFromString(gossip_message.message)
            header = ConsensusPeerMessageHeader()
            header.ParseFromString(peer_message.header)
            message_type = header.message_type
        else:
            peer_message = ConsensusPeerMessage()
            peer_message.ParseFromString(gossip_message.message)
            message_type = peer_message.message_type

        LOGGER.debug("GossipConsensusMessageHandler:peer_message '%s' peer=%s",message_type,gossip_message.sender_id)
        self._notifier.notify_peer_message(
            message=peer_message,
            sender_id=gossip_message.sender_id,
            message_type = message_type)
        return HandlerResult(status=HandlerStatus.PASS)
