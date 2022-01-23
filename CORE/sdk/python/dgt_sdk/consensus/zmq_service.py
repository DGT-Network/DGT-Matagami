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
# -----------------------------------------------------------------------------

from dgt_sdk.consensus.service import Service
from dgt_sdk.consensus.service import Block
from dgt_sdk.consensus import exceptions
from dgt_sdk.protobuf import consensus_pb2
from dgt_sdk.protobuf.validator_pb2 import Message
from dgt_sdk.protobuf.consensus_pb2 import ConsensusPeerMessageNew,ConsensusPeerMessageHeader
import logging
import hashlib
LOGGER = logging.getLogger(__name__)

class ZmqService(Service):
    def __init__(self, stream, timeout, name, version):
        self._stream = stream
        self._timeout = timeout
        self._name = name
        self._version = version
        self._signer = None 
    
    def set_signer(self,signer):
        # for signed consensus message
        self._signer = signer
        self._signer_public_key=self._signer.get_public_key().as_hex()
        LOGGER.debug(f"ZmqService:set_signer {self._signer_public_key}")

    def _send(self, request, message_type, response_type):
        response_bytes = self._stream.send(
            message_type=message_type,
            content=request.SerializeToString(),
        ).result(self._timeout).content

        response = response_type()
        response.ParseFromString(response_bytes)

        return response

    # -- P2P --
    def make_consensus_peer_message(self,message_type, payload):
        if self._signer is not None:
            # SIGNED MESSAGE MODE
            header = ConsensusPeerMessageHeader(                                          
                         signer_id = self._signer_public_key,                             
                         content_sha512  = hashlib.sha512(payload).hexdigest(),           
                         message_type = message_type,                                     
                         name = self._name,                                               
                         version = self._version                                          
                )                                                                         
            ser_header = header.SerializeToString()                                       
            signed_msg = ConsensusPeerMessageNew(                                               
                         header = ser_header,                                             
                         header_signature = self._signer.sign(ser_header),                
                         content = payload                                                
                )                                                                         
            #LOGGER.debug(f"ZmqService:consensus_peer_message header={header} msg={signed_msg}") 
            return signed_msg

        message = consensus_pb2.ConsensusPeerMessage(         
            message_type=message_type,                        
            content=payload,                                  
            name=self._name,                                  
            version=self._version)                            
        
        
         
        return message

    def send_to(self, peer_id, message_type, payload):
        message = self.make_consensus_peer_message(message_type, payload) 

        request = consensus_pb2.ConsensusSendToRequest(
            message=message.SerializeToString(),
            peer_id=peer_id)

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_SEND_TO_REQUEST,
            response_type=consensus_pb2.ConsensusSendToResponse)

        if response.status != consensus_pb2.ConsensusSendToResponse.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(response.status))

    def broadcast_to_cluster(self, message_type, payload):
        """
        FIXME - better use special message like CONSENSUS_BROADCAST_REQUEST and send only one message and validator take cluster's peer from topology
        """
        
        message = self.make_consensus_peer_message(message_type, payload)

        request = consensus_pb2.ConsensusBroadcastClusterRequest(message=message.SerializeToString())
        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_BROADCAST_CLUSTER_REQUEST,
            response_type=consensus_pb2.ConsensusBroadcastClusterResponse)

        if response.status != consensus_pb2.ConsensusBroadcastClusterResponse.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(response.status))
        

    def broadcast_to_arbiter(self, message_type, payload):
        """
        FIXME - better use special message like CONSENSUS_BROADCAST_REQUEST and send only one message and validator take cluster's peer from topology
        """
        message = self.make_consensus_peer_message(message_type, payload)

        request = consensus_pb2.ConsensusBroadcastArbiterRequest(message=message.SerializeToString())
        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_BROADCAST_ARBITER_REQUEST,
            response_type=consensus_pb2.ConsensusBroadcastArbiterResponse)

        if response.status != consensus_pb2.ConsensusBroadcastArbiterResponse.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(response.status))
        

    def broadcast(self, message_type, payload):
        message = self.make_consensus_peer_message(message_type, payload)

        request = consensus_pb2.ConsensusBroadcastRequest(message=message.SerializeToString())

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_BROADCAST_REQUEST,
            response_type=consensus_pb2.ConsensusBroadcastResponse)

        if response.status != consensus_pb2.ConsensusBroadcastResponse.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(response.status))

    # -- Block Creation --

    def initialize_block(self, previous_id=None,nest_colour=None):
        request = (
            consensus_pb2.ConsensusInitializeBlockRequest(
                previous_id=previous_id,nest_colour=nest_colour)
            if previous_id
            else consensus_pb2.ConsensusInitializeBlockRequest()
        )

        response_type = consensus_pb2.ConsensusInitializeBlockResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_INITIALIZE_BLOCK_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.INVALID_STATE:
            raise exceptions.InvalidState('Cannot initialize block in current state')

        if status == response_type.UNKNOWN_BLOCK:
            raise exceptions.UnknownBlock()

        if status != response_type.OK:
            raise exceptions.ReceiveError(
                'Failed with status {}'.format(status))

    def summarize_block(self):
        request = consensus_pb2.ConsensusSummarizeBlockRequest()

        response_type = consensus_pb2.ConsensusSummarizeBlockResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_SUMMARIZE_BLOCK_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.INVALID_STATE:
            raise exceptions.InvalidState('Cannot summarize block in current state')

        if status == response_type.BLOCK_NOT_READY:
            raise exceptions.BlockNotReady('Block not ready to be summarize')

        if status != response_type.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(status))

        return (response.summary,response.block_id)

    def finalize_block(self,block_id, data):
        request = consensus_pb2.ConsensusFinalizeBlockRequest(data=data,block_id=block_id)

        response_type = consensus_pb2.ConsensusFinalizeBlockResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_FINALIZE_BLOCK_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.INVALID_STATE:
            raise exceptions.InvalidState('Cannot finalize block in current state')

        if status == response_type.BLOCK_NOT_READY:
            raise exceptions.BlockNotReady('Block not ready to be finalized')

        if status != response_type.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(status))

        return response.block_id

    def cancel_block(self,branch_id=None):
        request = consensus_pb2.ConsensusCancelBlockRequest(branch_id=branch_id)

        response_type = consensus_pb2.ConsensusCancelBlockResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_CANCEL_BLOCK_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.INVALID_STATE:
            raise exceptions.InvalidState('Cannot cancel block in current state')

        if status != response_type.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(status))

    # -- Block Directives --

    def check_blocks(self, priority):
        request = consensus_pb2.ConsensusCheckBlocksRequest(block_ids=priority)

        response_type = consensus_pb2.ConsensusCheckBlocksResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_CHECK_BLOCKS_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.UNKNOWN_BLOCK:
            raise exceptions.UnknownBlock()

        if status != response_type.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(status))

    def commit_block(self, block_id,seal=None):
        # place for SEAL
        request = consensus_pb2.ConsensusCommitBlockRequest(block_id=block_id,seal=seal.SerializeToString() if seal is not None else seal)

        response_type = consensus_pb2.ConsensusCommitBlockResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_COMMIT_BLOCK_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.UNKNOWN_BLOCK:
            raise exceptions.UnknownBlock()

        if status != response_type.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(status))

    def ignore_block(self, block_id):
        request = consensus_pb2.ConsensusIgnoreBlockRequest(block_id=block_id)

        response_type = consensus_pb2.ConsensusIgnoreBlockResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_IGNORE_BLOCK_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.UNKNOWN_BLOCK:
            raise exceptions.UnknownBlock()

        if status != response_type.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(status))

    def fail_block(self, block_id):
        request = consensus_pb2.ConsensusFailBlockRequest(block_id=block_id)

        response_type = consensus_pb2.ConsensusFailBlockResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_FAIL_BLOCK_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.UNKNOWN_BLOCK:
            raise exceptions.UnknownBlock()

        if status != response_type.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(status))

    # -- Queries --

    def get_blocks(self, block_ids):
        request = consensus_pb2.ConsensusBlocksGetRequest(block_ids=block_ids)

        response_type = consensus_pb2.ConsensusBlocksGetResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_BLOCKS_GET_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.UNKNOWN_BLOCK:
            raise exceptions.UnknownBlock()

        if status != response_type.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(status))

        return {
            block.block_id: Block(block)
            for block in response.blocks
        }

    def get_chain_head(self,parent_id = None,new_parent_id=None,is_new=False):
        request = consensus_pb2.ConsensusChainHeadGetRequest(parent_id=parent_id,new_parent_id=new_parent_id,is_new=is_new)

        response_type = consensus_pb2.ConsensusChainHeadGetResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_CHAIN_HEAD_GET_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.NO_CHAIN_HEAD:
            raise exceptions.NoChainHead()
        if status == response_type.TOO_MANY_BRANCH:
            raise exceptions.TooManyBranch()
        if status == response_type.BLOCK_IS_PROCESSED_NOW:
            raise exceptions.BlockIsProcessedNow()
        if status != response_type.OK:
            raise exceptions.ReceiveError('Failed with status {}'.format(status))

        #LOGGER.debug('get_chain_head: block=%s',response.block)
        return Block(response.block)

    def get_settings(self, block_id, settings):
        request = consensus_pb2.ConsensusSettingsGetRequest(
            block_id=block_id,
            keys=settings)

        response_type = consensus_pb2.ConsensusSettingsGetResponse

        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_SETTINGS_GET_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.UNKNOWN_BLOCK:
            raise exceptions.UnknownBlock()

        if status != response_type.OK:
            raise exceptions.ReceiveError(f'Failed with status {status}')

        return {
            entry.key: entry.value
            for entry in response.entries
        }

    def get_state(self, block_id, addresses):
        request = consensus_pb2.ConsensusStateGetRequest(
            block_id=block_id,
            addresses=addresses)

        response_type = consensus_pb2.ConsensusStateGetResponse
        #LOGGER.debug(f"ZmqService:get_state {block_id}")
        response = self._send(
            request=request,
            message_type=Message.CONSENSUS_STATE_GET_REQUEST,
            response_type=response_type)

        status = response.status

        if status == response_type.UNKNOWN_BLOCK:
            raise exceptions.UnknownBlock()
        if status == response_type.BLOCK_IS_PROCESSED_NOW:   
            raise exceptions.BlockIsProcessedNow()           
        if status != response_type.OK:
            raise exceptions.ReceiveError(f'Failed with status {status}')

        return {
            entry.address: entry.data
            for entry in response.entries
        }
