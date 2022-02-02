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

import hashlib
import logging


from dgt_validator.concurrent.atomic import ConcurrentSet
from dgt_validator.protobuf.block_pb2 import BlockHeader
from dgt_validator.protobuf import consensus_pb2
from dgt_validator.protobuf.consensus_pb2 import ConsensusNotifyPeerConnected
from dgt_validator.protobuf import validator_pb2

LOGGER = logging.getLogger(__name__)


class ConsensusNotifier:
    """
    Handles sending notifications to the consensus engine using the provided
    interconnect service.
    """

    def __init__(self, consensus_service,signed_consensus=False):
        self._service = consensus_service
        self._registered_engines = ConcurrentSet()
        self._cluster = None
        self._signed_consensus = signed_consensus
    """
    def set_cluster(self,cluster):
        self._cluster = cluster
        LOGGER.debug('ConsensusNotifier: set cluster=%s',cluster)
        self._service.set_cluster(self._cluster)
    """
    def _notify(self, message_type, message):
        """
        for cluster topology we should isolate others cluster from our message
        we can set cluster list from topology for self._service
        BUT in this case we are working only with out consensus engine
        """
        #LOGGER.debug('ConsensusNotifier: _notify all peers')
        if self._registered_engines:
            LOGGER.debug('ConsensusNotifier: _notify peer=%s',self._service.connections_info)
            futures = self._service.send_all( # send_all
                message_type,
                message.SerializeToString())
            #LOGGER.debug('ConsensusNotifier: sent _notify to num=%s peers',len(futures))
            for future in futures:
                future.result()
        else:
            LOGGER.debug('ConsensusNotifier: CANT _notify - no registered engine ')

    def notify_peer_param_update(self, peer_id,cname,val=None):
        """
        peer change role or became arbiter
        """
        LOGGER.debug('ConsensusNotifier: notify_peer_param_update peer_id=%s PARAM=%s',peer_id[:10],cname)
        self._notify(
            validator_pb2.Message.CONSENSUS_NOTIFY_PEER_CONNECTED,
            ConsensusNotifyPeerConnected(
                peer_info=consensus_pb2.ConsensusPeerInfo(peer_id=bytes.fromhex(peer_id)),
                status = ConsensusNotifyPeerConnected.PARAM_UPDATE,
                mode = ConsensusNotifyPeerConnected.NORMAL,
                info = cname,
                data = val
                )
            )
    def notify_peer_join_cluster(self, peer_id,cname):
        """
        peer change role or became arbiter
        """
        LOGGER.debug('ConsensusNotifier: notify_peer_join_cluster peer_id=%s PARAM=%s',peer_id[:10],cname)
        self._notify(
            validator_pb2.Message.CONSENSUS_NOTIFY_PEER_CONNECTED,
            ConsensusNotifyPeerConnected(
                peer_info=consensus_pb2.ConsensusPeerInfo(peer_id=bytes.fromhex(peer_id)),
                status = ConsensusNotifyPeerConnected.JOIN_CLUSTER,
                mode = ConsensusNotifyPeerConnected.NORMAL,
                info = cname
                )
            )


    def notify_peer_change_role(self, peer_id,cname,is_arbiter=False):
        """
        peer change role or became arbiter
        """
        LOGGER.debug('ConsensusNotifier: notify_peer_change_role peer_id=%s CLUSTER=%s ARBITER=%s',peer_id[:10],cname,is_arbiter)
        self._notify(
            validator_pb2.Message.CONSENSUS_NOTIFY_PEER_CONNECTED,
            ConsensusNotifyPeerConnected(
                peer_info=consensus_pb2.ConsensusPeerInfo(peer_id=bytes.fromhex(peer_id)),
                status = ConsensusNotifyPeerConnected.ARBITER_CHANGE if is_arbiter else ConsensusNotifyPeerConnected.ROLE_CHANGE,
                mode = ConsensusNotifyPeerConnected.NORMAL,
                info = cname
                )
            )
    def notify_topology_cluster(self,peer_id,list=None):
        """                                                                                                                          
        peer add/del cluster                                                                                           
        """                                                                                                                          
        LOGGER.debug('ConsensusNotifier: notify_topology_cluster peer_id=%s',peer_id[:10])    
        self._notify(                                                                                                                
            validator_pb2.Message.CONSENSUS_NOTIFY_PEER_CONNECTED,                                                                   
            ConsensusNotifyPeerConnected(                                                                                            
                peer_info=consensus_pb2.ConsensusPeerInfo(peer_id=bytes.fromhex(peer_id)),                                           
                status = ConsensusNotifyPeerConnected.DEL_CLUSTER if list is None else ConsensusNotifyPeerConnected.ADD_CLUSTER,    
                mode = ConsensusNotifyPeerConnected.NORMAL,                                                                          
                info = list                                                                                                         
                )                                                                                                                    
            )         
    def notify_topology_peer(self,peer_id,list,oper=ConsensusNotifyPeerConnected.ADD_PEER):
        """                                                                                                                         
        peer add/del                                                                                                        
        """                                                                                                                         
        LOGGER.debug(f'ConsensusNotifier: notify_topology_peer peer_id={peer_id[:10]} oper={oper}')                                          
        self._notify(                                                                                                               
            validator_pb2.Message.CONSENSUS_NOTIFY_PEER_CONNECTED,                                                                  
            ConsensusNotifyPeerConnected(                                                                                           
                peer_info=consensus_pb2.ConsensusPeerInfo(peer_id=bytes.fromhex(peer_id)),                                          
                status = oper,    
                mode = ConsensusNotifyPeerConnected.NORMAL,                                                                         
                info = list                                                                                                         
                )                                                                                                                   
            )                                                                                                                       



    def notify_peer_connected(self, peer_id,assemble = True,mode=ConsensusNotifyPeerConnected.NORMAL):
        """
        A new peer was added
        """
        LOGGER.debug('ConsensusNotifier: notify_peer_connected peer_id=%s assemble=%s',peer_id[:10],assemble)
        self._notify(
            validator_pb2.Message.CONSENSUS_NOTIFY_PEER_CONNECTED,
            ConsensusNotifyPeerConnected(
                peer_info=consensus_pb2.ConsensusPeerInfo(peer_id=bytes.fromhex(peer_id)),
                status = ConsensusNotifyPeerConnected.OK if assemble else ConsensusNotifyPeerConnected.NOT_READY,
                mode = mode,

                )
            )

    def notify_peer_disconnected(self, peer_id):
        """An existing peer was dropped"""
        LOGGER.debug('ConsensusNotifier: notify_peer_disconnected peer_id=%s',peer_id[:10])
        self._notify(
            validator_pb2.Message.CONSENSUS_NOTIFY_PEER_DISCONNECTED,
            consensus_pb2.ConsensusNotifyPeerDisconnected(
                peer_id=bytes.fromhex(peer_id)))

    def notify_peer_message(self, message, sender_id,message_type):
        """
        A new message was received from a peer
        before send check peer key using topology
        """
        LOGGER.debug('ConsensusNotifier: notify_peer_message=%s sender_id=%s',message_type,sender_id.hex()[:8])
        if message_type == 'Arbitration':
            """
            before send Arbitration we should be shure that this validator(sender_id) know about this block
            so we can send this block right now and send arbitration too or we can ask this block into Arbiter after recieving this msg
            """
            LOGGER.debug('ConsensusNotifier: CHECK BLOCK for arbitration before send message consensus engine')
        elif message_type == 'ArbitrationDone':
            LOGGER.debug('ConsensusNotifier:  ArbitrationDone send block to arbiters')
        
        if self._signed_consensus:
            notify_peer_msg = consensus_pb2.ConsensusNotifyPeerMessageNew(message=message,sender_id=sender_id)
        else:
            notify_peer_msg = consensus_pb2.ConsensusNotifyPeerMessage(message=message,sender_id=sender_id)

        self._notify(
                     validator_pb2.Message.CONSENSUS_NOTIFY_PEER_MESSAGE,
                     notify_peer_msg
                    )

    def notify_block_new(self, block):
        """
        A new block was received and passed initial consensus validation
        in federation mode - send only own cluster's nodes
        """
        
        summary = hashlib.sha256()
        for batch in block.batches:
            summary.update(batch.header_signature.encode())
         
        LOGGER.debug('ConsensusNotifier: notify_block_new BLOCK=%s SUMMARY=%s\n',block.header_signature[:8],summary.digest().hex()[:10])
        block_header = BlockHeader()
        block_header.ParseFromString(block.header)
        self._notify(
            validator_pb2.Message.CONSENSUS_NOTIFY_BLOCK_NEW,
            consensus_pb2.ConsensusNotifyBlockNew(
                block=consensus_pb2.ConsensusBlock(
                    block_id=bytes.fromhex(block.header_signature),
                    previous_id=bytes.fromhex(block_header.previous_block_id),
                    signer_id=bytes.fromhex(block_header.signer_public_key),
                    block_num=block_header.block_num,
                    payload=block_header.consensus,
                    summary=summary.digest())))

    def notify_block_valid(self, block_id):
        """This block can be committed successfully"""
        LOGGER.debug('ConsensusNotifier: notify_block_valid BLOCK=%s\n',block_id[:8])
        self._notify(
            validator_pb2.Message.CONSENSUS_NOTIFY_BLOCK_VALID,
            consensus_pb2.ConsensusNotifyBlockValid(
                block_id=bytes.fromhex(block_id)))

    def notify_block_invalid(self, block_id):
        """This block cannot be committed successfully"""
        LOGGER.debug('ConsensusNotifier: notify_block_invalid block=%s\n',block_id[:8])
        self._notify(
            validator_pb2.Message.CONSENSUS_NOTIFY_BLOCK_INVALID,
            consensus_pb2.ConsensusNotifyBlockInvalid(
                block_id=bytes.fromhex(block_id)))

    def notify_block_commit(self, block_id):
        """This block has been committed"""
        LOGGER.debug('ConsensusNotifier: notify_block_commit block=%s\n',block_id[:8])
        self._notify(
            validator_pb2.Message.CONSENSUS_NOTIFY_BLOCK_COMMIT,
            consensus_pb2.ConsensusNotifyBlockCommit(
                block_id=bytes.fromhex(block_id)))

    def was_registered_engine(self, engine_name):
        return self._registered_engines.__contains__(engine_name)

    def add_registered_engine(self, engine_name, engine_version):
        """Add to list of registered consensus engines"""
        
        engine = (engine_name, engine_version)
        if self._registered_engines.__contains__(engine):
            LOGGER.debug('ConsensusNotifier: already registered consensus engine %s',engine_name)
        else:
            LOGGER.debug('ConsensusNotifier: add registered consensus engine')
            self._registered_engines.add(engine)
