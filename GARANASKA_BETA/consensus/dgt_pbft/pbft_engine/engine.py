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

import logging
import queue
import time
import json
from collections import namedtuple

from dgt_sdk.consensus.engine import Engine
from dgt_sdk.consensus import exceptions
from dgt_sdk.protobuf.validator_pb2 import Message
from dgt_sdk.protobuf.consensus_pb2 import ConsensusNotifyPeerConnected
from dgt_sdk.protobuf.pbft_consensus_pb2 import PbftMessage,PbftMessageInfo,PbftBlockMessage,PbftViewChange,PbftSeal
from pbft_engine.oracle import PbftOracle, PbftBlock,_StateViewFactoryProxy
from pbft_engine.pending import PendingForks
#from dgt_validator.protobuf.pbft_consensus_pb2 import PbftMessage,PbftMessageInfo,PbftBlockMessage,PbftViewChange,PbftSeal
#from pbft_common.protobuf.pbft_consensus_pb2 import PbftMessage,PbftMessageInfo,PbftBlockMessage,PbftViewChange,PbftSeal
#from dgt_validator.protobuf.consensus_pb2 import ConsensusNotifyPeerConnected
from pbft.journal.block_wrapper import NULL_BLOCK_IDENTIFIER
from pbft_common.utils import _short_id,_SID_
from enum import IntEnum,Enum

from dgt_sdk.messaging.future import FutureTimeoutError
from dgt_validator.gossip.fbft_topology import TOPOLOGY_GENESIS_HEX,PeerAtr

LOGGER = logging.getLogger(__name__)
# status , number of transaction where peer participates,count - how many times peer's was leader 
PeerInfo = namedtuple('PeerInfo',['status', 'num','count'])


_CONSENSUS_ = b'pbft'
PBFT_NAME = 'pbft' 
PBFT_VER  = '0.1'
TIMEOUT   = 0.02
PBFT_FULL = False  # full or short mode of PBFT

CHAIN_LEN_FOR_BRANCH = 3 # after this len make a new branch 
CHAIN_LEN_FOR_NESTING = 1
CONSENSUS_MSG = ['PrePrepare','Prepare','Commit','CheckPoint','ViewChange','Arbitration','ArbitrationDone']

class Consensus(Enum):
    done = 0
    fail = 1
    pending = 2

class State(IntEnum):
    NotStarted   = 0
    PrePreparing = 1
    Preparing    = 2
    Checking     = 3
    PreCommiting = 4
    Commiting    = 5
    Arbitration  = 6
    Finished     = 7

    


class BranchState(object):

    def __init__(self,bid,parent,block_num,service,oracle,engine,ind):
        self._head_id = bid
        self._ind = ind
        self._parent_id = parent
        self._block_num = block_num
        self._service = service
        self._oracle  = oracle
        self._committing = False
        self._building   = False
        self._published = True
        self._can_fail_block = False
        # for testing branch
        self._try_branch = True
        self._make_branch = False
        self._freeze_block = None
        self._num_block = 0
        self._chain_len = 0   # for chain lenght
        self._freeze = False # True for freeze block 3
        self._sequence_number = 0
        self._state = State.NotStarted
        self._start = None # time starting
        self._commit_msgs = {}
        self._engine = engine
        self._num_arbiters = 0
        self._arbiters_reply = {}
        self._nest_color = None
        self._stime = None
        self._can_cancel = True # possible to cancel
        self._already_send_commit = False
        self._is_arbiter = None
        self._own_type = None
        LOGGER.debug('BranchState: init BRANCH=%s for %s STATE=%s',self,_SID_(bid),self._state)

    @property
    def ind(self):
        return self._ind

    @property
    def nest_color(self):
        return self._nest_color
    @nest_color.setter
    def nest_color(self, color):
        LOGGER.debug('BranchState[{}]: init color={}'.format(self.ind,color))
        self._nest_color = color
    @property
    def own_type(self):
        # set for new block 
        if self._own_type is None:
            self._own_type = self._engine.own_type
        return self._own_type
    @property
    def is_sync(self):
        return  self._engine.is_sync
    @property
    def is_leader(self):
        return self.own_type == 'leader'
    @property
    def is_arbiter(self):
        if self._is_arbiter is None:
            self._is_arbiter = self._engine.is_arbiter
        return self._is_arbiter 

    @property
    def validator_id(self):
        return self._engine.validator_id

    @property
    def already_send_commit(self):
        return self._already_send_commit 

    @property
    def peers(self):
        return self._engine.peers

    @property
    def dag_step(self):
        return self._engine.dag_step

    @property
    def is_ready_arbiter(self):
        return self._engine.is_ready_arbiter

    @property
    def arbiters(self):
        return self._engine.arbiters
    @property
    def num_arbiters(self):
        return self._engine.num_arbiters
    @property
    def num_peers(self):
        return self._engine.num_peers

    @property
    def parent(self):
        return self._parent_id

    @property
    def block_num(self):
        return self._block_num

    @property
    def is_time_to_make_branch(self):
        return self._chain_len > self.dag_step # and self._make_branch

    @property
    def state(self):
        return self._state

    @property
    def can_cancel(self):
        return self._can_cancel and self._state >= State.PrePreparing #State.Commiting

    @property
    def stime(self):
        return self._stime

    @property
    def signer_id(self):
        return bytes.fromhex(self.validator_id)

    def pkey2nm(self,key):
        return self._engine.pkey2nm(key)

    def reset_chain_len(self):
        self._chain_len = 0
        LOGGER.debug("RESET_CHAIN_LEN branch[%s] step=%s",self._ind,self.dag_step) 
    def un_freeze_block(self):
        # for testing only
        block_id,parent_id = None,None
        if self._freeze_block is not None:
            LOGGER.warning("un_freeze_block: un freeze block for BRANCH=%s\n",_SID_(self._head_id))
            self.check_block(self._freeze_block.block_id) # commit freeze block
            #self.fail_block(self._freeze_block.block_id)  # fail block 
            block_id = self._freeze_block.block_id.hex()
            parent_id = self._freeze_block.previous_block_id
            self._freeze_block = None
        return block_id,parent_id

    def make_own_vote(self,block):
        commit = self._make_message(block,PbftMessageInfo.COMMIT_MSG)  
        vote = self._service.make_consensus_peer_message(CONSENSUS_MSG[PbftMessageInfo.COMMIT_MSG], commit.SerializeToString())
        return vote



    def send_genesis_seal(self):
        LOGGER.debug(f'SEND GENESIS SEAL FOR FIRST BLOCK={self.block_num} signer={self.signer_id}\n')
        block = PbftBlockMessage(                    
                    block_id  = bytes.fromhex(self._head_id),  
                    signer_id = self.signer_id, 
                    block_num = self.block_num, 
                    summary   = b''   
                )  
                                 
        seal = self._make_pbft_seal(block)
        LOGGER.debug(f'SEND GENESIS SEAL={seal} FOR FIRST BLOCK\n')                                         
        self._service.commit_block(bytes.fromhex(self._head_id),seal=seal)

    def _broadcast(self,payload,msg_type,block_id):
        """
        broadcast message  - it means we send message only nodes which belonge our cluster
        """ 
        block_id = block_id.hex()
        #state.shift_sequence_number(block_id,self._consensus_state_store)
        mgs_type = CONSENSUS_MSG[msg_type]
        LOGGER.debug("BROADCAST =>> '%s' for block_id=%s",mgs_type,_SID_(block_id))
        self._service.broadcast_to_cluster(mgs_type,payload.SerializeToString())
        #self._service.broadcast(mgs_type,payload.SerializeToString())

    def _broadcast2arbiter(self,payload,msg_type,block_id):
        """
        broadcast message to arbiter  - it means we send message only nodes which belonge arbiter's ring
        """ 
        block_id = block_id.hex()
        #state.shift_sequence_number(block_id,self._consensus_state_store)
        mgs_type = CONSENSUS_MSG[msg_type]
        LOGGER.debug("BROADCAST2ARBITER =>> '%s' for block_id=%s",mgs_type,_SID_(block_id))
        self._service.broadcast_to_arbiter(mgs_type,payload.SerializeToString())
        #self._service.broadcast(mgs_type,payload.SerializeToString())

    def _broadcast2cluster(self,payload,msg_type,block_id):
        """
        broadcast message to cluster  - it means we send message only nodes which belonge arbiter's ring
        """ 
        block_id = block_id.hex()
        #state.shift_sequence_number(block_id,self._consensus_state_store)
        mgs_type = CONSENSUS_MSG[msg_type]
        LOGGER.debug("BROADCAST2CLUSTER =>> '%s' for block_id=%s",mgs_type,_SID_(block_id))
        self._service.broadcast_to_cluster(mgs_type,payload.SerializeToString())
        #self._service.broadcast(mgs_type,payload.SerializeToString())

    def _send_to(self,peer_id,payload,msg_type,block_id):
        """
        send message to peer_is  
        """ 
        block_id = block_id.hex()
        mgs_type = CONSENSUS_MSG[msg_type]
        LOGGER.debug("SEND TO=%s =>> '%s' for block_id=%s",_SID_(peer_id),mgs_type,_SID_(block_id))
        self._service.send_to(bytes.fromhex(peer_id),mgs_type,payload.SerializeToString())

    def _make_message(self,block,msg_type,seal=None):
        # PBFT MESSAGE
        signer_id = self.validator_id if self._engine.is_malicious != ConsensusNotifyPeerConnected.MALICIOUS else ('f'+self.validator_id[1:])
        messageInfo = PbftMessageInfo(
                    msg_type = msg_type,
                    view     = 0,
                    seq_num  = self._sequence_number,
                    signer_id = bytes.fromhex(signer_id)
            ) 
        if msg_type == PbftMessageInfo.ARBITRATION_DONE_MSG:
            # seal from leader or leader's hand made seal
            content = seal if seal is not None else self._make_pbft_seal(block)
        else:
            content = PbftBlockMessage(
                        block_id  = block.block_id,
                        signer_id =  block.signer_id,
                        block_num = block.block_num,
                        summary   = block.summary 
                )
        
        return PbftMessage(info=messageInfo,content=content.SerializeToString())

    def _make_pbft_seal(self,block,commit_msgs={}):
        content = PbftBlockMessage(                    
                    block_id  = block.block_id,        
                    signer_id =  block.signer_id,      
                    block_num = block.block_num,       
                    summary   = block.summary          
            )   
        votes = [commit[1] for commit in commit_msgs.values()]  
        vote =  self.make_own_vote(content)
        votes.append(vote)
        LOGGER.debug("MAKE SEAL WITH {} VOTES FOR BLOCK NUM={}".format(len(votes),block.block_num))                                     
        seal = PbftSeal(
                block = content,
                commit_votes = votes
               )


        return seal

    def _send_pre_prepare(self,block):
        """
        send PRE_PREPARE message 
        """
        message = self._make_message(block,PbftMessageInfo.PRE_PREPARE_MSG)                                                                                                                 
        self._broadcast(message,PbftMessageInfo.PRE_PREPARE_MSG,block.block_id)
        
    def _send_prepare(self,block):
        """
        send PREPARE message 
        """
        # check state PrePreparing and shift into Preparing
        message = self._make_message(block,PbftMessageInfo.PREPARE_MSG)                                                                                                                 
        self._broadcast(message,PbftMessageInfo.PREPARE_MSG,block.block_id)

    def _send_commit(self,block,pstatus=ConsensusNotifyPeerConnected.OK,peer_id=None):
        """
        send COMMIT message - to own cluster or for peer's synchronization send only this peer
        TODO - make SEAL here
        """                                                                                                  
        message = self._make_message(block,PbftMessageInfo.COMMIT_MSG)  
        if pstatus == ConsensusNotifyPeerConnected.OK:
            self._broadcast(message, PbftMessageInfo.COMMIT_MSG, block.block_id)
        elif pstatus == ConsensusNotifyPeerConnected.NOT_READY:
            # synchronization mode - send directly this peer
            self._send_to(peer_id,message,PbftMessageInfo.COMMIT_MSG,block.block_id)
            self._send_arbitration_done(block,peer_id,seal=None) # 

    def _wait_arbitration_done(self,block_id):
        """
        wait ARBITRATION_DONE message :
         LEADER wait from cluster which asked arbitration and who is owner of block
         PLINK wait from leader
         ARBITER wait from leader which asked arbitration and who is owner of block
        """
        LOGGER.debug("WAIT ARBITRATION LEADER=%s ARBITER=%s total reply=%s.",self.is_leader,self.is_arbiter,len(self._arbiters_reply))
        self._state = State.Arbitration
        self._num_arbiters = 1
        if self.is_leader or self.is_arbiter:
            self.check_arbitration(block_id,broadcast=False)
        else:
            LOGGER.debug("WAIT ARBITRATION NOT LEADER OR ARBITER")
            for pid,block in self._arbiters_reply.items():
                self.arbitration_done(block,pid)




    def _send_arbitration(self,block):
        """
        send ARBITRATION message to all ring of cluster delegate
        
        """   
        self._num_arbiters = 0
        if self.is_leader :
            # send as leader
            # and wait messages from all rest arbiters which is active
            self._num_arbiters = self.num_arbiters
            LOGGER.debug("AS LEADER SEND ARBITRATION num_arbiters=%s",self._num_arbiters)
            message = self._make_message(block,PbftMessageInfo.ARBITRATION_MSG) 
            self._broadcast2arbiter(message,PbftMessageInfo.ARBITRATION_MSG,block.block_id)
            # AND WE WILL WAIT ARBITRATION_DONE or MAY BE COMMIT ? from other cluster - which is PEER VOTE
        else:
            # wait only one message ARBITRATION_DONE from own leader or from arbiter- which should be SEAL
            LOGGER.debug("Wait arbitration done from own leader")
            self._num_arbiters = 1
                    

    def _send_arbitration_done(self,block,peer_id,seal=None):
        """
        send ARBITRATION_DONE message to all ring of cluster delegate
        """                                                                                                  
        message = self._make_message(block,PbftMessageInfo.ARBITRATION_DONE_MSG,seal) 
        LOGGER.debug("SEND ARBITRATION_DONE_MSG to=%s  block=%s\n",_SID_(peer_id),_SID_(block.block_id.hex()))
        self._send_to(peer_id,message,PbftMessageInfo.ARBITRATION_DONE_MSG,block.block_id) 

    def _send_arbitration_repl(self,block,peer_id):                                                            
        """                                                                                                    
        send ARBITRATION_REPL message to leader block's owner                                          
        """                                                                                                    
        message = self._make_message(block,PbftMessageInfo.COMMIT_MSG)                               
        LOGGER.debug("SEND ARBITRATION_REPL_MSG to=%s  block=%s\n",_SID_(peer_id),_SID_(block.block_id.hex()))       
        self._send_to(peer_id,message,PbftMessageInfo.COMMIT_MSG,block.block_id)                     



    def broadcast_arbitration_done(self,block,seal=None):
        
        # FOR OWN CLUSTER
        # inform own cluster about arbitration done
        # and send SEAL -  TODO

        message = self._make_message(block,PbftMessageInfo.ARBITRATION_DONE_MSG,seal)
        self._broadcast2cluster(message, PbftMessageInfo.ARBITRATION_DONE_MSG, block.block_id)
        if self._own_cluster_blk:
            # I AM LEADER - INFORM RING OF ARBITERS IN CASE FINISHING ARBITRATION OF OWN BLOCK 
            # AT THIS POINT WE CAN MAKE SEAL OF COMMITING - and include in it own cluster VOTE and ARBITER's VOTE
            self._broadcast2arbiter(message,PbftMessageInfo.ARBITRATION_DONE_MSG,block.block_id)
                    
    def _send_checkpoint(self,block):
        """
        check point message, for log message rotation
        """ 
        message = self._make_message(block,PbftMessageInfo.CHECKPOINT_MSG)
        self._broadcast(message,PbftMessageInfo.CHECKPOINT_MSG,block.block_id) 

    def _send_viewchange(self,block):
        """
        View change message, for when a node suspects the leader node is faulty
        """ 
        message = self._make_message(block,PbftMessageInfo.VIEWCHANGE_MSG)

        self._broadcast(message,PbftMessageInfo.VIEWCHANGE_MSG,block.block_id) 

    def pre_prepare(self,block,force = False,first=False):
        """
        PrePrepare message - can appeared after prepare
        """
        if (self._state == State.PrePreparing or force) and self._state != State.Preparing:
            self._state = State.Preparing
            self._send_prepare(block)
        elif first : 
            # appeared after prepare - just send 
            self._send_prepare(block)
        else:
            summary  = block.summary.hex()
            LOGGER.debug("DON'T SEND PREPARE summary=%s fail %s\n",_SID_(summary),self._state)
        

    def check_consensus(self,block):
        
        if self._can_fail_block and block.block_num == 2:
            self._can_fail_block = False
            LOGGER.debug("check_consensus: MAKE BLOCK fail FOR TEST\n")
            return False
        return True

    def start_consensus(self,block):
        """
        New block message appeared - start consensus
        """
        self._start = time.time() # save time when new block appeared - we can update this time which was setted into finalize
        self._state = State.PrePreparing # State.NotStarted
        LOGGER.debug('Start F-BFT consensus block=%s time=%s',_SID_(block.block_id.hex()),self._start)
        self._send_pre_prepare(block)

    def finish_consensus(self,block,block_id,consensus):
        if self._state in [State.PrePreparing,State.Preparing,State.PreCommiting]:
            # shift to the checking state
            # check maybe we should send pre prepare or prerare message - because of bad order of message
            LOGGER.debug("finish_consensus:branch[%s] for block_id=%s consensus=%s %s->Checking\n",self._ind,_SID_(block_id),consensus,self._state)
            self._state = State.Checking
            if consensus:
                # check block and waiting valid or invalid message
                self.check_block(bytes.fromhex(block_id))
            else:
                #self.reset_state()
                self.fail_block(bytes.fromhex(block_id))
        else:
            LOGGER.debug("finish_consensus: IGNORE block_id=%s state=%s\n",_SID_(block_id),self._state)

    def check_block(self,block_id):
        # send in case of consensus was reached
        LOGGER.debug("check_block: block_id=%s\n",_SID_(block_id.hex()))
        try:
            self._service.check_blocks([block_id])
        except (exceptions.UnknownBlock,exceptions.ReceiveError):
            LOGGER.debug("check_block: ignore_block block_id=%s\n",_SID_(block_id.hex()))
            self.ignore_block(block_id)
            

    def fail_block(self, block_id):
        # send in case of consensus was not reached
        self._service.fail_block(block_id)

    def new_block(self,block,cluster=True,commits=None):
        self._own_cluster_blk = cluster # block belonge own cluster
        self._stime = time.time()
        # save own role - because it could be changed before commit this block
        self._own_type = self._engine.own_type
        self._is_arbiter = self._engine.is_arbiter
        if commits:
            # add commit messages
            for peer_id,block in commits.items():
                self.add_commit_msg(peer_id,block)

        num_peers = self.num_peers
        if cluster and num_peers > 0 and self.is_sync:
            """
            start consensus for many active peers and in case it is block of own cluster
            """
            self.start_consensus(block)
            return False

        if self.check_consensus(block):
            # at this point state PREPARED
            LOGGER.info('Passed consensus check in state PREPARED: %s cluster=%s is sync=%s peers=%s', _SID_(block.block_id.hex()),cluster,self.is_sync,num_peers)
            if block.block_num == 3 and self._try_branch:
                # try make branch pause current block for main branch
                self._make_branch = True
                self._try_branch = False
                if self._freeze:
                    self._freeze_block = block
                else:
                    self.check_block(block.block_id)
            else:
                # sync mode - check is prev block updated chain head  
                self.check_block(block.block_id) # this message send chain controller message for continue block validation
                # waiting block valid message
            return True
        else:
            block_id = block.block_id.hex()
            LOGGER.info('Failed consensus blk=%s branch=%s', _SID_(block_id),_SID_(self._head_id))
            self.reset_state(block_id)
            self.fail_block(block.block_id)
            return False
    
    def cancel_block(self,head_id):
        try:
            
            self._service.cancel_block(bytes.fromhex(self._head_id))
            # set new branch HEAD 
            self._head_id = head_id 
            self._num_block += 1 
            self._chain_len += 1
            LOGGER.warning("cancel_block: for branch[%s]=%s NUM HANDLED BLOCKS=%s chain len=%s\n",self._ind,_SID_(self._head_id),self._num_block,self._chain_len)
            if self._num_block == 1 and self._engine.is_dynamic_mode:
                self._oracle.update_state_view_block(bytes.fromhex(self._head_id))

        except exceptions.InvalidState:
            LOGGER.warning("cancel_block:  InvalidState\n")
            pass
    
    def commit_block(self, block_id,seal = None):
        """
        say validator that we can do commit AND SEND SEAL
        """
        LOGGER.warning("commit_block: block_id={}.{} seal={}\n".format(self.block_num,_SID_(block_id.hex()),seal))
        self._already_send_commit =True
        self._service.commit_block(block_id,seal=seal)

    def ignore_block(self, block_id):
        # send in case fork was not resolved
        self._service.ignore_block(block_id)

    def finalize_block(self,parent_id,summary):
        consensus = _CONSENSUS_ #self._oracle.finalize_block(summary)
        if consensus is None:
            return None

        try:
            # say to validator that we are ready to finalize this block and send name of consensus
            block_id = self._service.finalize_block(parent_id,consensus)
            self._start = time.time()
            LOGGER.info('Finalized summary=%s block_id=%s BRANCH=%s start=%s',summary,_SID_(block_id.hex()),_SID_(self._head_id),self._start) 
            self._building = True # ONLY for testing new version - normal True
            self._published = True # ONLY for testing new version- normal True
            # broadcast 
            #LOGGER.debug('broadcast ...')
            #self._service.broadcast('message_type',b'payload')
            return block_id
        except exceptions.BlockNotReady:
            LOGGER.debug('Block not ready to be finalized')
            return None
        except exceptions.InvalidState:
            LOGGER.warning('block cannot be finalized')
            return None

    def switch_forks(self, current_head, new_head):
        try:
            switch = self._oracle.switch_forks(current_head, new_head)
        # The BGT fork resolver raises TypeErrors in certain cases,
        # e.g. when it encounters non-BGT blocks.
        except TypeError as err:
            switch = False
            LOGGER.warning('BGT fork resolution error: %s', err)

        return switch

    def shift_to_commiting(self,block,pstatus=ConsensusNotifyPeerConnected.OK,peer_id=None):
        if self._state != State.PreCommiting:
            LOGGER.info('Send commit block=%s %s->PreCommiting',_SID_(block.block_id.hex()),self._state)
            self._state = State.PreCommiting 
            self._send_commit(block,pstatus,peer_id)
            

    def resolve_fork(self,chain_head,block):
        block_id = block.block_id.hex()
        LOGGER.info('Branch[%s] Choosing between chain heads current:%s new:%s SYNC=%s CLUST=%s',_SID_(self._head_id),_SID_(chain_head.block_id.hex()),_SID_(block_id),self.is_sync,self._own_cluster_blk)
        if self.switch_forks(chain_head, block):
            """
            for full version shift into commiting state
            for short we can commit right now
            """
            if self._oracle.is_pbft_full and (self._own_cluster_blk or block.block_num == 0) and self.is_sync:
                # broadcast commit message and shift into commiting state - NOT for block under arbitration
                # could be plink or leader
                self.shift_to_commiting(block)
                self._state = State.Commiting
                self.check_commit(block)
                return Consensus.pending
            else:
                block_id = block.block_id.hex()
                if self._oracle.is_pbft_full and self.is_sync:
                    # block from other clusters - do only arbitration
                    # wait arbitration done from owner of block(other cluster which ask arbitration) or from own leader
                    self._wait_arbitration_done(block_id)
                    
                else:
                    # TODO take as seal consensus from chain_head
                    LOGGER.info('Committing block=%s for BRANCH=%s', _SID_(block_id),_SID_(self._head_id))

                    self.commit_block(block.block_id)
                    self._committing = True
                    return Consensus.done
        else:
            LOGGER.info('Ignoring block=%s for BRANCH=%s', _SID_(block_id),_SID_(self._head_id))
            self.reset_state(block_id)
            try:    
                self.ignore_block(block.block_id)
            except exceptions.UnknownBlock:
                # block could be already rejected - it's not a problem in this case
                LOGGER.info('UnknownBlock block=%s already was DELLED', _SID_(block_id))    
            return Consensus.fail

    def ignore_by_timeout(self,block_id):
        LOGGER.info('Fail block=%s by timeout for BRANCH=%s', _SID_(block_id),_SID_(self._head_id))
        try:    
            if self._state >= State.Commiting:
                self.ignore_block(bytes.fromhex(block_id))
            else:
                self.fail_block(bytes.fromhex(block_id))
            self._can_cancel = False
        except exceptions.UnknownBlock:
            # block could be already rejected - it's not a problem in this case
            LOGGER.info('UnknownBlock block=%s already was DELETED', _SID_(block_id))    
        
    def check_commit(self,block):
        """
        check maybe it's time for commit
        """
        LOGGER.info('Check commit for block=%s state=%s _can_cancel=%s', self.block_num,self._state,self._can_cancel)
        if self._state == State.Commiting and self._can_cancel:
            # block was not interrupted
            # _commit_msgs should contain SEAL
            total = len(self._commit_msgs)
            N =  self.num_peers + 1
            F = round((N - 1)/3.)*2 + (0 if N%3. == 0 else 1) 
            #if N == 3:
            #    F = 2
            LOGGER.info('Check commit for block=%s state=%s total=%s N=%s F=%s LEADER=%s peers=%s', self.block_num,self._state,total,N,F,self.is_leader,[(_SID_(pid),self.pkey2nm(pid)) for pid in self._commit_msgs.keys()])
            if total >= F or N == 1:
                if not self.is_ready_arbiter:
                    # ignore not ready arbiters - make commit without arbitration
                    LOGGER.info('Ready to do commit for block=%s -> Finished(ARBITER UNDEF or DISCONNECTER)', self.block_num)
                    if self.is_leader:
                        # plink waiting ARBITRATION DONE in this case
                        # SEND SEAL HERE - only vote from own cluster peers
                        LOGGER.info('arbitration: broadcast ARBITRATION DONE for own cluster block=%s ???', self.block_num)
                        seal = self._make_pbft_seal(block,self._commit_msgs)
                        self.broadcast_arbitration_done(block,seal) # + SEAL
                        self._engine.keep_seal_info(self._commit_msgs)
                    else:
                        seal = None
                    self._state = State.Finished
                    self.commit_block(block.block_id,seal)
                else:
                    # As leader ask arbiter's ring
                    # as plink waiting arbitration done from leader
                    LOGGER.info('Ready to do commit for block=%s ask ARBITER=%s -> Arbitration', self.block_num,[_SID_(key) for key,val in self.arbiters.items() if val[1] == ConsensusNotifyPeerConnected.OK])
                    self._state = State.Arbitration
                    self._send_arbitration(block)

            return True

        return False



    def add_commit_msg(self,peer_id,block):
        """
        commit message from peers who is participating in consensus
        commit MSG can appeared before valid block MSG
        """
        if peer_id not in self._commit_msgs and peer_id in self.peers:
            self._commit_msgs[peer_id] = block
            LOGGER.info('Add commit MSG from peer=%s for block=%s total=%s', _SID_(peer_id),self.block_num,len(self._commit_msgs))
            if not self.check_commit(block[0]):
                LOGGER.info('Save commit MSG for block=%s and waiting VALID MSG', self.block_num)
        else:
            LOGGER.info('Ignore commit MSG from peer=%s msgs=%s peers=%s', _SID_(peer_id),[_SID_(peer) for peer in self._commit_msgs.keys()],[_SID_(peer) for peer in self.peers])

    def arbitration(self,block,peer_id,broadcast=True):
        """
        leader ask arbitration
        
        """
        #self._send_arbitration_done(block,peer_id) # to other cluster's leader who is initiator of arbitration
        self._send_arbitration_repl(block,peer_id)
        #if (self.is_leader or self.is_arbiter) and broadcast:
        #    LOGGER.info('SKIP broadcast ARBITRATION DONE for own cluster block=%s LEADER=%s ARBITER=%s\n', self.block_num, self.is_leader, self.is_arbiter)
            #self.broadcast_arbitration_done(block)

    def arbitration_repl(self,block,vote,peer_id):
        """
        I am leader and this arbitration repl
        """
        if self._state != State.Arbitration:                                                                                                                       
            LOGGER.info('arbitration_repl: for block=%s (%s) reply too early', self.block_num,self._state)                                                         
            if peer_id not in self._arbiters_reply:                                                                                                                
                self._arbiters_reply[peer_id] = block                                                                                                              
            return                                                                                                                                                 
        if peer_id not in self._arbiters_reply:
            self._num_arbiters -= 1 
            self._arbiters_reply[peer_id] = block
            # add vote of arbiter
            self._commit_msgs[peer_id] = (block,vote)
        else:
            LOGGER.info('IGNORE DUP arbitration_repl: for block=%s (%s) arbiters reply state=%s', self.block_num,self._num_arbiters,self._state)    
            return

        if self._num_arbiters == 0:                                                                                                                                
            """                                                                                                                                                    
             for own block we have answer from all arbiter and can make commit for this block                                                                      
             in case of external cluster block - we have message from cluster which is owner of block and arbiter inform other cluster                             
            """   
            seal = None                                                                                                                                                 
            if (self._own_cluster_blk and self.is_leader) :                                                     
                # AS Leader send ARB DONE for peers of cluster  
                # MAKE SEAL with vote of own cluster and send it                                                                                                    
                LOGGER.info('arbitration_repl: broadcast ARBITRATION DONE for own cluster and arbiters VOTE=%d block=%s',len(self._commit_msgs), self.block_num)  
                seal = self._make_pbft_seal(block,self._commit_msgs)                                             
                self.broadcast_arbitration_done(block,seal)  # + SEAL [commit + arbitration] 
                self._engine.keep_seal_info(self._commit_msgs)
                                                                                                                                                                   
            LOGGER.info('arbitration_done: for block=%s state=%s ', self.block_num,self._state)                                                                     
            self.commit_block(block.block_id,seal)                                                                                                                      
        



    def arbitration_done(self,block,peer_id,seal=None):
        """
        this is arbitration done from leader
        """
        if self._state != State.Arbitration:
            LOGGER.info('arbitration_done: for block=%s (%s) reply too early', self.block_num,self._state)
            if peer_id not in self._arbiters_reply:
                self._arbiters_reply[peer_id] = block
            return

        self._num_arbiters -= 1
        if self._num_arbiters == 0:
            """
             for own block we have answer from all arbiter and can make commit for this block 
             in case of external cluster block - we have message from cluster which is owner of block and arbiter inform other cluster
            """
            if (self.is_arbiter and not self._own_cluster_blk) :
                # AS ARBITER send ARB DONE for peers of cluster 
                LOGGER.info(f'arbitration_done: As ARBITER broadcast ARBITRATION DONE for own cluster block={self.block_num} seal={seal}')
                self.broadcast_arbitration_done(block,seal) # + SEAL 

            LOGGER.info('arbitration_done: for block=%s state=%s', self.block_num,self._state)
            self.commit_block(block.block_id,seal)
        else:
            # already was commited - this is dup message
            LOGGER.info('arbitration_done: for block=%s (%s) arbiters reply state=%s - dup message', self.block_num,self._num_arbiters,self._state)

    def check_arbitration(self,block_id,broadcast=True):
        # 
        if block_id in self._engine._arbitration_msgs:                     
            # reply on arbitration msg from other cluster's leader                            
            (block,peer_id) = self._engine._arbitration_msgs[block_id]     
            self.arbitration(block,peer_id,broadcast)                      
            del self._engine._arbitration_msgs[block_id]  
        else:
            # save as a marker - which means that arbitration was asked
            LOGGER.debug("check_arbitration: NO ARBITRATION MSG for block=%s is_sync=%s",_SID_(block_id),self.is_sync)
            if self.is_sync:
                self._engine._arbitration_msgs[block_id] = broadcast 


    def reset_state(self,block_id):
        ctime = time.time()
        LOGGER.info('reset_state: for blk=%s BRANCH[%s]=%s time=%s of processing=%s\n',_SID_(block_id), self._ind, _SID_(self._head_id),self.stime, ctime - (self.stime if self.stime else ctime))
        self._building = False   
        self._published = False  
        self._committing = False
        self._state = State.NotStarted
        self._sequence_number = 0
        self._commit_msgs = {}
        self._can_cancel = True
        self._already_send_commit = False
        self._arbiters_reply = {}
        if block_id in self._engine._arbitration_msgs:
            del self._engine._arbitration_msgs[block_id]

        LOGGER.info('reset_state:_arbitration_msgs=%s',self._engine._arbitration_msgs)
    def __str__(self):
        return "{} (block_num:{}, {})".format(
            _SID_(self.parent),
            self.block_num,
            self.state,
            
        )
     
        
class PbftEngine(Engine):
    def __init__(self, path_config, component_endpoint,pbft_config=None,signed_consensus=False):
        # components
        self._branches = {} # for DAG 
        self._new_heads = {}
        self._peers = {}
        self._arbiters = {}
        self._leaders = {} # other cluster leader's - only for arbiter
        self._peers_branches = {} # dict with BranchState() indexed by block id
        self._pre_prepare_msgs = {} # for aggregating blocks by summary 
        self._prepare_msgs = {}
        self._commit_msgs = {}
        self._arbitration_msgs = {} 
        self._pending_nest = {}   # for waiting nest
        self._pending_branch = {} # for waiting branch
        self._nest_color = []     # add color for nests
        self._path_config = path_config
        self._component_endpoint = component_endpoint
        self._service = None
        self._oracle = None
        self._skip   = False
        self._chain_head = None # GENESIS - keep for making federation palette 
        # state variables
        self._exit = False
        self._published = False # maker of federation's palette ready
        self._palette = False
        self._building = False
        self._committing = False
        self._can_fail_block = False #True #False # True for testing
        self._make_branch = True
        self._TOTAL_BLOCK = 0
        self._pending_forks_to_resolve = PendingForks()
        self._num_branches = 0 #
        self._validator_id = None
        self._dag_step = CHAIN_LEN_FOR_BRANCH
        self._is_sync = True
        self._mode = ConsensusNotifyPeerConnected.NORMAL 
        self._genesis_mode = True
        self._join_cluster = None
        self._signed_consensus = signed_consensus
        self._is_heartbeat = False
        self._last_seal_peers = []
        LOGGER.debug(f'PbftEngine: init done SIGNED={signed_consensus}')

    def name(self):
        LOGGER.debug('PbftEngine: ask name=%s',PBFT_NAME)
        return PBFT_NAME

    @property
    def signed_consensus(self):
        return self._signed_consensus

    def version(self):
        LOGGER.debug('PbftEngine: ask version=%s ',PBFT_VER)
        return PBFT_VER

    def stop(self):
        self._exit = True

    @property
    def validator_id(self):
        return self._validator_id

    @property
    def peers(self):
        return self._peers

    @property
    def dag_step(self):
        return self._dag_step if self._palette else CHAIN_LEN_FOR_NESTING

    @property
    def is_ready_arbiter(self):
        if not self.is_leader:
            # for plink - own leader is arbiter
            # think that leader is active and if not all transactions will be canceled by timeout
            return True
        if len(self.arbiters) == 0:
            # for plink - own leader is arbiter
            return False
        #LOGGER.debug(f'PbftEngine: is_ready_arbiter={len(self.arbiters)}')
        return max(self.arbiters.values(), key = lambda x: 1 if x[1] == ConsensusNotifyPeerConnected.OK else 0)[1] == ConsensusNotifyPeerConnected.OK

    @property
    def own_type(self):
        return self._oracle.own_type #self._own_type
    @property
    def is_leader(self):
        return self.own_type == 'leader'
    @property
    def is_arbiter(self):
        return self._oracle.is_arbiter 

    @property
    def is_sync(self):
        return self._is_sync

    @property
    def is_malicious(self):
        return self._mode

    @property
    def arbiters(self):
        return self._arbiters

    @property
    def num_arbiters(self):
        num = 0
        for val in self.arbiters.values():
            if val[1] == ConsensusNotifyPeerConnected.OK:
                num += 1
        return num
    @property
    def num_peers(self):
        """
        return number of active peers exclude me
        """
        num = 0
        for val in self._peers.values():
            if val.status == ConsensusNotifyPeerConnected.OK:
                num += 1
        return num

    @property
    def arbiters_info(self):
        # only arbiters which are ready
        return [val[2]+'('+str(val[1])+'='+_SID_(aid)+')' for aid,val in self.arbiters.items() if val[1] == ConsensusNotifyPeerConnected.OK]

    @property                                                                                                                              
    def peers_info(self):                                                                                                               
        # only peers which are ready                                                                                                    
        return [_SID_(pid)+'('+str(val.count)+')' for pid,val in self._peers.items() if val.status == ConsensusNotifyPeerConnected.OK]  

    @property
    def nest_color(self):
        if len(self._nest_color) == 0:
            # make list color for nests
            colors = []
            if self._cluster_name != self._genesis and not self._is_dynamic_cluster :#and self._cluster_name[:3] != 'dyn':
                # exclude dynamic cluster for which we have no nests
                colors.append(self._cluster_name)
            for cluster in self.arbiters.values():
                if cluster[2] != self._genesis:
                    colors.append(cluster[2])
            self._nest_color = sorted(colors)
            self._nest_color.append(self._genesis)
            LOGGER.debug('NEW NEST COLORS=%s DYN=%s',self._nest_color,self._is_dynamic_cluster)
        color = self._nest_color.pop()
        LOGGER.debug('FIRST NEST COLOR=%s',color) 
        return color

    @property
    def genesis_id(self):
        return self._chain_head.block_id if self._chain_head else None

    @property
    def block_timeout(self):
        return self._oracle.block_timeout

    @property
    def is_dynamic_mode(self):
        return self._peering_mode == 'dynamic'

    @property
    def is_genesis_node(self):
        return self._genesis_node == self.validator_id

    def pkey2nm(self,key):
        return self._oracle.peer_name_by_key(key)

    def belonge_cluster(self,peer_id):
        return self._oracle.is_own_peer(peer_id)

    def init_dag_nests(self):
        """
        genesis peer make nests
        """
        i,num = 0,self._oracle.max_branch*(CHAIN_LEN_FOR_NESTING+1) #len(self.arbiters)*2 # CHAIN_LEN_FOR_BRANCH
        LOGGER.debug('INIT DAG NESTS num=%s - ONLY GENESIS PEER',num)
        while i < num:
            self._oracle.make_nest_step(i) #self._chain_head.signer_public_key)
            i += 1
        

    def try_change_leader(self):
        if self.is_leader and self._oracle.is_leader_shift:
            for key,info in self.peers.items():
                if info.status == ConsensusNotifyPeerConnected.OK :
                    peer = self._oracle.peer_by_key(key)    
                    LOGGER.debug('TRY CHANGE LEADER %s=%s(%s)\n',peer[PeerAtr.name],_SID_(key),info.count)
                    self._oracle.make_topology_tnx({'cluster':self._cluster_name,'peer':peer[PeerAtr.name],'oper':'lead'})
                    return

    def do_heart_beat(self):
        LOGGER.debug('TRY TO DO  HEART BEAT {}'.format(self._last_seal_peers))
        self._oracle.send_heart_beat(self._last_seal_peers)

    def keep_seal_info(self,peers):
        self._last_seal_peers = [key for key in peers.keys()]
        self._last_seal_peers.append(self.validator_id)
        LOGGER.debug('keep_seal_info: {}'.format(self._last_seal_peers))

    def cluster_update(self):
        self._cluster = self._oracle.cluster
        self._cluster_name = self._oracle.cluster_name # own clusters name
        self._is_dynamic_cluster = self._oracle.is_dynamic_cluster

    def arbiters_update(self):
        narbiters = self._oracle.arbiters
        for key,arbiter in self._arbiters.items():
            if key not in narbiters and self._oracle.peer_is_leader(key):
                # was del from arbiter's ring but still stay in leader's
                self._leaders[key] = self._arbiters[key][1]
                LOGGER.debug('MOVE ARBITER=%s into LEADER LIST\n', _SID_(key)) 

        for key,arbiter in narbiters.items():
            if key in self._arbiters:
                # take arbiter's status
                status = self._arbiters[key][1]
                narbiters[key] = (arbiter[0],status,arbiter[2])

        self._arbiters = narbiters
        LOGGER.debug('UPDATE ARBITERS: %s\n', narbiters)

    def check_waiting_nest(self,bid):
        if bid in self._pending_nest:                                         
            LOGGER.debug('PbftEngine: WE CAN HANDLE BLOCK WAITING NEST')      
            block = self._pending_nest[bid]                                   
            del self._pending_nest[bid]                                       
            self._resolve_fork(block)       
                                              
    def _initialize_block(self,branch=None,new_branch=None,is_new = False):
        LOGGER.debug('PbftEngine: _initialize_block branch[%s] is_new=%s',_SID_(branch.hex()) if branch is not None else None,is_new)
        """
        getting addition chain head for DAG in case call _get_chain_head(parent_head) where parent_head is point for making chain branch
        """
        try:
            """
            To paint first nest with Genesis color 
            next new nest paint into color from arbiters[] - don't wait until cluster will be ready - reserve nest for them 
            for switch current branch to another node add argument new_branch
            """
            chain_head = self._get_chain_head(branch,new_branch,is_new) # get MAIN chain_head. chain_head.block_id is ID of parent's block 
            if not self._chain_head:
                self._chain_head = chain_head
        except exceptions.TooManyBranch:
            LOGGER.debug('PbftEngine: CANT CREATE NEW BRANCH (limit is reached)\n')
            self._make_branch = False
            self._palette     = True # pallete is ready
            return False
        except exceptions.NoChainHead:
            # head was updated or not commited yet
            LOGGER.debug('PbftEngine: CANT GET CHAIN HEAD for=%s',_SID_(branch.hex()) if branch is not None else None)
            return False
        except exceptions.BlockIsProcessedNow:
            LOGGER.debug('PbftEngine: CANT GET CHAIN HEAD for=%s - BLOCK IS PROCESSED',_SID_(branch.hex()) if branch is not None else None)
            return False
        # have got chain head block
        bid = branch.hex() if branch is not None else chain_head.block_id.hex()
        parent = chain_head.previous_block_id     
        block_num = chain_head.block_num          
        #LOGGER.debug('_initialize_block ID=%s chain_head=(%s)',_SID_(bid),chain_head)
        
        #initialize = True #self._oracle.initialize_block(chain_head)
        if branch is None and self.is_genesis_node and self._genesis_mode and self.signed_consensus:
            # for genesis node - send seal for first block 
            genesis_branch = self.create_branch(bid,parent,block_num)
            self.send_genesis_seal(genesis_branch)
        else:
            genesis_branch = None
        
        try:
            # ask init block
            color = self._branches[bid].nest_color if bid in self._branches else self.nest_color
            LOGGER.debug('_initialize_block ID=%s chain_head=(%s) color=%s',_SID_(bid),chain_head,color)
            self._service.initialize_block(previous_id=chain_head.block_id,nest_colour=color)
            # for remove this branch to another point 
            #bid = branch.hex() if branch is not None else chain_head.block_id.hex()
            if bid in self._branches:
                #branch = self._branches[bid]
                
                branch = self._branches[bid]
                branch._published = True
                branch._parent_id = parent
                branch._block_num = block_num
                if new_branch is not None :
                    del self._branches[bid]
                    nbid = new_branch.hex()
                    self._branches[nbid] = branch 
                    self.check_waiting_nest(nbid)
                    if nbid in self._pending_branch:
                        LOGGER.debug('HANDLE BLOCK WAITING BRANCH')      
                        block = self._pending_branch[nbid]                                   
                        del self._pending_branch[nbid]                                       
                        self._handle_new_block(block)

                LOGGER.debug('PbftEngine: _initialize_block USE Branch[%s]=%s',branch.ind,_SID_(bid))
            else:
                LOGGER.debug('PbftEngine: _initialize_block NEW Branch[%s]=%s color=%s pending=%s',self._num_branches,_SID_(bid),color,[_SID_(pid) for pid in self._pending_nest.keys()])
                self._branches[bid] = self.create_branch(bid,parent,block_num) if genesis_branch is None else genesis_branch
                self._branches[bid].nest_color = color
                self.check_waiting_nest(bid)
                
                
            
        except exceptions.UnknownBlock:
            LOGGER.debug('PbftEngine: _initialize_block ERROR UnknownBlock')
            #return False
        except exceptions.InvalidState :
            LOGGER.debug('PbftEngine: _initialize_block ERROR InvalidState')
            self._skip = True
            return False
        except Exception as ex:
            LOGGER.debug('PbftEngine: _initialize_block HEAD=%s.%s ERROR %s!!!\n',chain_head.block_num,_SID_(chain_head.block_id.hex()),ex)
            return False

        return True

    def create_branch(self,bid,parent,block_num):
        branch = BranchState(bid, parent, block_num, self._service, self._oracle, self,self._num_branches)
        self._num_branches += 1
        #if self._num_branches == 5:
        #    self._published = True
        return branch

    def is_not_build(self):
        for branch in self._branches.values():
            if branch._published and not branch._building:
                return True
        return False

    def _get_chain_head(self,bid=None,nbid=None,is_new=False):
        return PbftBlock(self._service.get_chain_head(bid,nbid,is_new))

    def _get_block(self, block_id):
        return PbftBlock(self._service.get_blocks([block_id])[block_id])

    def _summarize_block(self):
        try:
            return self._service.summarize_block()
        except exceptions.InvalidState as err:
            LOGGER.warning(err)
            return None,None
        except exceptions.BlockNotReady:
            #LOGGER.debug('exceptions.BlockNotReady')
            return None,None


    def _my_finalize_block(self):
        """
        in case DAG we should return parent for block which is ready  
        because we ask one of the initialized blocks
        """
        try:
            summary,parent_id = self._summarize_block()
        except FutureTimeoutError:
            LOGGER.debug('_my_finalize_block:  FutureTimeoutError\n')
            return None

        if summary is None:
            #LOGGER.debug('Block not ready to be summarized')
            return None
        bid = parent_id.hex()
        LOGGER.debug('Can FINALIZE NOW parent=%s branches=%s',_SID_(bid),self.branches_info)
        if bid in self._branches:
            LOGGER.debug('FINALIZE BRANCH=%s',_SID_(bid))
            branch = self._branches[bid]
            branch.finalize_block(parent_id,summary)
        else:
            LOGGER.debug('IGNORE FINALIZE FOR UNDEFINED BRANCH=%s\n',_SID_(bid))
        
    def _check_publish_block(self):
        # Publishing is based solely on wait time, so just give it None.
        LOGGER.debug('_check_publish_block ')
        return self._oracle.check_publish_block(None)

    def _testing_mode(self):
        # testing mode consensus
        if not self._published :
            # FIRST publish
            if not self._skip and self._initialize_block() :  
                self._published = True
        else: 
            for bid,branch in list(self._branches.items()):
                if not branch._published:
                    if self._TOTAL_BLOCK == 5 and branch.ind > 0:
                        # for testing only - try switch branch
                        LOGGER.debug('PbftEngine: TRY SWITCH BRANCH[%s] (%s->%s)\n',branch.ind,_SID_(bid),_SID_(branch._parent_id)) 
                        self._initialize_block(branch=bytes.fromhex(bid),new_branch=bytes.fromhex(branch._parent_id))
                    else:
                        self._initialize_block(bytes.fromhex(bid))
                else: # already published
                    if self._make_branch and branch._make_branch:
                        # create branch for testing - only one
                        LOGGER.debug('PbftEngine: CREATE NEW BRANCH[%s] (%s)\n',branch.ind,_SID_(branch._parent_id))
                        branch._make_branch = False
                        self._make_branch = False
                        self._initialize_block(bytes.fromhex(branch._parent_id))
                    if self._TOTAL_BLOCK == 5:
                        # for testing only - un freeze branch 0 and 
                        (block_id,parent_id) = branch.un_freeze_block()
                        if block_id is not None:
                            self.un_freeze_block(block_id,parent_id)

        if self.is_not_build(): # there is not build one
            self._sum_cnt += 1
            if self._sum_cnt > 10:
                self._sum_cnt = 0
                self._my_finalize_block()

    @property
    def start_switch_branch(self):
        return not self._make_branch and len(self._branches) > 1

    def _check_block_timeout(self):
        
        if self._make_branch:
            return
        ctime = time.time()
        for bid,branch in list(self._peers_branches.items()):
            if branch.can_cancel and (ctime - branch.stime) > self.block_timeout  :
                LOGGER.debug('TIMEOUT FOR BLOCK=%s state=%s\n',_SID_(bid),branch.state)
                branch.ignore_by_timeout(bid)
                #self._handle_invalid_block(bytes.fromhex(bid))
    def get_genesis_branch(self):
        
        for bid,branch in self._branches.items():
            if branch.block_num == 0:
                return branch

    def send_genesis_seal(self,genesis_branch=None):
        # make seal for genesis block and send into validator
        
        branch = self.get_genesis_branch() if genesis_branch is None else genesis_branch
        if branch:
            branch.send_genesis_seal()

    def _real_mode(self):
        # real mode consensus
        if not self._published :
            """
            FIRST publish or maybe we should make publish for all federations and connect all first candidates to genesis block
            """
            if not self._skip and self._initialize_block(branch=self.genesis_id,is_new=(self._chain_head is not None)) :  
                # at this point we can ask settings via chain using initial chain_head state_hash 
                if self.is_genesis_node and self._genesis_mode:
                    # send seal for genesis block 
                    self.init_dag_nests()

                self._published = True
                #if len(self._branches) == 5:
                #    self._published = True
        else: 
            for bid,branch in list(self._branches.items()):
                if not branch._published:
                    if self.start_switch_branch and branch.is_time_to_make_branch:
                        # for testing only - try switch branch
                        LOGGER.debug('PbftEngine: TRY SWITCH BRANCH[%s] (%s->%s)\n',branch.ind,_SID_(bid),_SID_(branch._parent_id)) 
                        if self._initialize_block(branch=bytes.fromhex(bid),new_branch=bytes.fromhex(branch._parent_id)):
                            """
                            At this moment leader can send heart beat transaction 
                            """
                            branch.reset_chain_len()
                            LOGGER.debug('PbftEngine: SYNC=%s SWITCHED BRANCH[%s]=%s\n',self.is_sync,branch.ind,_SID_(branch._parent_id)) 
                            if self.is_sync and self._is_heartbeat and self.is_leader:
                                self.do_heart_beat()
                            # check maybe there are blocks waiting that head
                            self.try_change_leader()
                            

                    else:
                        # try to do new branch 
                        if self._make_branch and branch.is_time_to_make_branch :
                            # try to create new branch until limit of branch will be reached
                            LOGGER.debug('PbftEngine: TRY1 CREATE NEW BRANCH[%s] (%s)\n',branch.ind,_SID_(branch._parent_id))
                            #branch._make_branch = False
                            #self._make_branch = False
                            if self._initialize_block(branch=bytes.fromhex(branch._parent_id),is_new=True) :
                                branch.reset_chain_len()
                                LOGGER.debug('PbftEngine:: SWITCHED BRANCH[%s]=%s\n',branch.ind,_SID_(branch._parent_id))
                        self._initialize_block(bytes.fromhex(bid))
                else: # already published
                    if self._make_branch and branch.is_time_to_make_branch :
                        # try to create new branch until limit of branch will be reached
                        LOGGER.debug('PbftEngine: TRY CREATE NEW BRANCH[%s] (%s)\n',branch.ind,_SID_(branch._parent_id))
                        #branch._make_branch = False
                        #self._make_branch = False
                        #if self._initialize_block(bytes.fromhex(branch._parent_id),is_new=True) :
                        #    branch.reset_chain_len()

                    if False and self._TOTAL_BLOCK == 5:
                        # for testing only - un freeze branch 0 and 
                        (block_id,parent_id) = branch.un_freeze_block()
                        if block_id is not None:
                            self.un_freeze_block(block_id,parent_id)

        if self.is_not_build(): # there is not build one
            self._my_finalize_block()

    def update_topology_settings(self):
        """
        for cluster topology use ring of arbiter
        """
        self._genesis_node = self._oracle.genesis_node # genesis node of all net - we take its genesis block for all net
        self._genesis      = self._oracle.genesis      # genesis cluster name
        #self._cluster_name = self._oracle.cluster_name # own clusters name
        #self._own_type = self._oracle.own_type
        self.arbiters_update()         # ring of arbiter  
        self.cluster_update()          # own cluster's peers
        
        if self._cluster_name is None:
            
            if self.is_dynamic_mode:
                LOGGER.debug("Waiting position into topology for=%s (Dynamic mode)\n",self._validator_id)
                self._is_sync = False
            else:
                LOGGER.debug("Undefined place into topology for=%s (Update dgt/etc/dgt_val.conf)", self._validator_id)
            LOGGER.debug("Genesis=%s(%s) Node=%s arbiters=%s",self._genesis,_SID_(self._genesis_node),_SID_(self._validator_id),self.arbiters_info)
        else:
            LOGGER.debug("Genesis=%s(%s) Node=%s %s in cluster=%s nodes=%s arbiters=%s(%s)",self._genesis,_SID_(self._genesis_node),_SID_(self._validator_id),self.own_type,self._cluster_name,[key[:8] for key in self._cluster.keys()],
                     self.arbiters_info,self.is_ready_arbiter
                     )

    def start(self, updates, service, startup_state):
        LOGGER.debug('PbftEngine: start service=%s startup_state=%s head=%s peering_mode=%s.',service,startup_state,startup_state.chain_head,startup_state.peering_mode)
        if startup_state.chain_head.previous_id.hex() != NULL_BLOCK_IDENTIFIER:
            self._is_sync = False
            LOGGER.debug('PbftEngine: Not Genisis start SYNC=%s!\n',self._is_sync)
            self._genesis_mode = False
        

        self._peering_mode = startup_state.peering_mode
        self._service = service
        self._state_view_factory = _StateViewFactoryProxy(service)
        self._oracle = PbftOracle(
            service=service,
            component_endpoint=self._component_endpoint,
            config_dir=self._path_config.config_dir,
            data_dir=self._path_config.data_dir,
            key_dir=self._path_config.key_dir,
            peering_mode = self._peering_mode,
            signed_consensus=self._signed_consensus)
        self._validator_id = self._oracle.validator_id

        
        self.update_topology_settings()
        
        #self._block_timeout = self._oracle.block_timeout 
        self._send_batches = self._oracle.send_batches 
        self._dag_step = self._oracle.dag_step
        CHAIN_LEN_FOR_BRANCH = self._dag_step
        self._is_heartbeat = self._oracle.is_heart_beat
        if self._is_heartbeat and self.is_leader:
            self._oracle.init_dec_client()
        

        # 1. Wait for an incoming message.
        # 2. Check for exit.
        # 3. Handle the message.
        # 4. Check for publishing.
        
        handlers = {
            Message.CONSENSUS_NOTIFY_BLOCK_NEW: self._handle_new_block,
            Message.CONSENSUS_NOTIFY_BLOCK_VALID: self._handle_valid_block,
            Message.CONSENSUS_NOTIFY_BLOCK_INVALID : self._handle_invalid_block,
            Message.CONSENSUS_NOTIFY_BLOCK_COMMIT:self._handle_committed_block,
            Message.CONSENSUS_NOTIFY_PEER_CONNECTED:self._handle_peer_connected,
            Message.CONSENSUS_NOTIFY_PEER_DISCONNECTED:self._handle_peer_disconnected,
            Message.CONSENSUS_NOTIFY_PEER_MESSAGE:self._handle_peer_message,
            # 
        }
        self._sum_cnt = 0
        self.is_real_mode = True
        LOGGER.debug('Start wait message in %s mode validator=%s dag_step=%s full=%s leader_shift=%s heartbeat=%s send_batches=%s timeout=%s.','REAL' if self.is_real_mode else 'TEST',
                      _SID_(self._validator_id),self._dag_step,self._oracle.is_pbft_full,self._oracle.is_leader_shift,self._is_heartbeat,self._send_batches,self.block_timeout
                    )
        #self._service.initialize_block() is None
        
        while True:
            try:
                try:
                    type_tag, data = updates.get(timeout=TIMEOUT)
                except queue.Empty:
                    pass
                else:
                    LOGGER.debug('PbftEngine:Received message: %s',Message.MessageType.Name(type_tag))

                    try:
                        handle_message = handlers[type_tag]
                    except KeyError:
                        LOGGER.error('PbftEngine:Unknown type tag: %s',Message.MessageType.Name(type_tag))
                    else:
                        handle_message(data)

                if self._exit:
                    break

                #self._try_to_publish()
                if self._cluster_name is None and not self.is_dynamic_mode:
                    if self.is_dynamic_mode:
                        # until get position into topology
                        pass

                    continue

                if self.is_real_mode:
                    self._check_block_timeout()
                    self._real_mode()
                    #self._check_block_timeout()
                else:
                    self._testing_mode()

            except Exception:  # pylint: disable=broad-except
                LOGGER.exception("PbftEngine:Unhandled exception in message loop")

        LOGGER.debug('PbftEngine: start DONE')

    def un_freeze_block(self,block_id,parent_id):
        self._new_heads[block_id] = parent_id
        LOGGER.info('   NEW_HEAD=%s for BRANCh=%s AFTER FREEZE', _SID_(block_id),_SID_(parent_id))

    def check_consensus(self,blocks,block_num,summary,num_peers):
        # check maybe all(really 2f+1 ) messages arrived
        LOGGER.debug("CHECK CONSENSUS BLOCKS=%s _send_batches=%s",len(blocks),self._send_batches)   
        if len(blocks) == (num_peers + 1) or not self._send_batches:                                                                                                                                
            for key in blocks:
                if key not in self._peers_branches:
                    LOGGER.debug("We have all prepares for block=%s but not ALL blocks(wait block=%s)",block_num,_SID_(key))
                    return
            selected = max(blocks.items(), key = lambda x: x[0])[0]
            LOGGER.debug("We have all prepares for block=%s SUMMARY=%s select=%s blocks=%s",block_num,_SID_(summary),_SID_(selected),[_SID_(key) for key in blocks.keys()])        
            LOGGER.debug("COMMIT BLOCK=%s",_SID_(selected))  
            branch = self._peers_branches[selected]                                                                                                                
            # send prepare again                                                                                                                                          
            #self._peers_branches[selected]._send_prepare(block)
            if selected in self._pre_prepare_msgs:
                """
                free PRE_PREPARE mess here. Now we have new_block and will ignore PRE_PREPARE
                """
                self._pre_prepare_msgs.pop(selected)
            
            """
            AT THIS POINT WE CAN START PBFT FOR SELECTED BLOCK
            we choice only one block from all peer's blocks and fail the rest of them 
            for simple version of consensus we can say commit right now
            """                                                                                                          
            branch.finish_consensus(None,selected,True)                                                                                           
            for bid in blocks.keys():                                                                                                                                     
                if bid != selected:                                                                                                                                       
                    LOGGER.debug("FAIL BLOCK=%s",_SID_(bid))                                                                                                                 
                    #self._peers_branches[bid]._send_prepare(block) 
                    if bid in self._pre_prepare_msgs:
                        self._pre_prepare_msgs.pop(bid)
                    self._peers_branches[bid].finish_consensus(None,bid,False) 
                    
                    # drop list for summary                                                                                                                               
            self._prepare_msgs.pop(summary)                                                                                                                               
            LOGGER.debug("=>ALL SUMMARY=%s\n",[_SID_(key) for key in self._prepare_msgs.keys()])                                                                             


    def _handle_new_block(self, block):
        """
        we should handle only block from own cluster 
        all rest blocks ignore
        """
        block = PbftBlock(block)
        block_id = block.block_id.hex()
        signer_id  = block.signer_id.hex()
        summary = block.summary.hex()
        block_num = block.block_num
        num_peers = self.num_peers 
        is_own = (signer_id == self._validator_id)
        LOGGER.info('=> NEW_BLOCK:Received block=%s.%s signer=%s summary=%s num_peers=%s SYNC=%s OWN=%s',block_num,_SID_(block_id),_SID_(signer_id),_SID_(summary),num_peers,self.is_sync,is_own)
        def check_consensus():
            if num_peers > 0 and summary in self._prepare_msgs:                                                                                                                   
                blocks = self._prepare_msgs[summary]
                self.check_consensus(blocks,block_num,summary,num_peers)

        commits = self._commit_msgs.pop(block_id,None)
        if is_own:
            # find branch for this block 
            if block.previous_block_id in self._branches:
                branch = self._branches[block.previous_block_id]
                self._peers_branches[block_id] = branch # add ref on branch for own block 
                result = branch.new_block(block, True, commits)
                if result == Consensus.done:
                    # refer for block on branch
                    self._new_heads[block_id] = block.previous_block_id
                    LOGGER.info('   NEW_HEAD=%s for BRANCh=%s', _SID_(block_id),_SID_(block.previous_block_id))
                elif result == Consensus.fail:
                    LOGGER.info('Failed consensus check: %s', _SID_(block_id))
                else:
                    # consensus was started
                    LOGGER.info('consensus started for block=%s->%s', _SID_(block_id),_SID_(block.previous_block_id))
                    self._new_heads[block_id] = block.previous_block_id
                    if block_id in self._pre_prepare_msgs:
                        """
                        free PRE_PREPARE mess here. Now we have new_block and will ignore PRE_PREPARE
                        """
                        msg = self._pre_prepare_msgs[block_id] # self._pre_prepare_msgs.pop(block_id)
                        branch.pre_prepare(msg)

                    check_consensus()
                    # Don't reset now - wait message INVALID_BLOCK
                    #self.reset_state()
            else:
                # new block can appeared before we have branch
                LOGGER.info('NEW OWN BLOCK=%s.%s no branch=%s pend=%s!\n',block_num,_SID_(block_id),_SID_(block.previous_block_id),len(self._pending_branch))
                self._pending_branch[block.previous_block_id] = block
        else:
            # external block from another node or maybe another cluster
            
            if block_id not in self._peers_branches:
                cluster = self.belonge_cluster(signer_id)
                LOGGER.info('EXTERNAL NEW BLOCK=%s.%s peer=%s CLUST=%s',block_num, _SID_(block_id),_SID_(signer_id),cluster)
                branch = self.create_branch('','',block_num)
                self._peers_branches[block_id] = branch
                LOGGER.info('START CONSENSUS for BLOCK=%s(%s) branch=%s',_SID_(block_id),_SID_(signer_id),branch.ind)
                branch.new_block(block,cluster,commits)
                self._new_heads[block_id] = block.previous_block_id
                LOGGER.info('   NEW_HEAD=%s for BRANCh=%s', _SID_(block_id),_SID_(block.previous_block_id))
                if block_id in self._pre_prepare_msgs:
                    """
                    free PRE_PREPARE mess here. Now we have new_block and will ignore PRE_PREPARE
                    """
                    msg = self._pre_prepare_msgs[block_id] # self._pre_prepare_msgs.pop(block_id)
                    branch.pre_prepare(msg)
                # check maybe all messages arrived
                check_consensus()
            else:
                LOGGER.info('EXTERNAL BLOCK=%s.%s num=%s peer=%s IGNORE(already has)', block_num,_SID_(block_id),_SID_(signer_id))
                


    def _handle_valid_block(self, block_id):
        """
        this is answer on check_block
        """
        bid = block_id.hex()
        LOGGER.info('=> VALID_BLOCK:Received %s', _SID_(bid))
        if bid in self._peers_branches:
            branch = self._peers_branches[bid]
            LOGGER.info('=> VALID BLOCK=%s state=%s', _SID_(bid),branch.state)
            if branch.state >= State.Commiting or branch.already_send_commit:
                LOGGER.info('=> IGNORE VALID_BLOCK: ALREADY RECIEVED %s', _SID_(bid))
                return
        try:
            block = self._get_block(block_id)
        except exceptions.UnknownBlock:
            LOGGER.info('=> VALID_BLOCK:CANT GET BLOCK=%s', _SID_(bid))
            return
        self._pending_forks_to_resolve.push(block)
        self._committing = False
        self._process_pending_forks()
        LOGGER.info('VALID_BLOCK  pending_forks DONE %s.',self._pending_forks_to_resolve)

    def _handle_invalid_block(self,block_id):
        """
        this is answer on check_block
        """
        try:
            block = self._get_block(block_id)
            signer_id  = block.signer_id.hex()
            bid = block_id.hex()
            LOGGER.info('=> INVALID_BLOCK:Received id=%s signer=%s\n', _SID_(bid),_SID_(signer_id))
            if bid in self._new_heads:
                self._new_heads.pop(bid)
            if signer_id == self._validator_id:
                if block.previous_block_id in self._branches:
                    branch = self._branches[block.previous_block_id]
                    if bid in self._peers_branches:
                        del self._peers_branches[bid]
                    if block.block_num == 0:
                        branch.reset_state(bid)
                    else:
                        # FIXME -may be we should do reset?
                        LOGGER.info('=> INVALID_BLOCK: DONT DO reset \n')
                        if not self.is_sync or not branch.can_cancel:
                            branch.reset_state(bid)
            else:
                LOGGER.info('=> INVALID_BLOCK: external block=%s branches=%s \n',_SID_(bid),self.peer_branches_info)
                if bid in self._peers_branches:
                    branch = self._peers_branches[bid]
                    branch = self.reset_state(bid)
                    del self._peers_branches[bid]
            LOGGER.info('=> INVALID_BLOCK: branches=%s \n',self.peer_branches_info)
        except :
            LOGGER.info('=> INVALID_BLOCK: undefined id=%s\n', _SID_(block_id.hex()))
        self.reset_state()

    def _process_pending_forks(self):
        LOGGER.info('_process_pending_forks commiting=%s %s.',self._committing,self._pending_forks_to_resolve)
        while not self._committing:
            block = self._pending_forks_to_resolve.pop()
            if block is None:
                LOGGER.info('_process_pending_forks NO PENDING BLOCK.')
                break

            self._resolve_fork(block)

    def _resolve_fork(self, block):
        # ask head for branch bid
        bid = block.previous_block_id
        bbid = bytes.fromhex(bid)
        signer_id  = block.signer_id.hex()
        block_id = block.block_id.hex()

        def resolve_fork(branch,chain_head,block):
            # resolve this fork
            LOGGER.info('RESOLVE FORK for BLOCK=%s(%s) branch=%s',_SID_(block_id),_SID_(signer_id),branch.ind)
            result = branch.resolve_fork(chain_head,block)
            if result == Consensus.done:
                self._committing = True
            elif result == Consensus.fail:
                self.reset_state()
            else:
                # pending start commiting
                LOGGER.info('START COMMITING for BLOCK=%s(%s)',_SID_(block_id),_SID_(signer_id))

        LOGGER.info('_resolve_fork PREV=%s BLOCK=%s(%s)',_SID_(bid),_SID_(block_id),_SID_(signer_id))
        if signer_id == self._validator_id and self.is_sync:
            if bid in self._branches:
                try:
                    # head could be already changed - we can get new head for this branch
                    LOGGER.info('BLOCK=%s(%s) num=%s prev=%s', _SID_(block_id),_SID_(signer_id),block.block_num,_SID_(bid))
                    chain_head = self._get_chain_head(bbid)
                    branch = self._branches[bid]
                    resolve_fork(branch,chain_head,block)
                except exceptions.NoChainHead:
                    LOGGER.info('BLOCK=%s.%s NO DAG HEAD=%s waiting NEST\n\n',block.block_num,_SID_(block_id),_SID_(bid))
                    self._pending_nest[bid] = block
            else:
                LOGGER.info('HEAD FOR BLOCK=%s(%s) was changed',block.block_num, _SID_(block_id),_SID_(signer_id))
        else:
            # external block 
            LOGGER.info('EXTERNAL BLOCK=%s(%s) num=%s prev=%s', _SID_(block_id),_SID_(signer_id),block.block_num,_SID_(bid))
            if block_id in self._peers_branches:
                # head could be already changed - we can get new head for this branch
                head_id = (None if bid == NULL_BLOCK_IDENTIFIER else bbid)
                try:
                    chain_head = self._get_chain_head(head_id) # ask head for branch
                    branch = self._peers_branches[block_id] 
                    resolve_fork(branch,chain_head,block)
                except exceptions.NoChainHead:
                    # in sync mode nest for this federation could be not ready
                    # we can pending this block until nest ready 
                    LOGGER.info('EXTERNAL BLOCK=%s.%s NO DAG HEAD=%s waiting NEST\n\n',block.block_num,_SID_(block_id),head_id if head_id is None else _SID_(bid))
                    self._pending_nest[bid] = block
            else:
                # RECOVERY MODE
                if not self.is_sync:
                    LOGGER.info('EXTERNAL BLOCK=%s.%s RECOVERY pbid=%s\n',block.block_num,_SID_(block_id),_SID_(bid))
                    branch = self.create_branch('','',block.block_num)
                    self._peers_branches[block_id] = branch
                    self._new_heads[block_id] = bid
                    branch.commit_block(block.block_id)
                    self._committing = True
                    
                


    def reset_state(self):
        self._building = False   
        #self._published = False  
        self._committing = False 


    def _handle_committed_block(self, block_id):
        """
        This is answer on commit 
        """
        block_id = block_id.hex()
        

        def _update_head_branch(prev_num,block_num):
            LOGGER.info('   _update_head_branch check=%s',prev_num)
            for key,branch in self._branches.items():
                if branch.block_num == prev_num:
                    LOGGER.info('   update chain head for BRANCH=%s -> %s',branch.ind,_SID_(block_id))
                    branch = self._branches.pop(key)
                    branch._parent_id = block_id
                    branch._block_num = block_num
                    self._branches[block_id] = branch
                    return True
            LOGGER.info('   Cant update chain head=%s on BLOCK=%s.%s\n',prev_num,block_num,_SID_(block_id))
            return False

        LOGGER.info('=> BLOCK_COMMIT Chain head updated to %s, abandoning block in progress heads=%s',_SID_(block_id),[_SID_(key) for key in self._new_heads.keys()])
        # for DAG new head for branch will be this block_id
        # and we should use it for asking chain head for this branch 
        if block_id in self._new_heads:
            hid = self._new_heads.pop(block_id) # hid is parent of this block
            LOGGER.info('   update chain head for BRANCH=%s->%s branches=%s+%s',_SID_(hid),_SID_(block_id),self.branches_info,self.peer_branches_info)
            if hid in self._branches:
                branch = self._branches.pop(hid)
                if block_id in self._peers_branches :
                    # inherit role 
                    branch._own_type= self._peers_branches[block_id].own_type
                branch.check_arbitration(block_id)
                branch.cancel_block(block_id) # change parent_id too 
                branch.reset_state(block_id)    
                self._branches[block_id] = branch
                self._TOTAL_BLOCK += 1 
                if block_id in self._peers_branches:
                    del self._peers_branches[block_id]
                LOGGER.info('   set new head=%s for BRANCH=%s TOTAL=%s peers branches=%s',_SID_(block_id),_SID_(hid),self._TOTAL_BLOCK,self.peer_branches_info)
            else:
                # external block
                LOGGER.info('head updated for=%s  peers branches=%s arb=%s',_SID_(block_id),self.peer_branches_info,[_SID_(key) for key in self._arbitration_msgs.keys()])
                if block_id in self._peers_branches:
                    branch = self._peers_branches[block_id]
                    branch.check_arbitration(block_id)
                    branch.cancel_block(block_id) # change parent_id too 
                    branch.reset_state(block_id)
                    del self._peers_branches[block_id] 
                    # update _branches
                    block = self._get_block(bytes.fromhex(block_id))
                    prev = block
                    while not _update_head_branch(prev.block_num,block.block_num):
                        try:
                            prev = self._get_block(bytes.fromhex(prev.previous_block_id))
                        except :
                            LOGGER.info('Head updated cant get BLOCK=%s\n',_SID_(prev.previous_block_id))
                            break
                            #if prev.previous_block_id == NULL_BLOCK_IDENTIFIER:
                            #    break


        
        LOGGER.info('=> BLOCK_COMMIT prepre=%s pre=%s branches=%s+%s',len(self._pre_prepare_msgs),len(self._prepare_msgs),self.branches_info,self.peer_branches_info)
        self._process_pending_forks()
        self.reset_state()

    def arbitration_sync(self,block,block_id,peer_id):
        """
        Arbitration into SYNC mode - ASK SEAL FOR THIS BLOCK
        """
        LOGGER.debug("peer=%s ASK ARBITRATION for block=%s SYNC mode",_SID_(peer_id),_SID_(block_id))
        blk = self._get_block(bytes.fromhex(block_id)) # TODO - this method should return SEAL TOO
        LOGGER.debug("GET block=%s SYNC mode",blk)
        for branch in self._branches.values():
            branch._send_arbitration_done(block,peer_id,seal=None)
            break

    def keep_commit_msg(self,block_id,block,peer_id):
        if block_id in self._commit_msgs:
            commits = self._commit_msgs[block_id]
        else:
            commits = {}
            self._commit_msgs[block_id] = commits
        LOGGER.debug('TRY SAVE COMMIT MSG for BLOCK=%s peer=%s total=%s',_SID_(block_id),_SID_(peer_id),len(commits))
        if peer_id not in commits and peer_id in self.peers:
            commits[peer_id] = block
            LOGGER.debug('SAVE COMMIT MSG for BLOCK=%s peer=%s total=%s',_SID_(block_id),_SID_(peer_id),len(commits))

    def peer_status(self,peer_id):
        # take in advance only message from own cluster or from arbiters
        # message from others peers will be ignored
        return self.peers[peer_id].status if peer_id in self.peers else (self.arbiters[peer_id][1] if peer_id in self.arbiters else (self._leaders[peer_id] if peer_id in self._leaders else ConsensusNotifyPeerConnected.NOT_READY))

    def _handle_peer_disconnected(self, peer_id):
        if peer_id:
            pid = peer_id.hex()
            LOGGER.debug('DisConnected peer=%s.%s',self.pkey2nm(pid),_SID_(pid)) 
            if self._oracle.is_own_peer(pid) :
                if pid in self.peers and self.peers[pid].status != ConsensusNotifyPeerConnected.NOT_READY:
                    self.change_peer_status(pid,ConsensusNotifyPeerConnected.NOT_READY,self.peers[pid].status)
            elif pid in self.arbiters:
                # one of the arbiters - mark as NOT ready 
                self.change_arbiter_status(pid,ConsensusNotifyPeerConnected.NOT_READY)
            

    def handle_topology_update(self,pid,oper,val,data):
        """
        topology update
        """
        if oper == ConsensusNotifyPeerConnected.ROLE_CHANGE:                                                                                      
            #LOGGER.debug('NEW LEADER PEER=%s CLUSTER -> %s\n',pid[:8],val)                                                                       
            changed,i_am_new = self._oracle.change_current_leader(pid,val)                                                                       
            if changed :  
                if i_am_new:
                    self.arbiters_update()
                if pid in self.peers:
                    # how many times this peer has leader's role
                    self.peers[pid]._replace(count=self.peers[pid].count+1)

            LOGGER.debug('NEW LEADER PEER=%s CLUSTER -> %s peers=%s\n', _SID_(pid), val, self.peers_info)

        elif oper == ConsensusNotifyPeerConnected.ARBITER_CHANGE:                                                                                 
            changed,i_am_new = self._oracle.change_current_arbiter(pid,val)                                                                      
            LOGGER.debug('NEW ARBITER PEER=%s CLUSTER -> %s ITS ME=%s ARBITER=%s\n', _SID_(pid), val, i_am_new, self.is_arbiter)                    
            if changed :                                                                                                                              
                self.arbiters_update()                                                                                                                
            
        elif oper == ConsensusNotifyPeerConnected.ADD_CLUSTER:                                                                                    
            ret,_ = self._oracle.add_new_cluster(pid,val)                                                                                        
            LOGGER.debug('ADD CLUSTER TO PEER=%s CLUSTER -> %s ret=%s\n',_SID_(pid),val,ret)                                                        
        elif oper == ConsensusNotifyPeerConnected.DEL_CLUSTER:                                                                                    
            ret,_ = self._oracle.del_cluster(pid)                                                                                                     
            LOGGER.debug('DEL CLUSTER PEER=%s ret=%s\n',_SID_(pid),ret)  
        elif oper == ConsensusNotifyPeerConnected.ADD_PEER:
            ret,err_info = self._oracle.add_peer(pid,val)
            LOGGER.debug('ADD PEER=%s %s ret=%s(%s)\n',pid,val,ret,err_info)
            if ret > 0:
                if (ret & 0b001) > 0:
                    LOGGER.debug('arbiters_update ')
                    self.arbiters_update()
                if (ret & 0b100) > 0:
                    LOGGER.debug('cluster_update ')
                    self.cluster_update()
            #own cluster update 
        elif oper == ConsensusNotifyPeerConnected.SET_NEST:
            ret,err = self._oracle.map_topo_nest(val)
            LOGGER.debug(f'MAP NEST={val}  ret={ret} err={err}')
            if ret == True:
                self.update_topology_settings()
            
        elif oper == ConsensusNotifyPeerConnected.DEL_PEER:
            ret,_ = self._oracle.del_peer(pid,val)
            LOGGER.debug('DEL PEER=%s %s ret=%s\n',_SID_(pid),val,ret)

        elif oper == ConsensusNotifyPeerConnected.PARAM_UPDATE:
            LOGGER.debug(f'PARAM_UPDATE [{val}]={data} join={self._join_cluster}\n')
            if self._oracle.update_param(val,data):
                # topology was updated
                is_not_joined = self._cluster_name is None
                self._oracle.get_topology(self._join_cluster)
                self.update_topology_settings()
                if is_not_joined:
                    self._nest_color = []
                #self.nest_color

        elif oper == ConsensusNotifyPeerConnected.JOIN_CLUSTER:
            LOGGER.debug('JOIN_CLUSTER=%s\n',val)
            self._join_cluster = val
        else:
            LOGGER.debug(f'UNDEF OPERATION {oper}\n')
            return False
        return True

    def change_arbiter_status(self,pid,status):
        val = self.arbiters[pid]
        pnm = self.pkey2nm(pid) 
        LOGGER.debug('Change arbiter status={} old={} '.format(status,val))
        if val[1] != status:
            self.arbiters[pid] = (val[0],status,val[2])
            
            LOGGER.debug('Connected peer[%s] with ID=%s  status=%s OUR ARBITER=%s arbiters=%s SYNC=%s\n',pnm, _SID_(pid),status,val,self.num_arbiters,self._is_sync)
        else:
            LOGGER.debug('Connected peer[%s] with ID=%s IS ARBITER status=%s the same arbiters=%s SYNC=%s\n',pnm, _SID_(pid),status,self.num_arbiters,self._is_sync)

    def change_peer_status(self,pid,stat,old_stat=None):                                                                                                                
        # reset .num                                                                                                                                               
        if old_stat is None:                                                                                                                                       
            self.peers[pid] = PeerInfo(stat,0,1 if self._oracle.peer_is_leader(pid) else 0 ) # defaults=(0,)                                                       
        else: # update already known peer                                                                                                                          
            self.peers[pid] = self.peers[pid]._replace(status=stat,num=0)                                                                                          
                                                                                                                                                                   
                                                                                                                                                                   
        if not self.is_sync and stat == ConsensusNotifyPeerConnected.OK:                                                                                           
            #self._is_sync = True                                                                                                                                  
            LOGGER.debug('SET OWN SYNC STATUS\n')                                                                                                                  
        LOGGER.debug('Change status peer=%s status=%s->%s SYNC=%s arbiters=%s peers=%s', _SID_(pid), old_stat, stat, self.is_sync,self.num_arbiters,self.peers_info)  



    def _handle_peer_connected(self, notif):
        """
        Handle peer activity - conn/discon and status change
        """
        #LOGGER.debug('Connected peer status=%s',notif[1])
        
        pid = notif[0].peer_id.hex()
        pnm = self.pkey2nm(pid)
        if self.handle_topology_update(pid,notif[1],notif[3],notif[4]):
            return True

        if pid not in self.peers:
            if pid == self.validator_id:
                self._is_sync = notif[1] != ConsensusNotifyPeerConnected.NOT_READY
                LOGGER.debug('Change OWN SYNC STATUS=%s MODE=%s->%s SYNC=%s arbiters=%s\n', notif[1],self._mode,notif[2],self._is_sync,self.num_arbiters) 
                if self._mode != notif[2] :
                    self._mode = notif[2]
            elif self._oracle.is_own_peer(pid):
                # take only peers from own cluster topology 
                # save status of peer
                self.change_peer_status(pid,notif[1])
                
            elif pid in self.arbiters:
                # one of the arbiters - mark as ready 
                self.change_arbiter_status(pid,notif[1])
                
            elif self.is_arbiter and self._oracle.peer_is_leader(pid) :
                # this is other leaders
                self._leaders[pid] = notif[1]
                LOGGER.info('Connected peer with ID=%s.%s status=%s is other leader=%s\n',pnm, _SID_(pid),notif[1],len(self._leaders))
            else:
                LOGGER.debug('Connected peer with ID=%s.%s(Ignore - not in our cluster and not arbiter)\n',pnm, _SID_(pid))

        else: # this peer is already known
            if self._oracle.is_own_peer(pid) and self.peers[pid].status != notif[1]:
                self.change_peer_status(pid,notif[1],self.peers[pid].status)
                
    @property
    def branches_info(self):
        return [_SID_(key) for key in self._branches.keys()]
    @property
    def peer_branches_info(self):
        return [_SID_(key) for key in self._peers_branches.keys()]
    
    def _handle_peer_message(self, msg):
        """
        consensuse message: PrePrepare, Prepare, Commit, Checkpoint 
        p2p_mesg - ConsensusPeerMessage or ConsensusPeerMessageNew
        """
        
        p2p_mesg = msg[0]
        # for COMMIT p2p_mesg is PbftSignedVote
        # for 
        payload = PbftMessage()
        payload.ParseFromString(p2p_mesg.content)
        # depend on payload.info we should decode payload.content
        # for ARBITRATION_DONE_MSG it will be PbftSeal
        info = payload.info
        msg_type = info.msg_type
        # peer information
        peer_id = info.signer_id.hex()                                                                
        peer_nm = self.pkey2nm(peer_id)                                                               
        peer_status = self._is_sync if self.validator_id == peer_id else self.peer_status(peer_id)    
        is_peer_arbiter = peer_id in self.arbiters

        if msg_type == PbftMessageInfo.ARBITRATION_DONE_MSG:
            seal = PbftSeal()
            seal.ParseFromString(payload.content)
            block = seal.block
        else:
            block = PbftBlockMessage()
            block.ParseFromString(payload.content)
            seal = None

        block_id = block.block_id.hex()
        signer_id = block.signer_id.hex()
        summary  = block.summary.hex()
        block_num = block.block_num

        
        if peer_status == ConsensusNotifyPeerConnected.NOT_READY:
            # take message from sync peer and peer from cluster or arbiter ring
            LOGGER.debug("=> IGNORE PEER_MESSAGE %s.'%s'  peer=%s.%s(%s) NOT READY\n",info.seq_num,CONSENSUS_MSG[msg_type],peer_nm,_SID_(peer_id),peer_status)
            return

        LOGGER.debug("=> PEER_MESSAGE %s.'%s' block_id=%s(%s) summary=%s peer=%s.%s(%s)",info.seq_num,CONSENSUS_MSG[msg_type],_SID_(block_id),_SID_(signer_id),_SID_(summary),peer_nm,_SID_(peer_id),peer_status)
        if msg_type == PbftMessageInfo.PRE_PREPARE_MSG:
            # send reply 
            LOGGER.debug("=>PRE PREPARE for block=%s branches=%s+%s",_SID_(block_id),self.branches_info,self.peer_branches_info)
            if block_id in self._branches:
                # for genesis block
                LOGGER.debug("=>PRE PREPARE for block=%s BRANCHES!!\n",_SID_(block_id))
                self._branches[block_id].pre_prepare(block,True)
            elif block_id in self._peers_branches:
                # already has NEW BLOCK message
                self._peers_branches[block_id].pre_prepare(block,first=(block_id not in self._pre_prepare_msgs))
            elif block_id not in self._pre_prepare_msgs:
                # message arrive before corresponding block appeared save block part of message
                LOGGER.debug("=>PRE PREPARE message arrive before corresponding BLOCK=%s appeared(SAVE it)\n",_SID_(block_id))
                self._pre_prepare_msgs[block_id] = block  

        elif msg_type == PbftMessageInfo.PREPARE_MSG:
            # continue consensus 
            LOGGER.debug("=>PREPARE for block=%s branches=%s+%s",_SID_(block_id),self.branches_info,self.peer_branches_info)
            if block_id in self._peers_branches:
                """
                it really means that NEW_BLOCK message already appeared
                """
                if block_num == 0:
                    self._peers_branches[block_id].finish_consensus(block,block_id,True)
                else:
                    pstate = self._peers_branches[block_id].state
                    if pstate not in [State.NotStarted,State.Preparing,State.PrePreparing,State.PreCommiting] :
                        """
                        prepare can appeared before prePrepare when we send it in case NEW BLOCK appeared after prePrepare
                        skip message after commit or fail 
                        """
                        LOGGER.debug("SKIP PREPARE message fail %s summary=%s\n",pstate,_SID_(summary))
                        return
                    # waiting until all block with equivalent summary will have prepare message
                    LOGGER.debug("=>CHECK SUMMARY=%s ALL=%s",summary[:10],[_SID_(key) for key in self._prepare_msgs.keys()])
                    if summary in self._prepare_msgs:
                        #  add block for summary list
                        blocks = self._prepare_msgs[summary]
                        LOGGER.debug("=>SUMMARY=%s have blocks=%s",summary[:10],[_SID_(key) for key in blocks.keys()])
                        if block_id in blocks:
                            LOGGER.debug("=>IGNORE BLOCK=%s FOR SUMMARY=%s (already has).",_SID_(block_id),_SID_(summary))
                        else:
                            # add block into list and check number of blocks
                            num_peers = self.num_peers
                            blocks[block_id] = True
                            LOGGER.debug("=>ADD BLOCK=%s INTO SUMMARY=%s total=%s peers=%s",_SID_(block_id),_SID_(summary),len(blocks),num_peers) 
                            self.check_consensus(blocks,block_num,summary,num_peers)
                            
                    else:
                        LOGGER.debug("=>ADD BLOCK=%s INTO SUMMARY=%s",_SID_(block_id),_SID_(summary))
                        self._prepare_msgs[summary] = {block_id : True}
                        if not self._send_batches:
                            # only one peer make block
                            self.check_consensus(self._prepare_msgs[summary],block_num,summary,self.num_peers)
            else:
                """
                there is no NEW_BLOCK message yet but save message
                """ 
                if summary in self._prepare_msgs:
                    # already into prepare - we can add info about this block in case it new 
                    blocks = self._prepare_msgs[summary]
                    LOGGER.debug("=>SUMMARY=%s have blocks=%s (no block yet)",summary[:10],[_SID_(key) for key in blocks.keys()])
                    if block_id not in blocks:
                         LOGGER.debug("=>ADD BLOCK=%s INTO SUMMARY=%s total=%s (no block yet)",_SID_(block_id),_SID_(summary),len(blocks))
                         blocks[block_id] = True
                    
                else:
                    # first prepare message for this block 
                    if block_id in self._pre_prepare_msgs:
                        # only after PRE_PREPARE - in case PRE_PREPARE missing - block was commited
                        LOGGER.debug("=>ADD BLOCK=%s INTO SUMMARY=%s (no block yet)",_SID_(block_id),_SID_(summary))
                        self._prepare_msgs[summary] = {block_id : True}

        elif msg_type == PbftMessageInfo.COMMIT_MSG:
            """
            commiting state - COMMIT MSG can appeared before NEW_BLOCK
            in case message from arbiter it is reply on arbitration
            """
            LOGGER.debug("=>%s for block=%s peer=%s.%s(%s) branches=%s+%s",("ARBITRATION_REPL" if is_peer_arbiter else "COMMIT"), _SID_(block_id),peer_nm, _SID_(peer_id), peer_status,self.branches_info,self.peer_branches_info)
            if is_peer_arbiter:
                # reply from arbiter
                if block_id in self._peers_branches:                                                       
                    branch = self._peers_branches[block_id]                                                
                    if block_id in self._arbitration_msgs:                                                 
                        marker = self._arbitration_msgs[block_id]                                          
                        if isinstance(marker, bool) :                                                      
                            LOGGER.debug("GET ARBITRATION MARKER=%s for block=%s",marker,_SID_(block_id))     
                            del self._arbitration_msgs[block_id]                                           
                            self._arbitration_msgs[block_id] = (block,peer_id)                             
                                                                                                           
                    branch.arbitration_repl(block,p2p_mesg,peer_id)                                                 
                return
            if block_id in self._peers_branches:
                branch = self._peers_branches[block_id]
                branch.add_commit_msg(peer_id,(block,p2p_mesg))
                LOGGER.debug("=>COMMIT for block=%s peer branch=%s",_SID_(block_id),branch)
            elif block_id in self._branches:
                # this is own block and it already commited (first block) 
                branch = self._branches[block_id]
                if branch.block_num == 0:
                    branch.shift_to_commiting(block,self.peers[peer_id].status,peer_id)
                    LOGGER.debug("=>COMMIT for block=%s branch=%s",_SID_(block_id),branch)
            else:
                # COMMIT BEFORE NEW BLOCk
                self.keep_commit_msg(block_id,(block,p2p_mesg),peer_id)
                 

        elif msg_type == PbftMessageInfo.ARBITRATION_MSG:
            """
            other cluster leader ask Arbitration - and I am arbiter
            """
            if not self.is_arbiter:
                LOGGER.debug("=>IGNORE ARBITRATION for block=%s peer=%s.%s I am not ARBITER",_SID_(block_id),peer_nm,_SID_(peer_id))
                return
            LOGGER.debug("=>ARBITRATION for block=%s peer=%s.%s branches=%s+%s",_SID_(block_id),peer_nm,_SID_(peer_id),self.branches_info,self.peer_branches_info)
            """
            if block_id in self._branches:
                branch = self._branches[block_id]
                LOGGER.debug("=>ARBITRATION_DONE for block=%s peer branch=%s",_SID_(block_id),branch)
                branch.arbitration(block,peer_id)
            else:
            """
            # usually we get this message before new block - so save it
            if block_id not in self._arbitration_msgs:
                LOGGER.debug("SAVE ARBITRATION for block=%s peer=%s",_SID_(block_id),peer_nm)
                self._arbitration_msgs[block_id] = (block,peer_id)
                if self.peer_status(peer_id) == ConsensusNotifyPeerConnected.NOT_READY:
                    # peer ask synchronization
                    self.arbitration_sync(block,block_id,peer_id)
            else:
                # may be we saved marker 
                marker = self._arbitration_msgs[block_id]
            
                if isinstance(marker, bool) :
                    LOGGER.debug("GET ARBITRATION MARKER=%s for block=%s",marker,_SID_(block_id))
                    # drop marker                     
                    del self._arbitration_msgs[block_id]
                    if block_id in self._peers_branches:
                        branch = self._peers_branches[block_id]
                        branch.arbitration(block,peer_id,marker) 
                    
                
        elif msg_type == PbftMessageInfo.ARBITRATION_DONE_MSG:
            # message from leader of cluster which is owner of block
            #check peer_id which should be arbiter or leader TODO
            LOGGER.debug("=>ARBITRATION_DONE for block=%s peer=%s.%s branches=%s+%s",_SID_(block_id),peer_nm,_SID_(peer_id),self.branches_info,self.peer_branches_info)
            if block_id in self._peers_branches:
                branch = self._peers_branches[block_id]
                if block_id in self._arbitration_msgs:
                    marker = self._arbitration_msgs[block_id]
                    if isinstance(marker, bool) :
                        LOGGER.debug("GET ARBITRATION MARKER=%s for block=%s",marker,_SID_(block_id))
                        del self._arbitration_msgs[block_id]
                        self._arbitration_msgs[block_id] = (block,peer_id)

                branch.arbitration_done(block,peer_id,seal)
                
            
