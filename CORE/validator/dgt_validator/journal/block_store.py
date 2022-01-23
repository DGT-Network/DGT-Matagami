# Copyright 2019 DGT NETWORK INC © Stanislav Parsov 
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

# pylint: disable=no-name-in-module
import logging
import timeit
import hashlib
# for save graph of DAG
#from graphviz import Digraph

from collections.abc import MutableMapping

from dgt_validator.journal.block_wrapper import BlockStatus
from dgt_validator.journal.block_wrapper import BlockWrapper
from dgt_validator.protobuf.block_pb2 import Block
from dgt_validator.state.merkle import MerkleDatabase,INIT_ROOT_KEY
LOGGER = logging.getLogger(__name__)

FEDERATION_NUM = 0
FEDERATION_MAX = 100
def static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate

@static_vars(NUM=0)
class Federation(object):
    
    """
    for block_num generation 
    """
    def __init__(self, colour,store):
        Federation.NUM += 1
        self._colour = colour
        self._store = store
        self._feder_num = Federation.NUM
        #self._num = 0               # separated from others cluster blocks numeration
        self._last_num = -1          # separated from others cluster blocks numeration
        self._block_nums  = {}      # for DAG - list of reserved block candidate number and signers for it  
        self._free_block_nums  = [] # for DAG - list of free block number's
        LOGGER.debug("NEW FEDERATION=%s.%s",self._feder_num,colour)

    @property
    def feder_num(self):
        return self._feder_num

    @property
    def block_nums(self):
        return self._block_nums

    @staticmethod
    def coloured_num(fnum,bnum):
        return int(str(fnum)+str(bnum)) 

    @staticmethod
    def feder_num_to_num(block_num):
        snum = str(block_num)
        num = int(snum[1:]) if snum[1:] != '' else -1 # genesis num
        fnum = int(snum[0:1])    
        return fnum,num

    @staticmethod
    def dec_feder_num(block_num):
        fnum,num = Federation.feder_num_to_num(block_num)
        if num <= 0:
            return str(0)
        return str(fnum)+str(num-1)

    @staticmethod
    def inc_feder_num(block_num):
        fnum,num = Federation.feder_num_to_num(block_num)
        return str(fnum)+str(num+1)

    @staticmethod
    def is_diff_feder(fnum,fnum1):
        fn,_ = Federation.feder_num_to_num(fnum)
        fn1,_ = Federation.feder_num_to_num(fnum1)
        rt = fn != fn1 and fn > 0 and fn1 > 0
        LOGGER.debug("IS_DIFF_FEDER %s~%s rt=%s",fnum,fnum1,rt)
        return rt

    def gap_feder_num(prev_num,block_num):
        pfnum,pnum = Federation.feder_num_to_num(prev_num)
        fnum,num = Federation.feder_num_to_num(block_num)
        if pfnum != fnum:
            # difference federation - say there is a gap
            return 2
        return pnum - num 

    def update_head(self,num):
        if num > self._last_num:
            self._last_num = num
            LOGGER.debug("NEW HEAD=%s INTO FEDERATION=%s.%s",num,self._feder_num,self._colour)
        else:
            LOGGER.debug("COMMIT HEAD=%s INTO FEDERATION=%s.%s LAST=%s",num,self._feder_num,self._colour,self._last_num)

    def get_block_num(self,signer):
        """
        get block number 
        take last fixed head and use his number
        BUT FOR FEDERATION mode we should take last fixed block for federation 
        """
        block_num = self._last_num + 1
        LOGGER.debug("FIND from last num=%s",block_num)
        while block_num in self._block_nums:
            peers = self._block_nums[block_num]
            if signer not in peers:
                # other peer already make block with this number and we can use this num too
                # stop and add own key into peers for this num
                break
            # already reserved by some branch try take next number
            block_num += 1
        return block_num

    def get_internal_num(self,coloured):
        return int(str(coloured)[1:])

    def make_coloured_num(self,block_num):
        return int(str(self._feder_num)+str(block_num))

    def get_free_block_num(self,parent_num):
        LOGGER.debug("Feder=%s block_nums=%s free=%s for=%s",self._colour,self._block_nums,sorted(self._free_block_nums),parent_num)
        if len(self._free_block_nums) > 0:
            """
            for new federation _free_block_nums will be empty 
            not new federation can connect only into the same federation
            """
            pnum = self.get_internal_num(parent_num)
            if max(self._free_block_nums) > pnum:
                
                for num in sorted(self._free_block_nums):
                    if num > pnum:
                        # there is free number more then parent number
                        self._free_block_nums.remove(num)
                        colour_num = self.make_coloured_num(num)
                        LOGGER.debug("USE num=%s coloured=%d free=%s",num,colour_num,self._free_block_nums)
                        return colour_num

        return None

    def ref_block_number(self,block_num,signer):
        # for external Block  make ref for block num - this block can appeared before we allocate this number
        # in this case block_num is not coloured yet
        if block_num in self._block_nums:
            peers = self._block_nums[block_num]
        else:
            peers = []
            self._block_nums[block_num] = peers

        peers.append(signer)
        colour_num = self.make_coloured_num(block_num) 
        LOGGER.debug("REF block number=%s coloured=%s signer=%s nums=%s",block_num,colour_num,signer[:8],self._block_nums)
        return colour_num

    def pop_block_number(self,block_num,signer,force=False):
        """
        for external Block pop too because we make ref for external block
        drop signer from list
        """
        if block_num in self._block_nums:
            if force:
                del self._block_nums[block_num]
            else:
                peers = self._block_nums[block_num]
                if signer in peers:
                    peers.remove(signer)
                    LOGGER.debug("POP block number=%s drop signer=%s",block_num,signer[:8])
                if len(peers) == 0:
                    del self._block_nums[block_num]
            LOGGER.debug("POP force=%s block number=%s sig=%s nums=%s",force,block_num,signer[:8],self._block_nums) # [key for key in self._block_nums.keys()]

    def free_block_number(self,block_num,signer):
        # free block number - because block was not validated
        # block_num is coloured here
        
        if block_num < self._last_num:
            # put into free block num list
            self._free_block_nums.append(block_num)
            LOGGER.debug("FREE block number=%s free=%s",block_num,self._free_block_nums)

    @property
    def last_num(self):
        return self._last_num
    @property
    def last_feder_num(self):
        if self.last_num < 0:
            return 0 if self.feder_num == 1 else -1 
        return self.make_coloured_num(self.last_num)

class BlockStore(MutableMapping):
    """
    A dict like interface wrapper around the block store to guarantee,
    objects are correctly wrapped and unwrapped as they are stored and
    retrieved.
    """

    def __init__(self, block_db):
        self._block_store = block_db
        self._federations = {}
        self._num2federations = {}
        self._chain_heads = {} # for DAG
        self._is_recovery = False
        self._is_nest_ready = True
        self._recover_feder_nums = {}
        self._max_feder_nums = {}

        #self._block_nums  = {} # for DAG - list of reserved block candidate number and signers for it  
        #self._free_block_nums  = [] # for DAG - list of free block number's 
        chead = self.chain_head
        if chead is not None :
            # start in recovery mode 
            LOGGER.debug("BlockStore: check DAG database (head=%s)\n",chead)
            self.make_federation_nests()

    def __setitem__(self, key, value):
        if key != value.identifier:
            raise KeyError("Invalid key to store block under: {} expected {}".format(key, value.identifier))
        self._block_store.put(key, value)

    def __getitem__(self, key):
        return self._get_block(key)

    def __delitem__(self, key):
        del self._block_store[key]

    def __contains__(self, x):
        return x in self._block_store

    def __iter__(self):
        
        return self.get_block_iter()

    def __len__(self):
        # Required by abstract base class, but implementing is non-trivial
        raise NotImplementedError('BlockStore has no meaningful length')

    def __str__(self):
        out = []
        for key in self._block_store.keys():
            value = self._block_store[key]
            out.append(str(value))
        return ','.join(out)

    @property
    def is_recovery(self):
        return self._is_recovery

    def get_recovery_mode(self):
        return self.is_recovery

    def block_recovered(self,blk_id):
        if self._recovery_num > 0:
            self._recovery_num -= 1

    def set_nests_ready(self):
        self._is_nest_ready = True

    def get_recovery_block(self,nest):
        def inc_bnum(fnum,block_num):
            _,bnum = Federation.feder_num_to_num(block_num)                                 
            if bnum != self._max_feder_nums[fnum]:                               
                next_num = Federation.inc_feder_num(block_num)                              
                self._recover_feder_nums[fnum] = int(next_num)                   
            else:                                                                           
                # stop for this federation and start for next                               
                del self._recover_feder_nums[fnum]
                next_num = None  
                                             
        feder = self._federations[nest]
        if feder.feder_num in self._recover_feder_nums:
            if feder.feder_num > 1 and not self._is_nest_ready:
                return None
            block_num = self._recover_feder_nums[feder.feder_num]
            next_num  = inc_bnum(feder.feder_num,block_num)
            LOGGER.debug("get_recovery_block for NEST[%s]=%s BLOCK=%s->%s recovered=%d",feder.feder_num,nest,block_num,next_num,self._recovery_num)
            return [self.get_block_by_number(block_num)]
        else:
            if self._is_recovery :
                LOGGER.debug("get_recovery_block STOP nest_ready=%s recover=%s recovered=%d",self._is_nest_ready,self._recover_feder_nums,self._recovery_num)
                if len(self._recover_feder_nums) == 1:
                    # remain only genesis block - recovery completed but we should control it into chain
                    # 
                    if self._recovery_num == 1:
                        self._is_recovery = False
                        LOGGER.debug("remain only genesis block - recovery completed")
                    else:
                        LOGGER.debug("Remain only genesis block but not all blocks from recovery list were completed")
                    return None
                
                if feder.feder_num == 1:
                    # add first blocks from other federation into chain controller
                    blks = []
                    for fnum,block_num in list(self._recover_feder_nums.items()):
                        if fnum > 0:
                            inc_bnum(fnum,block_num)
                            blks.append(self.get_block_by_number(block_num))
                    return blks if len(blks) > 0 else None
                #
        return None

    def make_federation_nests(self):
        """
        check DAG intergity and make federation
        """
        self._is_recovery = True
        self._is_nest_ready = False
        bad_block = []
        block_nums = [-1 for i in range(FEDERATION_MAX)]
        self._max_feder_nums = {}
        num = 0
        start = timeit.default_timer()
        
        for blk in self:
            LOGGER.debug("check BLK=%s.%s",blk.block_num,blk.identifier[:8])
            num += 1
            err = ''
            if blk.block_num != 0 and blk.previous_block_id not in self:
                err = 'prev,'
            #feder,fnum = self.get_feder_num(blk.block_num)
            fnum,bnum = Federation.feder_num_to_num(blk.block_num)
            if fnum in self._max_feder_nums:
                if bnum > self._max_feder_nums[fnum]:
                    self._max_feder_nums[fnum] = bnum
            else:
                self._max_feder_nums[fnum] = bnum

            # skip genesis block
            block_num = block_nums[fnum] # previous block num into this federation 
            if block_num != -1 and block_num != bnum+1:
                # gap between block number
                # check block from blk.block_num+1 < block_num
                gap = range(bnum+1,block_num-1)
                LOGGER.debug("check_integrity GAP=%s",gap)
                skip = 0
                if skip > 0:
                    err += "num({}),".format(skip)

            block_nums[fnum] = bnum

            if err != '':
                bad_block.append("{}.{}:{}".format(blk.block_num,blk.identifier[:8],err))
        spent = timeit.default_timer()-start
        self._recover_feder_nums  = { key : Federation.coloured_num(key,0) for key in self._max_feder_nums }
        self._recovery_num = num
        if len(bad_block) == 0:
            bad_block.append( "correct:checked={} blks spent={}s".format(num,spent))
        else:
            bad_block.append( "bad:checked={} blks spent={}s".format(num,spent))

        LOGGER.debug("make_federation_nests num=%s feder=%s recover=%s spent=%s DONE\n",num,self._max_feder_nums,self._recover_feder_nums,spent)


    @staticmethod
    def create_index_configuration():
        return {
            'batch': BlockStore._batch_index_keys,
            'transaction': BlockStore._transaction_index_keys,
            'block_num': BlockStore._block_num_index_keys,
        }

    @staticmethod
    def deserialize_block(value):
        """
        Deserialize a byte string into a BlockWrapper

        Args:
            value (bytes): the byte string to deserialze

        Returns:
            BlockWrapper: a block wrapper instance
        """
        # Block id strings are stored under batch/txn ids for reference.
        # Only Blocks, not ids or Nones, should be returned by _get_block.
        block = Block()
        block.ParseFromString(value)
        return BlockWrapper(
            status=BlockStatus.Valid,
            block=block)

    @staticmethod
    def serialize_block(blkw):
        """
        Given a block wrapper, produce a byte string

        Args:
            blkw: (:obj:`BlockWrapper`) a block wrapper to serialize

        Returns:
            bytes: the serialized bytes
        """
        return blkw.block.SerializeToString()

    @staticmethod
    def wrap_block(blk):
        return BlockWrapper.wrap(blk)

    def update_chain(self, new_chain, old_chain=None):
        """
        Set the current chain head, does not validate that the block
        store is in a valid state, ie that all the head block and all
        predecessors are in the store.

        :param new_chain: The list of blocks of the new chain.
        :param old_chain: The list of blocks of the existing chain to
            remove from the block store.
        store.
        :return:
        None
        """
        add_pairs = [(blkw.header_signature, blkw) for blkw in new_chain]
        add_block_nums = [blkw.block_num for blkw in new_chain]
        if old_chain:
            del_keys = [blkw.header_signature for blkw in old_chain]
        else:
            del_keys = []

        self._block_store.update(add_pairs, del_keys)
        # update head for federations
        for block_num in add_block_nums:
            feder,num = self.get_feder_num(block_num)
            if feder:
                feder.update_head(num)

    def add_branch(self,block_id,block):
        # for DAG version - add new branch from block with block_id
        self._chain_heads[block_id] = block

    def update_branch(self,hid,new_hid,block,keep=True):
        # for DAG version - update branch to another point
        if hid in self._chain_heads:
            if not keep:
                del self._chain_heads[hid]
            self._chain_heads[new_hid] = block
            LOGGER.debug("BlockStore: update_branch=%s->%s.%s USED=%s heads=%s",hid[:8],block.block_num,new_hid[:8],keep,self._heads_list)

    def update_chain_heads(self,bid,hid,new_block,keep=True):
        #for DAG only - main head not in _chain_heads
        if bid in self._chain_heads:
            if not keep:
                del self._chain_heads[bid]
            self._chain_heads[hid] = new_block # self._chain_heads[new_block.identifier]
            LOGGER.debug("BlockStore: update_chain_heads=%s->%s.%s USED=%s",bid[:8],new_block.block_num,new_block.identifier[:8],keep)
        else:
            # could be for external block
            for key,head in self._chain_heads.items():
                if head.block_num == new_block.block_num:
                    LOGGER.debug("BlockStore: update_chain_heads EXTERNAL del old block=%s.%s",head.block_num,key[:8])
                    del self._chain_heads[key]
                    break
            
            LOGGER.debug("BlockStore: update_chain_heads=%s->%s.%s USED=%s NUM=%s",bid[:8],new_block.block_num,new_block.identifier[:8],keep,len(self._chain_heads))
            self._chain_heads[hid] = new_block

    @property
    def _heads_list(self):
        return [str(head.block_num)+':'+key[:8] for key,head in self._chain_heads.items()]

    def get_chain_head(self,branch_id):
        # for external block there is no chain head
        #if branch_id in self._chain_heads:
        return self._chain_heads[branch_id]
        # take from store 
         

    def get_chain_heads(self,summary=False):
        # for external block there is no chain head
        heads = sorted([str(head.block_num)+':'+key[:8] for key,head in self._chain_heads.items()])
        if summary:
            summary = hashlib.sha256()            
            for head in heads:                    
                summary.update(head.encode())
            LOGGER.debug("BlockStore: heads=%s",heads)         
            return summary.digest().hex() 
        else:
            return heads

    def check_integrity(self):
        """
        check DAG intergity
        """
        bad_block = []
        block_nums = [-1 for i in range(len(self._federations)+1)]
        num = 0
        start = timeit.default_timer()
        """
        FIXME - when we will check block num we should control numbers integrity inside cluster only 1.0 1.1 1.2 ... 2.0 2.1 2.3 
        """
        for blk in self:
            #LOGGER.debug("check_integrity blk=%s prev=%s",blk.block_num,blk.previous_block_id[:8])
            num += 1
            err = ''
            if blk.block_num != 0 and blk.previous_block_id not in self:
                err = 'prev,'
            feder,fnum = self.get_feder_num(blk.block_num)
            if feder:
                # skip genesis block
                block_num = block_nums[feder.feder_num] # previous block num into this federation 
                if block_num != -1 and block_num != fnum+1:
                    # gap between block number
                    # check block from blk.block_num+1 < block_num
                    gap = range(fnum+1,block_num-1)
                    LOGGER.debug("check_integrity GAP=%s NUMS=%s",gap,feder.block_nums)
                    skip = 0
                    for n in gap:
                        # check mayby this number reserved for block candidate
                        if n not in feder.block_nums:
                            skip += 1
                    if skip > 0:
                        err += "num({}),".format(skip)

                block_nums[feder.feder_num] = fnum

            if err != '':
                bad_block.append("{}.{}:{}".format(blk.block_num,blk.identifier[:8],err))
        spent = timeit.default_timer()-start
        if len(bad_block) == 0:
            bad_block.append( "correct:checked={} blks spent={}s".format(num,spent))
        else:
            bad_block.append( "bad:checked={} blks spent={}s".format(num,spent))
        LOGGER.debug("check_integrity num=%s spent=%s DONE\n",num,spent)
        return bad_block

    def get_graph(self):
        bad_block = ['save']
        LOGGER.debug("get_graph DONE\n")
        fed_colour = ['white','yellow','green','blue','grey','red','darkcyan','teal']
        gv = open('DAG.gv', 'w')
        gv.write("digraph DAG {\n")
        #gv.write('node [style="filled", fillcolor="yellow", fontcolor="black", margin="0.01"]')
        prev = None
        prev_num = None
        feder_num = -1
        for blk in self:
            prev = blk.previous_block_id[:8] 
            feder,fnum = self.get_feder_num(blk.block_num)
            prev_num = self._get_block(blk.previous_block_id).block_num if blk.previous_block_id in self else -1
            
            if feder :
                if feder.feder_num != feder_num:
                    if feder_num != -1:
                        gv.write('}\n')
                    gv.write('{\n node [style="filled", fillcolor="'+fed_colour[feder.feder_num]+'", fontcolor="black", margin="0.01"]')
                    feder_num = feder.feder_num
            else:
                gv.write('}\n')
            if prev_num == -1:
                gv.write('"{}.{}" -> "{}";\n'.format(blk.block_num,blk.identifier[:8],prev))
            else:
                gv.write('"{}.{}" -> "{}.{}";\n'.format(blk.block_num,blk.identifier[:8],prev_num,prev)) 
            """
            if feder :
                LOGGER.debug("feder=%s nums=%s\n",feder.feder_num,feder.block_nums)
                if fnum in feder.block_nums:
                    # add nest marker
                    gv.write('"{}" -> "{}";\n'.format(fnum,blk.identifier[:8])) 

            """    


        gv.write('"{}" [fillcolor="red",shape="circle"];\n'.format(prev))         
        gv.write("}\n")
        gv.close()

    @property
    def chain_heads(self):
        return self._chain_heads

    @property
    def chain_head(self):
        """
        Return the head block of the current chain. LAST FIXED in database
        for DAG return last from sorted node's list
        """
        with self._block_store.cursor(index='block_num') as curs:
            curs.last()
            return curs.value()

    @property
    def federation_heads(self):
        feder_heads =[]
        for colour,feder in self._federations.items():
            LOGGER.debug("federation_heads colour=%s head=%s",colour,feder.last_feder_num) 
            if feder.last_feder_num >= 0:
                # add into head list
                feder_heads.append(self.get_block_by_number(feder.last_feder_num))
        return feder_heads

    def has_federation(self,block_num):
        feder,num = self.get_feder_num(block_num)
        return (feder is not None or block_num == 0)
    
    def get_block_num(self,parent_num,signer,colour):
        """
        for DAG version
        Return the last head block of sorted graph and reserve this number because others branch can ask this number
        FOR federation mode use federation color 
        parent_num - already coloured
        """
        if colour not in self._federations:
            # new federation
            feder = Federation(colour,self)
            self._federations[colour] = feder
            self._num2federations[feder.feder_num] = feder
        else:
            feder = self._federations[colour]

        
        num = feder.get_free_block_num(parent_num)
        if num:
            return num

        """
        take last fixed head and use his number
        BUT FOR FEDERATION mode we should take last fixed block for federation 
        """
        num = feder.get_block_num(signer)
        """
        add into reserved list  - taken by candidate for current federation
        and return coloured num
        """
        block_num = feder.ref_block_number(num,signer)
        return block_num

    def pop_block_number(self,block_num,signer,force=False):
        # for external Block pop too because we make ref for external block
        # drop signer from list
        feder,num = self.get_feder_num(block_num)
        if feder:
            feder.pop_block_number(num,signer,force)
       

    def get_feder_num(self,block_num):
        # get federation and block num into it
        # now only one position for federation so only 9 maximum 
        fnum,num = Federation.feder_num_to_num(block_num)
        """
        snum = str(block_num)
        num = int(snum[1:]) if snum[1:] != '' else -1 # genesis num
        fnum = int(snum[0:1])
        """
        if fnum in self._num2federations:
            return self._num2federations[fnum],num 
        
        return None,num

    def ref_block_number(self,block_num,signer):
        """
        for external Block  make ref for block num
        block_num is coloured here
        """
        feder,num = self.get_feder_num(block_num)
        if feder:
            feder.ref_block_number(num,signer)
        

    def free_block_number(self,block_num,signer):
        # free block number - because block was not validated
        # block_num is coloured here
        feder,num = self.get_feder_num(block_num)
        if feder:
            feder.pop_block_number(num,signer)
            feder.free_block_number(num,signer)
        """
        head = self.chain_head
        if block_num < head.block_num + 1:
            # put into free block num list
            self._free_block_nums.append(block_num)
            LOGGER.debug("FREE block number=%s free=%s",block_num,self._free_block_nums)
        """

    def set_global_state_db(self,global_state_db):
        # for DAG - use mercle database for getting root state
        self._global_state_db = global_state_db

    def chain_head_state_root(self):
        """
        Return the state hash of the head block of the current chain.
        FIXME - for DAG use real merkle root state
        """
        chain_head = self.chain_head
        if chain_head is not None:
            return MerkleDatabase.get_real_merkle_root(self._global_state_db)
            #return chain_head.state_root_hash
        return INIT_ROOT_KEY

    @property
    def store(self):
        """
        Access to the underlying store.
        """
        return self._block_store

    def get_predecessor_iter(self, starting_block=None):
        """Returns an iterator that traverses block via its predecesssors.

        Args:
            starting_block (:obj:`BlockWrapper`): the block from which
                traversal begins

        Returns:
            An iterator of block wrappers
        """
        return self.get_block_iter(start_block=starting_block)

    def get_block_iter(self, start_block=None, start_block_num=None,reverse=True):
        """Returns an iterator that traverses blocks in block number order.

        Args:
            start_block (:obj:`BlockWrapper`): the block from which traversal
                begins
            start_block_num (str): a starting block number, in hex, from where
                traversal begins; only used if no starting_block is provided

            reverse (bool): If True, traverse the blocks in from most recent
                to oldest block. Otherwise, it traverse the blocks in the
                opposite order.

        Returns:
            An iterator of block wrappers

        Raises:
            ValueError: If start_block or start_block_num do not specify a
                valid block
        """
        #LOGGER.debug("BlockStore: get_block_iter...")
        with self._block_store.cursor(index='block_num') as curs:
            if start_block:
                start_block_num = BlockStore.block_num_to_hex(start_block.block_num)
                if not curs.seek(start_block_num):
                    raise ValueError('block {} is not a valid block'.format(start_block))
            elif start_block_num:
                if not curs.seek(start_block_num):
                    raise ValueError('Block number {} does not reference a valid block'.format(start_block_num))

            iterator = None
            if reverse:
                iterator = curs.iter_rev()
            else:
                iterator = curs.iter()

            for block in iterator:
                yield block

    @staticmethod
    def _batch_index_keys(block):
        blkw = BlockWrapper.wrap(block)
        return [batch.header_signature.encode()
                for batch in blkw.batches]

    @staticmethod
    def _transaction_index_keys(block):
        blkw = BlockWrapper.wrap(block)
        keys = []
        for batch in blkw.batches:
            for txn in batch.transactions:
                keys.append(txn.header_signature.encode())
        return keys

    @staticmethod
    def _block_num_index_keys(block):
        blkw = BlockWrapper.wrap(block)
        # Format the number to a 64bit hex value, for natural ordering
        return [BlockStore.block_num_to_hex(blkw.block_num).encode()]

    @staticmethod
    def block_num_to_hex(block_num):
        """Converts a block number to a hex string.
        This is used for proper index ordering and lookup.

        Args:
            block_num: uint64

        Returns:
            A hex-encoded str
        """
        return "{0:#0{1}x}".format(block_num, 18)

    def _get_block(self, key):
        value = self._block_store.get(key)
        if value is None:
            raise KeyError('Block "{}" not found in store'.format(key))

        return BlockWrapper.wrap(value)

    def get_blocks(self, block_ids):
        """Returns all blocks with the given set of block_ids.
        If a block id in the provided iterable does not exist in the block
        store, it is ignored.

        Args:
            block_ids (:iterable:str): an iterable of block ids

        Returns
            list of block wrappers found for the given block ids
        """
        return [block for _, block in self._block_store.get_multi(block_ids)]

    def get_block_by_transaction_id(self, txn_id):
        """Returns the block that contains the given transaction id.

        Args:
            txn_id (str): a transaction id

        Returns:
            a block wrapper of the containing block

        Raises:
            ValueError if no block containing the transaction is found
        """
        block = self._block_store.get(txn_id, index='transaction')
        if not block:
            raise ValueError(
                'Transaction "{}" not in BlockStore'.format(txn_id))

        return block

    def get_block_by_number(self, block_num):
        """Returns the block that contains the given transaction id.

        Args:
            block_num (uint64): a block number

        Returns:
            a block wrapper of the containing block

        Raises:
            KeyError if no block with the given number is found
        """
        block = self._block_store.get(
            BlockStore.block_num_to_hex(block_num), index='block_num')
        if not block:
            raise KeyError(
                'Block number "{}" not in BlockStore'.format(block_num))

        return block

    def has_transaction(self, txn_id):
        """Returns True if the transaction is contained in a block in the
        block store.

        Args:
            txn_id (str): a transaction id

        Returns:
            True if it is contained in a committed block, False otherwise
        """
        return self._block_store.contains_key(txn_id, index='transaction')

    def get_block_by_batch_id(self, batch_id):
        """Returns the block that contains the given batch id.

        Args:
            batch_id (str): a batch id

        Returns:
            a block wrapper of the containing block

        Raises:
            ValueError if no block containing the batch is found
        """
        block = self._block_store.get(batch_id, index='batch')
        if not block:
            raise ValueError('Batch "{}" not in BlockStore'.format(batch_id))

        return block

    def get_blocks_by_batch_ids(self, batch_ids):
        """Returns the block that contains the given batch id.

        Args:
            batch_id (str): a batch id

        Returns:
            a block wrapper of the containing block

        Raises:
            ValueError if no block containing the batch is found
        """
        return self._block_store.get_multi(batch_ids, index='batch')

    def has_batch(self, batch_id):
        """Returns True if the batch is contained in a block in the
        block store.

        Args:
            batch_id (str): a batch id

        Returns:
            True if it is contained in a committed block, False otherwise
        """
        return self._block_store.contains_key(batch_id, index='batch')

    def get_batch_by_transaction(self, transaction_id):
        """
        Check to see if the requested transaction_id is in the current chain.
        If so, find the batch that has the transaction referenced by the
        transaction_id and return the batch. This is done by finding the block
        and searching for the batch.

        :param transaction_id (string): The id of the transaction that is being
            requested.
        :return:
        The batch that has the transaction.
        """
        block = self.get_block_by_transaction_id(transaction_id)
        if block is None:
            return None
        # Find batch in block
        for batch in block.batches:
            for txn in batch.transactions:
                if txn.header_signature == transaction_id:
                    return batch
        return None

    def get_batch(self, batch_id):
        """
        Check to see if the requested batch_id is in the current chain. If so,
        find the batch with the batch_id and return it. This is done by
        finding the block and searching for the batch.

        :param batch_id (string): The id of the batch requested.
        :return:
        The batch with the batch_id.
        """
        block = self.get_block_by_batch_id(batch_id)
        return BlockStore._get_batch_from_block(block, batch_id)

    def get_batches(self, batch_ids):
        """Returns a list of committed batches from a iterable of batch ids.
        Any batch id that does not exist in a committed block is ignored.

        Args:
            batch_ids (:iterable:str): the batch ids to find

        Returns:
            A list of the batches found by the given batch ids
        """
        blocks = self._block_store.get_multi(batch_ids, index='batch')

        return [
            BlockStore._get_batch_from_block(block, batch_id)
            for batch_id, block in blocks
        ]

    @staticmethod
    def _get_batch_from_block(block, batch_id):
        for batch in block.batches:
            if batch.header_signature == batch_id:
                return batch

        raise ValueError(
            'Batch {} not in block {}: possible index mismatch'.format(
                batch_id, block.identifier))

    def get_transaction(self, transaction_id):
        """Returns a Transaction object from the block store by its id.

        Params:
            transaction_id (str): The header_signature of the desired txn

        Returns:
            Transaction: The specified transaction

        Raises:
            ValueError: The transaction is not in the block store
        """
        block = self.get_block_by_transaction_id(transaction_id)
        return BlockStore._get_txn_from_block(block, transaction_id)

    def get_transactions(self, transaction_ids):
        blocks = self._block_store.get_multi(transaction_ids,
                                             index='transaction')

        return [
            BlockStore._get_txn_from_block(block, txn_id)
            for txn_id, block in blocks
        ]

    @staticmethod
    def _get_txn_from_block(block, txn_id):
        for batch in block.batches:
            for txn in batch.transactions:
                if txn.header_signature == txn_id:
                    return txn

        raise ValueError(
            'Transaction {} not in block {}: possible index mismatch'.format(
                txn_id, block.identifier))
