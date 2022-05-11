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

import ctypes
import logging
from enum import IntEnum
from dgt_validator.consensus.proxy import UnknownBlock

LOGGER = logging.getLogger(__name__)

#from dgt_validator.ffi import OwnedPointer
from dgt_validator.protobuf.block_pb2 import Block
#from dgt_validator import ffi


class MissingPredecessor(Exception):
    pass


class MissingPredecessorInBranch(Exception):
    pass


class MissingInput(Exception):
    pass

"""
class UnknownBlock(Exception):
    pass


class ErrorCode(IntEnum):
    Success = 0
    NullPointerProvided = 0x01
    MissingPredecessor = 0x02
    MissingPredecessorInBranch = 0x03
    MissingInput = 0x04
    UnknownBlock = 0x05
    InvalidInputString = 0x06
    Error = 0x07
    InvalidPythonObject = 0x0F
    StopIteration = 0x11


class _PutEntry(ctypes.Structure):
    _fields_ = [('block_bytes', ctypes.c_char_p),
                ('block_bytes_len', ctypes.c_size_t)]

    @staticmethod
    def new(block_bytes):
        return _PutEntry(
            block_bytes,
            len(block_bytes)
        )
"""

class ManagedBlock(object):
        def __init__(self, value):
            self.value = value.SerializeToString()
            #self.timestamp = time.time()  # the time this State was created,
            # used for house keeping, ie when to flush this from the cache.
            self._count = 0

        @property
        def cnt(self):
            return self._count

        def touch(self):
            """
            Mark this entry as accessed.
            """
            pass #self.timestamp = time.time()

        def inc_count(self):
            self._count += 1
            self.touch()

        def dec_count(self):
            if self._count > 0:
                self._count -= 1
            self.touch()

class BlockManager():

    def __init__(self):
        self.pointer = 1 # this is fake pointer
        LOGGER.debug("BlockManager: __init__")
            
    def add_store(self, name, block_store):
        """
        _pylibexec("block_manager_add_store",
                   self.pointer,
                   ctypes.c_char_p(name.encode()),
                   ctypes.py_object(block_store))
        """
        self._name = name
        self._block_store = {} # block_store if block_store is not None else {} 
        LOGGER.debug("BlockManager: add_store name=%s",name)

    def put(self, branch):
        """
        c_put_items = (ctypes.POINTER(_PutEntry) * len(branch))()
        for (i, block) in enumerate(branch):
            c_put_items[i] = ctypes.pointer(_PutEntry.new(
                block.SerializeToString(),
            ))
        """
        for (i, block) in enumerate(branch): 
            LOGGER.debug("BlockManager: put[%s] block_id=%s total=%s",i,block.header_signature[:8],len(self._block_store))
            self._block_store[block.header_signature] = ManagedBlock(block)
        """
        _libexec("block_manager_put",
                 self.pointer,
                 c_put_items, ctypes.c_size_t(len(branch)))
        """

    # Raises UnknownBlock if the block is not found
    def ref_block(self, block_id):
        """
        use for keeping block until it's need 
        mark parent block of new block 
        """
        #LOGGER.debug("BlockManager: ref_block block_id=%s",block_id[:8])
        if block_id in self._block_store:
            mblk = self._block_store[block_id] 
            mblk.inc_count()
            LOGGER.debug("BlockManager: ref_block contain block_id=%s ref=%s",block_id[:8],mblk.cnt)
        else:
            LOGGER.debug("BlockManager: ref_block UnknownBlock block_id=%s",block_id[:8])
            raise UnknownBlock
        """
        _libexec(
            "block_manager_ref_block",
            self.pointer,
            ctypes.c_char_p(block_id.encode()))
        """
        #self._block = self._block_store._get_block(block_id)
        #LOGGER.debug("BlockManager: ref_block block=(%s)",self._block) 

    # Raises UnknownBlock if the block is not found
    def unref_block(self, block_id):
        """
        mark block as could be free
        """
        #LOGGER.debug("BlockManager: unref_block block_id=%s",block_id[:8])
        if block_id in self._block_store:
            mblk = self._block_store[block_id] 
            mblk.dec_count()
            LOGGER.debug("BlockManager: unref_block contain block_id=%s ref=%s",block_id[:8],mblk.cnt)
        else:
            LOGGER.debug("BlockManager: unref_block UnknownBlock block_id=%s",block_id[:8])
            raise UnknownBlock

        
    def persist(self, block_id, store_name):
        LOGGER.debug("BlockManager: persist block_id=%s  store_name=%s",block_id,store_name)
        """
        _libexec("block_manager_persist",
                 self.pointer,
                 ctypes.c_char_p(block_id.encode()),
                 ctypes.c_char_p(store_name.encode()))
        """
    def __contains__(self, block_id):
        LOGGER.debug("BlockManager: __contains__ block_id=%s",block_id[:8])
        #contains = ctypes.c_bool(True)
        contains = True if block_id in self._block_store else False
        
        return contains

    def get(self, block_ids):
        #LOGGER.debug("BlockManager: get block_ids=%s",block_ids)
        return _GetBlockIterator(block_ids,self._block_store)

    def branch(self, tip):
        LOGGER.debug("BlockManager: branch tip=%s",tip)
        return _BranchIterator(self.pointer, tip)

    def branch_diff(self, tip, exclude):
        LOGGER.debug("BlockManager: branch_diff tip=%s",tip)
        return _BranchDiffIterator(self.pointer, tip, exclude)

"""
def _libexec(name, *args):
    return _exec(ffi.LIBRARY, name, *args)


def _pylibexec(name, *args):
    return _exec(ffi.PY_LIBRARY, name, *args)


def _exec(library, name, *args):
    res = library.call(name, *args)
    if res == ErrorCode.Success:
        return

    if res == ErrorCode.NullPointerProvided:
        raise TypeError("Provided null pointer(s)")
    elif res == ErrorCode.StopIteration:
        raise StopIteration()
    elif res == ErrorCode.MissingPredecessor:
        raise MissingPredecessor("Missing predecessor")
    elif res == ErrorCode.MissingPredecessorInBranch:
        raise MissingPredecessorInBranch("Missing predecessor")
    elif res == ErrorCode.MissingInput:
        raise MissingInput("Missing input to put method")
    elif res == ErrorCode.UnknownBlock:
        raise UnknownBlock("Block was unknown")
    elif res == ErrorCode.InvalidInputString:
        raise TypeError("Invalid block store name provided")
    else:
        raise Exception("There was an unknown error: {}".format(res))
"""

class _BlockIterator:

    def __del__(self):
        if self._c_iter_ptr:
            LOGGER.debug("_BlockIterator: __del__ ptr=%s",self._c_iter_ptr)

    def __iter__(self):
        #LOGGER.debug("_BlockIterator: __iter__ ptr=%s ....",self)
        return self

    def __next__(self):
        if not self._c_iter_ptr:
            LOGGER.debug("_BlockIterator: StopIteration ")
            raise StopIteration()
        #LOGGER.debug("_BlockIterator: __next__ ptr=%s",self._c_iter_ptr)
        block_id = next(self._c_iter_ptr)
        #LOGGER.debug("_BlockIterator: next=%s",block_id)
        if block_id in self._block_store:
            mblk = self._block_store[block_id]  
            LOGGER.debug("BlockManager: get block_id=%s ref=%s",block_id[:8],mblk.cnt) 
            block = Block()
            block.ParseFromString(mblk.value)
            if mblk.cnt == 0:
                LOGGER.debug("BlockManager: DEL block_id=%s",block_id[:8])
                del self._block_store[block_id]
        else:
            LOGGER.debug("_BlockIterator:not in store  StopIteration ")
            raise StopIteration()

        return block 


class _GetBlockIterator(_BlockIterator):
    name = "block_manager_get_iterator"
    def __init__(self, block_ids,block_store = None):
        self._c_iter_ptr = iter(block_ids)
        self._block_store = block_store
        #LOGGER.debug("_GetBlockIterator: __init__ block_ids=%s",self._c_iter_ptr)

class _BranchDiffIterator(_BlockIterator):

    name = "block_manager_branch_diff_iterator"

    def __init__(self, block_manager_ptr, tip, exclude):
        LOGGER.debug("_BranchDiffIterator: __init__ block_manager_ptr=%s tip=%s",block_manager_ptr,tip)
        c_tip = ctypes.c_char_p(tip.encode())
        c_exclude = ctypes.c_char_p(exclude.encode())

        self._c_iter_ptr = ctypes.c_void_p()
        """
        _libexec("{}_new".format(self.name),
                 block_manager_ptr,
                 c_tip,
                 c_exclude,
                 ctypes.byref(self._c_iter_ptr))
        """

class _BranchIterator(_BlockIterator):

    name = "block_manager_branch_iterator"

    def __init__(self, block_manager_ptr, tip):

        c_tip = ctypes.c_char_p(tip.encode())

        self._c_iter_ptr = ctypes.c_void_p()
        LOGGER.debug("_BranchIterator: __init__ block_manager_ptr=%s tip=%s",block_manager_ptr,tip)
        """
        _libexec("{}_new".format(self.name),
                 block_manager_ptr,
                 c_tip,
                 ctypes.byref(self._c_iter_ptr))
        """
