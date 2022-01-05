# Copyright 2018 NTRlab
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
from pbft_common.utils import _short_id
LOGGER = logging.getLogger(__name__)

class PendingForks:
    """FIFO backlog of forks that have to be be resolved. If a new block is
    pushed that extends a pending fork, it replaces the parent without the
    parent losing its place in the queue.
    """

    def __init__(self):
        self._queue = []
        self._blocks = {}

    def push(self, block):
        try:
            index = self._queue.index(block.previous_id)
        except ValueError:
            self._queue.insert(0, block.block_id)
            self._blocks[block.block_id] = block
            LOGGER.debug('PendingForks PUSH block_id=%s',_short_id(block.block_id.hex()))
            return
        try:
            del self._blocks[block.previous_id]
            LOGGER.debug('PendingForks DEL block_id=%s',_short_id(block.previous_id.hex()))
        except KeyError:
            pass
        LOGGER.debug('PendingForks PUSH  block_id=%s INSTEAD prev',_short_id(block.block_id.hex()))
        self._queue[index] = block.block_id
        self._blocks[block.block_id] = block

    def pop(self):
        try:
            block_id = self._queue.pop()
        except IndexError:
            return None

        block = self._blocks.pop(block_id)
        return block
    def __str__(self):
        return "PENDING blocks={}->{}".format([bid.hex()[:8] for bid in self._queue],[bid.hex()[:8] for bid in self._blocks.keys()])
