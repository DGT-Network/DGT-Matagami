# Copyright DGT NETWORK INC  2019
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

from abc import ABCMeta
from abc import abstractmethod
import logging
import queue
import time
from threading import RLock

from dgt_validator.concurrent.thread import InstrumentedThread
from dgt_validator.concurrent.threadpool import InstrumentedThreadPoolExecutor
from dgt_validator.journal.block_wrapper import BlockStatus
from dgt_validator.journal.block_wrapper import BlockWrapper
from dgt_validator.journal.block_wrapper import NULL_BLOCK_IDENTIFIER
from dgt_validator.journal.consensus.consensus_factory import ConsensusFactory
from dgt_validator.journal.chain_commit_state import ChainCommitState
from dgt_validator.journal.validation_rule_enforcer import ValidationRuleEnforcer
from dgt_validator.state.settings_view import SettingsViewFactory
from dgt_validator.protobuf.transaction_pb2 import TransactionHeader
from dgt_validator.protobuf.transaction_receipt_pb2 import TransactionReceipt
from dgt_validator.metrics.wrappers import CounterWrapper
from dgt_validator.metrics.wrappers import GaugeWrapper

from dgt_validator.state.merkle import INIT_ROOT_KEY
from dgt_validator.protobuf.block_pb2 import Block
from dgt_validator.consensus.proxy import UnknownBlock,TooManyBranch,BlockIsProcessedNow
from dgt_validator.journal.block_store import Federation

LOGGER = logging.getLogger(__name__)

MAX_DAG_BRANCH = 3 # for DAG 
PEERS_NUM      = 3 # threads for peers  
GENESIS_FEDERATION_BLOCK = 10

class BlockValidationAborted(Exception):
    """
    Indication that the validation of this fork has terminated for an
    expected(handled) case and that the processing should exit.
    """
    pass


class ChainHeadUpdated(Exception):
    """ Raised when a chain head changed event is detected and we need to abort
    processing and restart processing with the new chain head.
    """


class InvalidBatch(Exception):
    """ Raised when a batch fails validation as a signal to reject the
    block.
    """
    pass


# pylint: disable=stop-iteration-return
def look_ahead(iterable):
    """Pass through all values from the given iterable, augmented by the
    information if there are more values to come after the current one
    (True), or if it is the last value (False).
    """
    # Get an iterator and pull the first value.
    it = iter(iterable)
    last = next(it)
    # Run the iterator to exhaustion (starting from the second value).
    for val in it:
        # Report the *previous* value (more to come).
        yield last, True
        last = val
    # Report the last value.
    yield last, False


class BlockValidator(object):
    """
    Responsible for validating a block, handles both chain extensions and fork
    will determine if the new block should be the head of the chain and return
    the information necessary to do the switch if necessary.
    """

    def __init__(self,
                 consensus_module,
                 block_cache,
                 new_block,
                 state_view_factory,
                 done_cb,
                 executor,
                 get_recompute_context,
                 belong_cluster,
                 is_sync,
                 squash_handler,
                 context_handlers,
                 identity_signer,
                 data_dir,
                 config_dir,
                 permission_verifier,
                 metrics_registry=None,
                 block_manager=None,
                 merkle_lock=None):
        """Initialize the BlockValidator
        Args:
             consensus_module: The consensus module that contains
             implementation of the consensus algorithm to use for block
             validation.
             block_cache: The cache of all recent blocks and the processing
             state associated with them.
             new_block: The block to validate.
             state_view_factory: The factory object to create.
             done_cb: The method to call when block validation completed
             executor: The thread pool to process block validations.
             squash_handler: A parameter passed when creating transaction
             schedulers.
             identity_signer: A cryptographic signer for signing blocks.
             data_dir: Path to location where persistent data for the
             consensus module can be stored.
             config_dir: Path to location where config data for the
             consensus module can be found.
        Returns:
            None
        """
        self._consensus_module = consensus_module
        self._block_manager = block_manager
        self._verifier = None      # for proxy only
        self._fork_resolver = None # for proxy only
        self._block_cache = block_cache
        self._block_store = self._block_cache.block_store
        self._chain_commit_state = ChainCommitState(self._block_store, [])
        self._new_block = new_block
        
        # Set during execution of the of the  BlockValidation to the current
        # chain_head at that time.
        self._chain_head = None

        self._state_view_factory = state_view_factory
        self._done_cb = done_cb
        self._executor = executor
        # for external block recompute_context == None
        self._get_recompute_context = get_recompute_context
        self._belong_cluster = belong_cluster
        self._is_sync = is_sync
        self._squash_handler = squash_handler
        self._context_handlers = context_handlers 
        self._check_merkle = context_handlers['check_merkle']
        self._get_merkle_root = context_handlers['merkle_root']
        self._update_state_hash = context_handlers['update_state']
        self._merkle_lock = merkle_lock
        self._identity_signer = identity_signer
        self._validator_id = self._identity_signer.get_public_key().as_hex()
        self._data_dir = data_dir
        self._config_dir = config_dir
        self._result = {
            'new_block': new_block,
            'chain_head': None ,  # start with this head
            'new_chain': [],
            'cur_chain': [],
            'committed_batches': [],
            'uncommitted_batches': [],
            'num_transactions': 0
        }
        LOGGER.debug('BlockValidator: init new block=%s.%s signer=%s parent=%s IS_SYNC=%s',new_block.block_num,new_block.identifier[:8],self._validator_id[:8],self.previous_block_id[:8],self._is_sync)
        self._permission_verifier = permission_verifier

        self._validation_rule_enforcer = ValidationRuleEnforcer(SettingsViewFactory(state_view_factory))

        if metrics_registry:
            self._moved_to_fork_count = CounterWrapper(metrics_registry.counter('chain.BlockValidator.chain_head_moved_to_fork_count'))
        else:
            self._moved_to_fork_count = CounterWrapper()

    @property
    def previous_block_id(self):
        return self._new_block.previous_block_id
    @property
    def identifier(self):
        return self._new_block.identifier

    def _get_previous_block_root_state_hash(self, blkw):
        if blkw.previous_block_id == NULL_BLOCK_IDENTIFIER:
            return INIT_ROOT_KEY
        """
        for DAG use last root state fixed in the merkle
        because self._block_cache[blkw.previous_block_id].state_root_hash could be not correct 
        because of concurrence block with max number could has not last merkle root, so take root from merkle directly
        """
        main_head = self._block_store.chain_head
        state_root_hash = self._get_merkle_root()
        LOGGER.debug('BlockValidator: get block root state for BLOCK=%s STATE=%s:%s REAL=%s\n',blkw.identifier[:8],main_head.block_num,main_head.state_root_hash[:10],state_root_hash[:10])
        return state_root_hash #main_head.state_root_hash
        #return self._block_cache[blkw.previous_block_id].state_root_hash

    def _txn_header(self, txn):
        txn_hdr = TransactionHeader()
        txn_hdr.ParseFromString(txn.header)
        return txn_hdr

    def _verify_batch_transactions(self, batch,persist=True):
        """Verify that all transactions in are unique and that all
        transactions dependencies in this batch have been satisfied, ie
        already committed by this block or prior block in the chain.

        :param batch: the batch to verify
        :return:
        Boolean: True if all dependencies are present and all transactions
        are unique.
        """
        for txn in batch.transactions:
            txn_hdr = self._txn_header(txn)
            if self._chain_commit_state.has_transaction(txn.header_signature):
                LOGGER.debug("Block rejected due to duplicate transaction, transaction: %s",txn.header_signature[:8])
                raise InvalidBatch()
            for dep in txn_hdr.dependencies:
                if not self._chain_commit_state.has_transaction(dep):
                    LOGGER.debug("Block rejected due to missing transaction dependency, transaction %s depends on %s",txn.header_signature[:8],dep[:8])
                    raise InvalidBatch()
            if persist:
                self._chain_commit_state.add_txn(txn.header_signature)

    def _verify_block_batches(self, blkw,persist=True):
        if blkw.block.batches :
            
            """
            skip checking for external block
            check again using proc of transactions
            FOR DAG prev_state could be different from merkle state which was used into publisher FIXME 
            """
            if self._block_store.is_recovery:
                LOGGER.debug("Recovery for BLOCK=%s.%s(%s)",blkw.block_num,blkw.identifier[:8],blkw.signer_id[:8])
                return True

            with self._merkle_lock:
                prev_state = self._get_previous_block_root_state_hash(blkw)
                # Use root state from previous block for DAG use last state
                # 
                belong_cluster = self._belong_cluster(blkw.signer_id)
                is_my = (blkw.signer_id == self._validator_id)
                is_sync = self._is_sync and is_my
                LOGGER.debug("Have processed transactions again for BLOCK=%s.%s(%s) STATE=%s cluster=%s persist=%s sync=%s",blkw.block_num,blkw.identifier[:8],blkw.signer_id[:8],prev_state[:8],belong_cluster,persist,self._is_sync)
                #scheduler = self._executor.create_scheduler(self._squash_handler,prev_state,self._context_handlers)
                recompute_context = self._get_recompute_context(self._new_block.previous_block_id)
                
                if not is_my:
                    LOGGER.debug("Processing EXTERNAL transactions for block=%s.%s state=%s batches=%s",blkw.block_num,blkw.identifier[:8],blkw.state_root_hash[:8],len(blkw.block.batches))
                    if blkw.block_num == 0 and False:
                        # for external genesis block add mapping to own genesis state 
                        # FIXME Also we should make transaction from this block
                        # because in case dynamic mode this block contain info about topology 
                        prev_state = self._block_store.chain_head.state_root_hash 
                        self._update_state_hash(blkw.state_root_hash,prev_state)
                        return True
                    
                
                scheduler = self._executor.create_scheduler(self._squash_handler,prev_state,self._context_handlers)
                if recompute_context is not None:
                    """
                    Rrecompute correct state for block using current STATE and CONTEXT which was taken from candidate block
                    recomputed_state - is real new state for new block which going to be commited
                    """ 
                    LOGGER.debug("Branch=%s recompute merkle=%s\n",self._new_block.previous_block_id[:8],recompute_context)
                    recomputed_state = scheduler.recompute_merkle_root(prev_state,recompute_context)
                else:
                    recomputed_state = blkw.state_root_hash
                    LOGGER.debug("_verify_block_batches:EXTERNAL block=%s for ARBITRATION",blkw.identifier[:8])
                
                if recomputed_state and recomputed_state != blkw.state_root_hash:
                    # for DAG - in case state for block was changed - make virtual link 
                    LOGGER.debug("recomputed STATE=%s is not match with state hash from block",recomputed_state[:8])
                    scheduler.update_state_hash(blkw.state_root_hash,recomputed_state)
                    LOGGER.debug("recomputed STATE=%s is not match state from block",recomputed_state[:8])
                
                self._executor.execute(scheduler)
                
                # testing
                #self._check_merkle(blkw.state_root_hash,'NEW before execution')
                LOGGER.debug("RECALCULATE batches=%s for block=%s",len(blkw.block.batches),blkw)
                try:
                    for batch, has_more in look_ahead(blkw.block.batches):
                        if self._chain_commit_state.has_batch(batch.header_signature):
                            # was already commited block with the same batch
                            blk = self._block_store.get_block_by_batch_id(batch.header_signature)
                            LOGGER.debug("Block(%s) rejected due to duplicate batch, batch: %s blk=%s", blkw,batch.header_signature[:8],blk)
                            raise InvalidBatch()
                
                        self._verify_batch_transactions(batch,persist)
                        if persist:
                            self._chain_commit_state.add_batch(batch, add_transactions=False)
                        if has_more:
                            scheduler.add_batch(batch)
                        else:
                            """
                            blkw.state_root_hash - new state calculated into publisher - for DAG it could be incorrect 
                            AT THIS POINT we say recalculate merkle state
                            """  
                            LOGGER.debug("LAST BATCH: for block=%s UPDATE STATE=%s-->%s",blkw,prev_state[:8],recomputed_state[:8] if recomputed_state else None)
                            #FOR ARBITRATION force fixing new state 
                            scheduler.add_batch(batch,'verify' if not persist else (recomputed_state if belong_cluster and is_sync else 'arbitration')) # prev_state if blkw.state_root_hash != recomputed_state else blkw.state_root_hash

                except InvalidBatch:
                    #the same block was already commited
                    LOGGER.debug("Invalid batch %s encountered during verification of block %s",batch.header_signature[:8],blkw)
                    scheduler.cancel()
                    return False
                except Exception:
                    scheduler.cancel()
                    raise

                LOGGER.debug("Finalize for BLOCK=%s.%s(%s)",blkw.block_num,blkw.identifier[:8],blkw.signer_id[:8])
                scheduler.finalize()
                LOGGER.debug("Complete for BLOCK=%s.%s(%s)",blkw.block_num,blkw.identifier[:8],blkw.signer_id[:8])
                scheduler.complete(block=True)
                state_hash = None
                
                """
                FOR SERIAL SCHEDULER AT THIS POINT NEW BLOCK STATE APPEARED INTO STATE DATABASE !!!
                and we can unlock merkle state 
                """
                LOGGER.debug("CURRENT NEW STATE=%s SYNC=%s\n",self._get_merkle_root()[:8],is_sync)
                # testing
                #self._check_merkle(prev_state,'_verify_block_batches OLD root')
                #self._check_merkle(recomputed_state,'_verify_block_batches NEW root') #blkw.state_root_hash
                for batch in blkw.batches:
                    batch_result = scheduler.get_batch_execution_result(batch.header_signature)
                    if batch_result is not None and batch_result.is_valid:
                        txn_results = scheduler.get_transaction_execution_results(batch.header_signature)
                        blkw.execution_results.extend(txn_results)
                        state_hash = batch_result.state_hash
                        blkw.num_transactions += len(batch.transactions)
                        #LOGGER.debug("Block=%s NEW ROOT STATE=%s",blkw,state_hash[:8] if state_hash else None)
                    else:
                        return False

            """
            FOR PARALLEL SCHEDULER AT THIS POINT NEW BLOCK STATE APPEARED INTO STATE DATABASE !!!
            and we can unlock merkle state 
            """
            if (belong_cluster and is_sync and recomputed_state != state_hash): # or (not recomputed_state and blkw.state_root_hash != state_hash): # blkw.state_root_hash != state_hash
                # for DAG this states could be different
                # ignore for other cluster block
                LOGGER.debug("Block(%s) rejected due to state root hash mismatch: %s != %s\n", blkw, recomputed_state[:8] if recomputed_state else None,state_hash[:8] if state_hash else None)
                return False

            if (not belong_cluster or not is_sync) and state_hash != blkw.state_root_hash and persist:
                """
                for other's cluster blocks we excecute transactions only once and fix merkle root state without comparing this state with state from publisher   
                """
                LOGGER.debug("UPDATE TO STATE=%s->%s for EXTERNAL ARBITRATED BLOCK=%s.%s",state_hash[:8],self._get_merkle_root()[:8],blkw.block_num,blkw.identifier[:8])
                scheduler.update_state_hash(blkw.state_root_hash,state_hash)

            LOGGER.debug("Was verified BLOCK=%s.%s(%s) num tnx=%s state=%s~%s\n",blkw.block_num,blkw.identifier[:8],blkw.signer_id[:8],blkw.num_transactions,state_hash[:8],recomputed_state[:8] if recomputed_state else None)

        return True

    def _validate_permissions(self, blkw):
        """
        Validate that all of the batch signers and transaction signer for the
        batches in the block are permitted by the transactor permissioning
        roles stored in state as of the previous block. If a transactor is
        found to not be permitted, the block is invalid.
        """
        if blkw.block_num != 0:
            try:
                state_root = self._get_previous_block_root_state_hash(blkw)
            except KeyError:
                LOGGER.info("Block rejected due to missing predecessor: %s", blkw)
                return False

            for batch in blkw.batches:
                if not self._permission_verifier.is_batch_signer_authorized(
                        batch, state_root):
                    return False
        return True

    def _validate_on_chain_rules(self, blkw):
        """
        Validate that the block conforms to all validation rules stored in
        state. If the block breaks any of the stored rules, the block is
        invalid.
        """
        if blkw.block_num != 0:
            try:
                state_root = self._get_previous_block_root_state_hash(blkw)
            except KeyError:
                LOGGER.debug("Block rejected due to missing" + " predecessor: %s", blkw)
                return False

            return self._validation_rule_enforcer.validate(blkw, state_root)
        return True

    def on_check_block(self):
        # for external consensus
        LOGGER.debug('BlockValidator: on_check_block say validator about reply\n')
        self._verifier.verify_block_complete(True)

    def on_commit_block(self):
        # for external consensus
        LOGGER.debug('BlockValidator: on_commit_block say validator about reply\n')
        self._fork_resolver.compare_forks_complete(True)

    def on_ignore_block(self):
        # for external consensus
        LOGGER.debug('BlockValidator: on_ignore_block say validator about reply ID=%s\n',self._new_block.identifier[:8])
        self._fork_resolver.compare_forks_complete(False)

    def on_fail_block(self):
        # for external consensus - say that this block will be mark as invalid
        LOGGER.debug('BlockValidator: on_fail_block say validator about reply\n')
        self._verifier.verify_block_complete(False)

    def validate_block(self, blkw):
        # pylint: disable=broad-except
        LOGGER.debug("BlockValidator:validate_block status=%s",blkw.status)
        try:
            if blkw.status == BlockStatus.Valid:
                return True
            elif blkw.status == BlockStatus.Invalid:
                return False
            else:
                valid = True
                LOGGER.debug("BlockValidator:validate_block -> _validate_permissions")
                valid = self._validate_permissions(blkw)

                if valid:
                    public_key = self._identity_signer.get_public_key().as_hex()
                    verifier = self._consensus_module.BlockVerifier(
                        block_cache=self._block_cache,
                        state_view_factory=self._state_view_factory,
                        data_dir=self._data_dir,
                        config_dir=self._config_dir,
                        validator_id=public_key)
                    self._verifier = verifier # save for reply from external consensus

                    LOGGER.debug("BlockValidator:validate_block -> verify_block")
                    """
                    use proxy engine for verification and send message NEW_BLOCK to consensus
                    when we got return from verifier.verify_block() consensus already say OK or BAD for this block   
                    and also we have already selected block (one of the the same block from all peer's block) for consensus                
                    """
                    valid = verifier.verify_block(blkw)
                    LOGGER.debug("BlockValidator:validate_block <- verify_block valid=%s",valid)
                    
                if valid:
                    valid = self._validate_on_chain_rules(blkw)

                if valid and blkw.signer_id != self._validator_id:
                    """
                    MAYBE check only for external block - which was made by others peer 
                    """
                    #if self._is_sync:
                    valid = self._verify_block_batches(blkw,persist=False)
                    #pass

                # since changes to the chain-head can change the state of the
                # blocks in BlockStore we have to revalidate this block.
                #FIXME for DAG - think about block_store.chain_head 
                if (self._chain_head is not None
                    and self._chain_head.identifier != self._block_store.chain_head.identifier
                    and self._chain_head.identifier not in self._block_store.chain_heads):
                    LOGGER.debug("Validate block raise ChainHeadUpdated HEAD=%s block=%s.%s heads=%s\n",self._chain_head.identifier[:8],blkw.block_num,blkw.identifier[:8],self._block_store.get_chain_heads())
                    raise ChainHeadUpdated()

                blkw.status = BlockStatus.Valid if valid else BlockStatus.Invalid
                if not valid and hasattr(verifier, 'verify_block_invalid'):
                    pass
                    #verifier.verify_block_invalid(blkw)

                LOGGER.debug("BlockValidator:validate_block valid=%s",valid)

                return valid
        except ChainHeadUpdated as chu:
            raise chu
        except Exception:
            LOGGER.exception("Unhandled exception BlockPublisher.validate_block()")
            return False

    def _find_common_height(self, new_chain, cur_chain):
        """
        Walk back on the longest chain until we find a predecessor that is the
        same height as the other chain.
        The blocks are recorded in the corresponding lists
        and the blocks at the same height are returned
        FIXME for DAG version
        """
        new_blkw = self._new_block
        cur_blkw = self._chain_head
        # 1) find the common ancestor of this block in the current chain
        # Walk back until we have both chains at the same length

        # Walk back the new chain to find the block that is the
        # same height as the current head.
        if new_blkw.block_num > cur_blkw.block_num:
            # new chain is longer
            # walk the current chain back until we find the block that is the
            # same height as the current chain.
            while new_blkw.block_num > cur_blkw.block_num and \
                    new_blkw.previous_block_id != NULL_BLOCK_IDENTIFIER:
                new_chain.append(new_blkw)
                try:
                    new_blkw = self._block_cache[new_blkw.previous_block_id]
                except KeyError:
                    LOGGER.info(
                        "Block %s rejected due to missing predecessor %s",
                        new_blkw,
                        new_blkw.previous_block_id)
                    for b in new_chain:
                        b.status = BlockStatus.Invalid
                    raise BlockValidationAborted()
        elif new_blkw.block_num < cur_blkw.block_num:
            # current chain is longer
            # walk the current chain back until we find the block that is the
            # same height as the new chain.
            while (cur_blkw.block_num > new_blkw.block_num
                   and new_blkw.previous_block_id != NULL_BLOCK_IDENTIFIER):
                cur_chain.append(cur_blkw)
                cur_blkw = self._block_cache[cur_blkw.previous_block_id]
        return (new_blkw, cur_blkw)

    def _find_common_ancestor(self, new_blkw, cur_blkw, new_chain, cur_chain,is_external=False):
        """ Finds a common ancestor of the two chains.
            FIXME for DAG version
        """
        while cur_blkw.identifier != new_blkw.identifier:
            if (cur_blkw.previous_block_id == NULL_BLOCK_IDENTIFIER
                    or new_blkw.previous_block_id == NULL_BLOCK_IDENTIFIER):
                # We are at a genesis block and the blocks are not the same
                # it could be external genesis block
                if is_external:
                    new_chain.append(new_blkw)
                    break
                LOGGER.info("Block rejected due to wrong genesis: %s %s",cur_blkw, new_blkw)
                for b in new_chain:
                    b.status = BlockStatus.Invalid
                raise BlockValidationAborted()

            new_chain.append(new_blkw)
            # for external genesis block there is no predecessor
            try:
                new_blkw = self._block_cache[new_blkw.previous_block_id]
            except KeyError:
                LOGGER.info("Block %s rejected due to missing predecessor %s",
                    new_blkw,
                    new_blkw.previous_block_id)
                for b in new_chain:
                    b.status = BlockStatus.Invalid
                raise BlockValidationAborted()
                

            cur_chain.append(cur_blkw)
            cur_blkw = self._block_cache[cur_blkw.previous_block_id] # prev curr block

    def _test_commit_new_chain(self):
        """ Compare the two chains and determine which should be the head.
        """
        public_key = self._identity_signer.get_public_key().as_hex()
        fork_resolver = \
            self._consensus_module.ForkResolver(
                block_cache=self._block_cache,
                state_view_factory=self._state_view_factory,
                data_dir=self._data_dir,
                config_dir=self._config_dir,
                validator_id=public_key)
        self._fork_resolver = fork_resolver # for proxy
        LOGGER.debug("_test_commit_new_chain block=%s parent=%s", self.identifier[:8],self.previous_block_id[:8]) # [x for x, y in fork_resolver.__dict__.items() if True or callable(y)])
        return fork_resolver.compare_forks(self._chain_head, self._new_block)

    def _compute_batch_change(self, new_chain, cur_chain):
        """
        Compute the batch change sets.
        """
        committed_batches = []
        for blkw in new_chain:
            for batch in blkw.batches:
                committed_batches.append(batch)

        uncommitted_batches = []
        for blkw in cur_chain:
            for batch in blkw.batches:
                uncommitted_batches.append(batch)

        return (committed_batches, uncommitted_batches)

    def run(self):
        """
        Main entry for Block Validation, Take a given candidate block
        and decide if it is valid then if it is valid determine if it should
        be the new head block. Returns the results to the ChainController
        so that the change over can be made if necessary.
        """
        try:
            branch_id = self._new_block.previous_block_id
            LOGGER.debug("run: Starting validation NEW BLOCK=%s.%s signer_id=%s for BRANCH=%s",self._new_block.block_num,self._new_block.identifier[:8],self._new_block.signer_id[:8],branch_id[:8])
            cur_chain = self._result["cur_chain"]  # ordered list of the  current chain blocks
            new_chain = self._result["new_chain"]  # ordered list of the new chain blocks
            """
            FIXME get the current chain_head .For DAG we should take head for branch relating to _new_block
            """
            self._chain_head = self._block_store.chain_head
            is_external = False
            if self._chain_head.identifier != branch_id : # and branch_id != NULL_BLOCK_IDENTIFIER:
                # this is DAG version 
                try:
                    self._chain_head = self._block_store.get_chain_head(branch_id) 
                except KeyError:
                    # for external block 
                    is_external = True
                    # take from cache
                    try:
                        self._chain_head = self._block_cache[branch_id]
                    except KeyError:
                        # use main chain head
                        LOGGER.info("External block there is no HEAD for BRANCH=%s heads=%s\n",branch_id[:8],self._block_store.get_chain_heads())
                         
                LOGGER.info("BlockValidator:run get head for BRANCH=%s num=%s",self._chain_head.identifier[:8],self._chain_head.block_num)

            self._result['chain_head'] = self._chain_head
            
            LOGGER.info("BlockValidator:: try to add new block chain_head=%s~%s head num=%s", self._chain_head.identifier[:8],branch_id[:8],self._chain_head.block_num)
            # 1) Find the common ancestor block, the root of the fork.
            # walk back till both chains are the same height
            (new_blkw, cur_blkw) = self._find_common_height(new_chain,cur_chain)

            # 2) Walk back until we find the common ancestor
            # for external genesis block
            self._find_common_ancestor(new_blkw, cur_blkw,new_chain, cur_chain,is_external)

            # 3) Determine the validity of the new fork
            # build the transaction cache to simulate the state of the
            # chain at the common root.
            self._chain_commit_state = ChainCommitState(self._block_store, cur_chain)

            valid = True
            for block in reversed(new_chain):
                if valid:
                    if not self.validate_block(block):
                        LOGGER.info("Block validation failed: %s", block)
                        valid = False
                    self._result["num_transactions"] += block.num_transactions
                    LOGGER.info("Block marked valid : %s",block)
                else:
                    LOGGER.info("Block marked invalid (invalid predecessor): %s",block)
                    block.status = BlockStatus.Invalid

            if not valid:
                self._done_cb(False, self._result)
                return

            LOGGER.info("Block is Valid new_chain=%s cur_chain=%s",len(new_chain),len(cur_chain))
            # 4) Evaluate the 2 chains to see if the new chain should be
            # committed
            LOGGER.info("Comparing current chain head '%s' against new block '%s'",self._chain_head, self._new_block)
            for i in range(max(len(new_chain), len(cur_chain))):
                cur = new = num = "-"
                if i < len(cur_chain):
                    cur = cur_chain[i].header_signature[:8]
                    num = cur_chain[i].block_num
                if i < len(new_chain):
                    new = new_chain[i].header_signature[:8]
                    num = new_chain[i].block_num
                LOGGER.info("Fork comparison at height %s is between %s and %s",num, cur, new)
            # testing
            #self._check_merkle(self._new_block.state_root_hash,'_test_commit_new_chain')

            # fork_resolver - for proxy send message  
            commit_new_chain = self._test_commit_new_chain()
            """
            in case ignore from consenus we have commit_new_chain == False
            in case commite commit_new_chain == True - only at this point we can change merkle state
            """ 
            # 5) Consensus to compute batch sets (only if we are switching).
            if commit_new_chain:
                if self._verify_block_batches(self._result["new_block"]) :
                    (self._result["committed_batches"],self._result["uncommitted_batches"]) = self._compute_batch_change(new_chain, cur_chain)
                    if new_chain[0].previous_block_id != self._chain_head.identifier:
                        self._moved_to_fork_count.inc()
                else:
                    commit_new_chain = False


            # 6) Tell the journal we are done.
            LOGGER.info("_done_cb  commit_new_chain=%s block=%s\n",commit_new_chain,self._new_block.identifier[:8])
            #self._check_merkle(self._new_block.state_root_hash)
            # into _done_cb - make receipty
            self._done_cb(commit_new_chain, self._result) # on_block_validated() 

            LOGGER.info("Finished new block=%s.%s validation STATE=%s\n",self._new_block.block_num,self._new_block.identifier[:8],self._new_block.state_root_hash[:10])
            #self._check_merkle(self._new_block.state_root_hash)
            

        except BlockValidationAborted:
            self._done_cb(False, self._result)
            return
        except ChainHeadUpdated:
            self._done_cb(False, self._result)
            return
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception(
                "Block validation failed with unexpected error: %s",
                self._new_block)
            # callback to clean up the block out of the processing list.
            self._done_cb(False, self._result)


class ChainObserver(object, metaclass=ABCMeta):
    @abstractmethod
    def chain_update(self, block, receipts):
        """This method is called by the ChainController on block boundaries.

        Args:
            block (:obj:`BlockWrapper`): The block that was just committed.
            receipts (dict of {str: receipt}): Map of transaction signatures to
                transaction receipts for all transactions in the block."""
        raise NotImplementedError()


class _ChainThread(InstrumentedThread):
    def __init__(self, chain_controller, block_queue, block_cache):
        super().__init__(name='_ChainThread')
        self._chain_controller = chain_controller
        self._block_queue = block_queue
        self._block_cache = block_cache
        self._exit = False

    def run(self):
        try:
            while True:
                try:
                    block = self._block_queue.get(timeout=1)
                    LOGGER.debug("_ChainThread: NEW BLOCK: %s",block)
                    self._chain_controller.on_block_received(block)
                except queue.Empty:
                    # If getting a block times out, just try again.
                    pass

                if self._exit:
                    return
        # pylint: disable=broad-except
        except Exception:
            LOGGER.exception("ChainController thread exited with error.")

    def stop(self):
        self._exit = True


class ChainController(object):
    """
    To evaluating new blocks to determine if they should extend or replace
    the current chain. If they are valid extend the chain.
    """

    def __init__(self,
                 block_cache,
                 block_sender,
                 state_view_factory,
                 transaction_executor,
                 chain_head_lock,
                 on_chain_updated,
                 on_head_updated,
                 on_topology_updated,
                 get_recompute_context,
                 belong_cluster,
                 squash_handler,
                 context_handlers,
                 chain_id_manager,
                 identity_signer,
                 data_dir,
                 config_dir,
                 permission_verifier,
                 chain_observers,
                 thread_pool=None,
                 metrics_registry=None,
                 consensus_notifier=None,
                 block_manager=None,
                 max_dag_branch=None):
        """Initialize the ChainController
        Args:
            block_cache: The cache of all recent blocks and the processing
                state associated with them.
            block_sender: an interface object used to send blocks to the
                network.
            state_view_factory: The factory object to create
            transaction_executor: The TransactionExecutor used to produce
                schedulers for batch validation.
            chain_head_lock: Lock to hold while the chain head is being
                updated, this prevents other components that depend on the
                chain head and the BlockStore from having the BlockStore change
                under them. This lock is only for core Journal components
                (BlockPublisher and ChainController), other components should
                handle block not found errors from the BlockStore explicitly.
            block_publisher.on_chain_updated: The callback to call to notify the rest of the
                 system the head block in the chain has been changed.
                 squash_handler: a parameter passed when creating transaction
                 schedulers.
            chain_id_manager: The ChainIdManager instance.
            identity_signer: Private key for signing blocks.
            data_dir: path to location where persistent data for the
                consensus module can be stored.
            config_dir: path to location where config data for the
                consensus module can be found.
            chain_observers (list of :obj:`ChainObserver`): A list of chain
                observers.
        Returns:
            None
        """
        self._lock = RLock()
        self._merkle_lock = RLock() # for merkle state update 
        self._chain_head_lock = chain_head_lock # publisher lock
        self._block_cache = block_cache
        self._block_store = block_cache.block_store
        self._state_view_factory = state_view_factory
        self._block_sender = block_sender
        self._transaction_executor = transaction_executor
        self._notify_on_chain_updated = on_chain_updated
        self._notify_on_head_updated = on_head_updated
        self._notify_on_topology_updated = on_topology_updated
        self._get_recompute_context = get_recompute_context
        self._belong_cluster = belong_cluster
        self._squash_handler = squash_handler
        self._context_handlers=context_handlers
        self._get_merkle_root = context_handlers['merkle_root']
        self._update_state = context_handlers['update_state']
        self._update_merkle_root = context_handlers['update_merkle_root'] 
        self._identity_signer = identity_signer
        self._validator_id = identity_signer.get_public_key().as_hex()
        self._data_dir = data_dir
        self._config_dir = config_dir

        self._blocks_processing = {}  # a set of blocks that are
        # currently being processed.
        self._blocks_pending = {}  # set of blocks that the previous block
        # is being processed. Once that completes this block will be
        # scheduled for validation.
        self._chain_id_manager = chain_id_manager
        self._is_genesis_federation_block = False
        self._is_nests_ready = False
        self._store_chain_head = None # is not None only for restore mode
        self._chain_head = None # main branch
        self._chain_heads = {} # for DAG only
        self._permission_verifier = permission_verifier
        self._chain_observers = chain_observers
        self._metrics_registry = metrics_registry
        self._consensus_notifier = consensus_notifier # for external consensus
        self._block_manager = block_manager
        self._max_dag_branch = max_dag_branch if max_dag_branch is not None else MAX_DAG_BRANCH
        LOGGER.info("Chain controller initialized with max_dag_branch=%s max_workers=%s validator=%s",self._max_dag_branch,self._max_dag_branch*PEERS_NUM,self._validator_id[:8])
        if metrics_registry:
            self._chain_head_gauge = GaugeWrapper(metrics_registry.gauge('chain.ChainController.chain_head', default='no chain head'))
            self._committed_transactions_count = CounterWrapper(metrics_registry.counter('chain.ChainController.committed_transactions_count'))
            self._block_num_gauge = GaugeWrapper(metrics_registry.gauge('chain.ChainController.block_num'))
            self._committed_transactions_gauge = GaugeWrapper(metrics_registry.gauge('chain.ChainController.committed_transactions_gauge'))
            self._blocks_considered_count = CounterWrapper(metrics_registry.counter('chain.ChainController.blocks_considered_count'))
            LOGGER.info("Chain controller set METRICS DONE")
            """
            mlist = self._metrics_registry.dump_metrics
            self._metric_key = None
            for mkey in mlist.keys():
                LOGGER.info("Chain controller _metric_key=%s fnd=%s",mkey,mkey.find('chain_head'))
                if mkey.find('chain_head') >= 0:
                    self._metric_key = mkey
                    break
            LOGGER.info("Chain controller _metric_key=%s",self._metric_key)
            self._metric_key = 'chain_head'
            """

        else:
            self._chain_head_gauge = GaugeWrapper()
            self._committed_transactions_count = CounterWrapper()
            self._committed_transactions_gauge = GaugeWrapper()
            self._block_num_gauge = GaugeWrapper()
            self._blocks_considered_count = CounterWrapper()

        self._block_queue = queue.Queue()
        """
        get max dag from chain
        
        state_view = self._state_view_factory.create_view()
        self._max_dag_branch = settings_view.get_setting('bgx.dag.max_branch', default_value=MAX_DAG_BRANCH)
        LOGGER.info("Chain MAX_DAG_BRANCH=%s",self._max_dag_branch)
        """
        # we use thread for each peer and for each head
        self._thread_pool = (
            InstrumentedThreadPoolExecutor(max_workers=self._max_dag_branch*PEERS_NUM, name='Validating',metrics_registry=metrics_registry)
            if thread_pool is None else thread_pool
        )
        self._chain_thread = None

        # Only run this after all member variables have been bound
        self._set_chain_head_from_block_store()

    def _set_chain_head_from_block_store(self):
        try:
            # main chain head self._block_manager.put([new_head.get_block()])
            self._chain_head = self._block_store.chain_head
            if self._chain_head is not None:
                LOGGER.info("Chain controller initialized with main chain head: %s",self._chain_head)
                if self._chain_head.block_num != 0:
                    """
                    Use DAG which was already builded
                    set genesis block as head
                    """ 
                    self._store_chain_head = self._chain_head # keep real head for consensus engine
                    self._chain_head = self._block_store.get_block_by_number(0)
                    blk = self._chain_head.get_block()
                    self._block_manager.put([blk])
                    self._block_manager.ref_block(blk.header_signature)

                hid = self._chain_head.identifier
                # add main BRANCH for DAG chain
                self._chain_heads[hid] = self._chain_head
                self._block_store.update_chain_heads(hid,hid,self._chain_head)
                self._chain_head_gauge.set_value(hid)
        except Exception:
            LOGGER.exception("Invalid block store. Head of the block chain cannot be determined")
            raise

    def start(self):
        self._set_chain_head_from_block_store()
        LOGGER.debug("ChainController:START call _notify PUBLISHER on_chain_updated ID=%s\n",self._chain_head.identifier[:8] if self._chain_head else None)
        self._notify_on_chain_updated(self._chain_head)

        self._chain_thread = _ChainThread(
            chain_controller=self,
            block_queue=self._block_queue,
            block_cache=self._block_cache)
        self._chain_thread.start()

    def stop(self):
        if self._chain_thread is not None:
            self._chain_thread.stop()
            self._chain_thread = None

        if self._thread_pool is not None:
            self._thread_pool.shutdown(wait=True)

    def queue_block(self, block):
        """
        New block has been received, queue it with the chain controller
        for processing.
        from publisher.on_check_publish_block() 
        """
        LOGGER.debug("ChainController: queue BLOCK=%s",block.identifier[:8])
        self._block_queue.put(block)

    def get_real_head_of_branch(self,branch_id,deep=3):
        for key,head  in list(self._chain_heads.items()):
            # check may be for this branch head was changed
            branch = head
            step = 0
            while branch.previous_block_id != NULL_BLOCK_IDENTIFIER and step < deep:
                if branch.previous_block_id == branch_id :
                    LOGGER.debug("get_real_head of branch=%s found for=%s",branch_id[:8],key[:8])
                    return head
                LOGGER.debug("get_real_head of branch=%s GO BACK check=%s for=%s step=%s",branch_id[:8],branch.previous_block_id[:8],key[:8],step)
                branch = self._block_cache[branch.previous_block_id]
                step += 1
        return None
    
    def has_genesis_federation_block(self):
        LOGGER.debug("ChainController: has_genesis_federation_block=%s",self._is_genesis_federation_block)
        return self._is_genesis_federation_block

    def is_nests_ready(self):
        """
        for sync mode - means all nests ready and we can start rest federations
        """
        return self._is_nests_ready

    @property
    def _heads_list(self):
        return [str(blk.block_num)+':'+key[:8] for key,blk in self._chain_heads.items()]

    @property
    def blocks_processing(self):
        return [key[:8] for key in self._blocks_processing.keys()]

    def get_chain_head(self,parent_id=None,new_parent_id=None,is_new=False):
        """
        for DAG version - in case new_parent_id != None - switch parent_id to new_parent_id block as new branch 
        """ 
        if parent_id is None:
            LOGGER.debug("get_chain_head: parent_id=None GENESIS heads=%s",self._heads_list)
            return self._chain_head

        if parent_id in self._chain_heads:
            if new_parent_id is not None and new_parent_id in self._block_cache:
                # switch 'parent_id' head to new point 'new_parent_id'
                LOGGER.debug("ChainController: SWITCH BRANCH %s->%s heads=%s",parent_id[:8],new_parent_id[:8],self._heads_list)
                new_head = self._block_cache[new_parent_id]
                del self._chain_heads[parent_id]
                self._chain_heads[new_parent_id] = new_head
                # check maybe parent_id stil used 
                is_used = self.is_parent_used(parent_id)
                self._block_store.update_branch(parent_id,new_parent_id,new_head,is_used) # is_used
                self._notify_on_head_updated(parent_id,new_parent_id,new_head)
                LOGGER.debug("ChainController: SWITHED BRANCH  heads=%s",self._heads_list)
                #also we should put this block into block manager again - for use as parent for new block
                if new_parent_id not in self._block_manager:
                    self._block_manager.put([new_head.get_block()])
                return new_head
            LOGGER.debug("ChainController: get_chain_head for=%s is_new=%s heads=%s",parent_id[:8],is_new,self._heads_list)
            head = self._chain_heads[parent_id]
            if parent_id not in self._block_manager:
                self._block_manager.put([head.get_block()])
            return head
        elif is_new :
            # ask new branch
            if len(self._chain_heads) >= self._max_dag_branch :
                LOGGER.debug("ChainController: TOO MANY NEW BRANCH heads=%s",self._heads_list)
                self._is_nests_ready = True
                self._block_store.set_nests_ready()
                # after nests were builded we can start with head of others federations
                self._block_sender.check_pending_head()
                raise TooManyBranch
                #return None
            # create new branch for DAG
            if parent_id in self._block_cache:
                # mark block into block_store as new DAG branch 
                LOGGER.debug("ChainController: get_chain_head NEW BRANCH=%s",parent_id[:8])
                new_head = self._block_cache[parent_id]
                self._block_store.add_branch(parent_id,new_head)
                self._chain_heads[parent_id] = new_head
                #also we should put this block into block manager again - for use as parent for new block
                if parent_id not in self._block_manager:
                    self._block_manager.put([new_head.get_block()])
                return new_head

        else: 
            """
            head for branch can be changed  or not commited yet because we can ask head too fast after commit
            soo we should restrict deep of seek for real head - it's will be better to ask it again  
            or we can check may be this block is under commiting now
            """  
            LOGGER.debug("ChainController: get_chain_head for=%s heads=%s",parent_id[:8],self._heads_list)
            if parent_id in self._blocks_processing:
                LOGGER.debug("ChainController: get_chain_head for=%s WAIT BLOCK IS PROCESSED NOW!\n",parent_id[:8])
                #return None
                raise BlockIsProcessedNow
            # ? try to just wait and send head into next request
            #new_head = self.get_real_head_of_branch(parent_id)
            #LOGGER.debug("ChainController: get_chain_head for=%s real head=%s",parent_id[:8],new_head)
            #return new_head
            
        return None

    
    def is_block_processed_now(self,block_id):
        return block_id in self._blocks_processing

    @property
    def chain_head(self):
        # FIXME - investigate what we should return for DAG here
        return self._chain_head

    @property
    def store_chain_head(self):
        return self._store_chain_head if self._store_chain_head is not None else self._chain_head

    @property
    def is_recovery(self):
        """
        restore after restart node
        """
        return self._block_store.is_recovery
    def set_block_recover(self,blk_id):
        self._block_store.block_recovered(blk_id)

    def _submit_blocks_for_verification(self, blocks):
        """
        order of blocks is important - before try to verificate block - we should  check nest for block
        """
        for blkw in blocks:
            """
            blkw could be from another nodes
            """
            branch_id = blkw.previous_block_id
            LOGGER.debug("_submit_blocks_for_verification: BLOCK=%s.%s(%s) BRANCH=%s chain heads=%s",blkw.block_num,blkw.identifier[:8],blkw.signer_id[:8],branch_id[:8],self._heads_list)
            main_head = self._block_store.chain_head
            if blkw.signer_id == self._validator_id:
                # Own block
                if branch_id in self._chain_heads:
                    # block from our publisher
                    chain_head = self._chain_heads[branch_id]
                else:
                    # head of branch can be changed because of commiting another block with the same summary
                    chain_head = self.get_real_head_of_branch(branch_id)
            else:
                """
                block from another node but list head should have head connected with this block
                try to use last head
                """
                LOGGER.debug("_submit_blocks_for_verification: EXTERNAL block=%s signer=%s",blkw.identifier[:8],blkw.signer_id[:8])
                if branch_id in self._chain_heads:
                    # block from our publisher
                    chain_head = self._chain_heads[branch_id]
                    LOGGER.debug("_submit_blocks_for_verification: EXTERNAL block=%s take head=%s",blkw.identifier[:8],chain_head)
                else:
                    chain_head = main_head
                    LOGGER.debug("_submit_blocks_for_verification: EXTERNAL block=%s take MAIN HEAD=%s\n",blkw.identifier[:8],chain_head)

            state_view = BlockWrapper.state_view_for_block(main_head,self._state_view_factory) # for DAG use main_head instead chain_head
            LOGGER.debug("ChainController: _submit_blocks_for_verification BRANCH=%s head=%s",branch_id[:8],chain_head == self.chain_head)
            """
            consensus_module = \
                ConsensusFactory.get_configured_consensus_module(
                    self.chain_head.header_signature,
                    state_view)
            """
            chain_header_signature =  chain_head.header_signature if chain_head else None # for recovery mode
            #if chain_head is None:
            #    LOGGER.debug("ChainController: _submit_blocks_for_verification HEAD=%s BLOCK=%s.%s\n",chain_head,blkw.block_num,blkw.identifier[:8])
            consensus_module,consensus_name = ConsensusFactory.try_configured_consensus_module(chain_header_signature,state_view)
            
            if not consensus_module:
                # there is no internal consensus 
                # check may consensus engine already was registred
                LOGGER.debug("ChainController: no internal consensus_module=%s use proxy",consensus_name)
                #self._consensus = consensus_name[0] # save consensus name
                consensus_module = ConsensusFactory.try_configured_proxy_consensus()
                consensus_module._CONSENSUS_NAME_ = consensus_name[0]
                consensus_module._consensus_notifier = self._consensus_notifier
                if self._block_manager:
                    # add NEW block into block manager 
                    blk = blkw.get_block()
                    self._block_manager.put([blk]) 
                    self._block_manager.ref_block(blk.header_signature)
                    """
                    mark parent block ref_block(blk.previous_block_id) in case it external block previous_block_id don't exists
                    """
                    try:
                        #self._block_manager.ref_block(blkw.header.previous_block_id)
                        pass
                    except UnknownBlock:
                        LOGGER.debug("External block=%s with out parent",blkw.identifier[:8])
                    #block_iter = self._block_manager.get([blk.header_signature])
                    #blocks = [b for b in block_iter]
                    #blocks = next(self._block_manager.get([blk.header_signature]))
                    #LOGGER.debug("BlockValidator:validate_block blocks=%s",blocks)
            
            validator = BlockValidator(
                consensus_module=consensus_module,
                new_block=blkw,
                block_cache=self._block_cache,
                state_view_factory=self._state_view_factory,
                done_cb=self.on_block_validated,
                executor=self._transaction_executor,
                get_recompute_context=self._get_recompute_context, # from publisher candidate which is freezed
                belong_cluster=self._belong_cluster,
                is_sync = self._block_sender.is_sync,
                squash_handler=self._squash_handler,
                context_handlers=self._context_handlers,
                identity_signer=self._identity_signer,
                data_dir=self._data_dir,
                config_dir=self._config_dir,
                permission_verifier=self._permission_verifier,
                metrics_registry=self._metrics_registry,
                block_manager=self._block_manager,
                merkle_lock = self._merkle_lock)
            self._blocks_processing[blkw.block.header_signature] = validator
            """
            ref block_num for external block - it prevents against using this block number for other candidate
            """ 
            if blkw.signer_id != self._validator_id:
                # in this case blkw.block_num is already coloured
                self._block_store.ref_block_number(blkw.block_num,blkw.signer_id)
            # start validation
            self._thread_pool.submit(validator.run)
            LOGGER.debug("Submit_blocks_for_verification DONE BLOCK=%s.%s signer=%s BRANCH=%s SYNC=%s",blkw.block_num,blkw.block.header_signature[:8],blkw.signer_id[:8],branch_id[:8],self._block_sender.is_sync)

    """
    for external consensus
    """ 
    def get_block_from_cache(self,block_id):
        return self._block_cache[block_id]

    def on_check_block(self,block_id):
        # for external consensus - say that verification was done
        bid = block_id.hex()
        LOGGER.debug('ChainController: on_check_block block=%s num=%s\n',bid[:8],len(self._blocks_processing))
        
        if bid in self._blocks_processing : 
            validator = self._blocks_processing[bid]
            validator.on_check_block()
            
        else:
            LOGGER.debug('ChainController: on_check_block NO block=%s blocks_processing=%s',bid,self._blocks_processing)

    def block_validation_result(self, block_id):
        # for external consensus
        """
        status = ctypes.c_int32(0)

        _libexec("chain_controller_block_validation_result", self.pointer,
                 ctypes.c_char_p(block_id.encode()),
                 ctypes.byref(status))
        """
        if block_id in self._blocks_processing : 
            validator = self._blocks_processing[block_id]
            LOGGER.debug("ChainController:block_validation_result validator=%s",validator._new_block.status)
            return validator._new_block.status #BlockStatus.Valid
        else:
            LOGGER.debug("ChainController:block_validation_result id=%s blocks_processing=%s",block_id[:8],self._blocks_processing)
            return BlockStatus.Unknown #BlockStatus(status.value)

    def get_blocks_validation(self, block_ids):
        # for external consensus
        blocks = []
        for block_id in block_ids:
            if block_id in self._blocks_processing : 
                validator = self._blocks_processing[block_id]
                LOGGER.debug("ChainController:block_validation_result validator=%s",validator._new_block.status)
                blocks.append(validator._new_block)
        return blocks

    def _undef_block(self,block_id):
        try:
            self._block_manager.unref_block(block_id)
        except UnknownBlock:
            pass

    def commit_block(self, block):   
        # for external consensus 
        # after that we send message commited and can free this block from block manager    
        block_id = block.hex()
        if block_id in self._blocks_processing :
            validator = self._blocks_processing[block_id]
            LOGGER.debug("ChainController:commit block=%s parent=%s\n",block_id[:8],validator.previous_block_id[:8])
            validator.on_commit_block()
            self._block_manager.unref_block(block_id)
            #self._undef_block(validator.previous_block_id)
            
        else:
            if self.chain_head is not None and block_id == self.chain_head.header_signature and self.chain_head.block_num == 0:
                # genesis block
                return
            LOGGER.debug("ChainController:commit_block id=%s undefined\n",block_id[:8])
            raise UnknownBlock

    def ignore_block(self, block):   
        # for external consensus  - can free this block from block manager    
        block_id = block.hex()
        if block_id in self._blocks_processing :
            validator = self._blocks_processing[block_id]
            LOGGER.debug("ChainController:ignore_block id=%s parent=%s\n",block_id[:8],validator.previous_block_id[:8])
            validator.on_ignore_block()
            self._block_manager.unref_block(block_id)
            #self._undef_block(validator.previous_block_id)
           
        else:
            LOGGER.debug("ChainController:ignore_block id=%s undefined\n",block_id[:9])
            #raise UnknownBlock

    def _is_the_same_block_commited(self,new_block,head_id):
        head = self.get_real_head_of_branch(head_id)
        if head is not None:
            if head.summary == new_block.summary:
                LOGGER.debug("_is_the_same_block_commited: the same block=%s commited num EQUAL=%s", head.identifier[:8],head.block_num == new_block.block_num)
                
                return head
        return None

    def fail_block(self,block):
        # for external consensus - after that we send message block invalid and consensus ask get_block(<this block>) 
        # when it happend we can drop this one from block manager    
        block_id = block.hex()
        if block_id in self._blocks_processing :
            validator = self._blocks_processing[block_id]
            LOGGER.debug("ChainController:FAIL block=%s parent=%s\n",block_id[:8],validator.previous_block_id[:8])
            validator.on_fail_block()
            self._block_manager.unref_block(block_id)
            #self._undef_block(validator.previous_block_id)

        else:
            LOGGER.debug("ChainController:FAIL block id=%s undefined\n",block_id[:8])
            raise UnknownBlock

    def is_parent_used(self,pid):
        """
        if pid in self._chain_heads:
            return True
        """
        for val in self._blocks_processing.values():
            if val.previous_block_id == pid:
                return True
        return False

    def on_block_validated(self, commit_new_block, result):
        """
        call as done_cb() 
        Message back from the block validator, that the validation is
        complete
        Args:
        commit_new_block (Boolean): whether the new block should become the
        chain head or not.
        result (Dict): Map of the results of the fork resolution.
        Returns:
            None
        """
        def is_parent_used(pid):
            for val in self._blocks_processing.values():
                if val.previous_block_id == pid:
                    return True
            return False

        def on_block_invalid(new_block,descendant_blocks,is_external):
            # Since the block is invalid, we will never accept any
            # blocks that are descendants of this block.  We are going
            # to go through the pending blocks and remove all
            # descendants we find and mark the corresponding block
            # as invalid.
            #
            # Block could be invalid in case of consensus fail
            # we should inform external consensus
            LOGGER.debug("ChainController:on_block_invalid BLOCK=%s.%s signer=%s INVALID\n",new_block.block_num,new_block.identifier[:8],new_block.signer_id[:8])
            # for external block don't free block_number
            # if not is_external:
            # we should keep number until commit - the same block 
            #self._block_store.free_block_number(new_block.block_num,new_block.signer_id)
            if new_block.signer_id == self._validator_id:
                # for block timeout cancel mode 
                self._block_store.free_block_number(new_block.block_num,new_block.signer_id)
            while descendant_blocks:
                pending_block = descendant_blocks.pop()
                pending_block.status = BlockStatus.Invalid

                LOGGER.debug('Marking descendant block invalid: %s',pending_block)

                descendant_blocks.extend(
                    self._blocks_pending.pop(
                        pending_block.identifier,
                        []))
            if self._consensus_notifier is not None:
                # say external consensus 
                self._consensus_notifier.notify_block_invalid(new_block.header_signature)

        def on_block_commit(new_block,bid,descendant_blocks,is_external):
            """
            block could be commited
            """
            nid = new_block.identifier
            LOGGER.debug("on_block_commit COMMIT NEW BLOCK=%s.%s signer=%s for BRANCH=%s\n",new_block.block_num,nid[:8],new_block.signer_id[:8],bid[:8])
            with self._chain_head_lock:
                # FIXME - change head for branch==bid into self._chain_heads
                #
                # say that block number really used - FIXME - think about external block
                #if not is_external:
                # dell all peers which keeping this block
                self._block_store.pop_block_number(new_block.block_num,new_block.signer_id,True)
                # add new head
                self._chain_heads[nid] = new_block
                # check may be 'bid' used some others block which has this parent is now validating 
                is_used = self.is_parent_used(bid)
                self._block_store.update_chain_heads(bid,nid,new_block,is_used) # bid is_parent_used(bid)
                LOGGER.debug("update HEAD=%s->%s heads=%s",bid[:8],nid[:8],self._heads_list)
                # for DAG self._chain_head just last update branch's head it could be local variable 
                self._chain_head = new_block

                if bid in self._chain_heads:
                    # drop old head from list for external genesis this code does not work
                    del self._chain_heads[bid]
                    LOGGER.debug("COMMIT DROP OLD HEAD=%s",bid[:8])
                else:
                    """
                    for  DAG we should update self._chain_heads using list of block from result["cur_chain"]
                    in case if block from "cur_chain" there is in _chain_heads we should change this position
                    """
                    for key,head in self._chain_heads.items() :
                        if head.block_num == new_block.block_num:
                            del self._chain_heads[key]
                            LOGGER.debug("COMMIT DROP OLD HEAD=%s EXTERNAL",key[:8])
                            break
                    """
                    LOGGER.debug("CHECK CUR CHAINS=%s HEADS=%s",[blkw.header_signature[:8] for blkw in result["cur_chain"]],self._heads_list)
                    for blk in result["cur_chain"]:
                        if blk.header_signature in self._chain_heads:
                            LOGGER.debug("DROP EXTERNAL BLOCK=%s from _chain_heads",blk.header_signature[:8])   
                    """
                    LOGGER.debug("COMMIT NEW EXTERNAL BLOCK=%s",nid[:8])

                LOGGER.info("Chain head branch=%s UPDATED HEADS=%s num-tx=%s",bid[:8],self._heads_list,new_block.num_transactions)
                # update the the block store to have the new chain
                self._block_store.update_chain(result["new_chain"],result["cur_chain"])

                # make sure old chain is in the block_caches
                self._block_cache.add_chain(result["cur_chain"])

                self._chain_head_gauge.set_value(self._chain_head.identifier) # FIXME for external block

                self._committed_transactions_count.inc(new_block.num_transactions) #result["num_transactions"])
                self._committed_transactions_gauge.set_value(self._metrics_registry.get_metrics('chain.ChainController.committed_transactions_count')['count'] if self._metrics_registry else 0)
                self._block_num_gauge.set_value(self._chain_head.block_num)

                # tell the BlockPublisher else the chain for branch is updated
                LOGGER.debug("NOTIFY CHAIN UPDATED TO block=%s.%s %s store heads=%s\n",new_block.block_num,new_block.identifier[:8],'EXTERNAL' if is_external else 'INTERNAL',self._block_store.get_chain_heads())
                self._notify_on_chain_updated(
                    new_block,
                    result["committed_batches"],
                    result["uncommitted_batches"])

                for batch in new_block.batches:
                    if batch.trace:
                        LOGGER.debug("TRACE %s: %s",batch.header_signature,self.__class__.__name__)

            # Submit any immediate descendant blocks for verification
            LOGGER.debug('Verify descendant blocks: %s (%s)',new_block,[block.identifier[:8] for block in descendant_blocks])
            if self.is_recovery:
                # recovery mode - inform that block recover
                self.set_block_recover(nid)
            else:
                if len(descendant_blocks) == 0 and len(self._blocks_pending) == 0 and self._block_sender.is_pending_head == False and not self._block_sender.is_sync:
                    LOGGER.debug('There are no descendant blocks - TRY TO SYNC WITH OTHER PEERS\n')
                    self._block_sender.try_to_sync_with_net()

            self._submit_blocks_for_verification(descendant_blocks)

            for block in reversed(result["new_chain"]):
                receipts = self._make_receipts(block.execution_results)
                # Update all chain observers
                LOGGER.debug('Update all chain OBSERVERS: num=%s BLOCK=%s.%s receipts=%s\n',len(self._chain_observers),new_block.block_num,nid[:8],receipts)
                topology_updated = 0
                for observer in self._chain_observers:
                    if observer.chain_update(block, receipts):
                        topology_updated += 1
                if topology_updated > 0:
                    LOGGER.debug(f'UPDATE TOPOLOGY BLOCK={new_block.block_num}.{nid[:8]}')
                    self._notify_on_topology_updated()

        if self._metrics_registry:
            #LOGGER.debug("CHAIN DUMP METRICS=%s",self._metrics_registry.dump_metrics)
            pass
            #LOGGER.debug("CHAIN DUMP METRICS=%s",self._metrics_registry.get_metrics('chain.ChainController.committed_transactions_count'))
        # new block was validated
        try:
            with self._lock:
                self._blocks_considered_count.inc()
                new_block = result["new_block"]
                signer_id = new_block.signer_id
                is_external = (signer_id != self._validator_id) 
                # remove from the processing list
                del self._blocks_processing[new_block.identifier]
                LOGGER.info('on_block_validated: block=%s.%s(%s) external=%s chain_head=%s status=%s',new_block.block_num,new_block.identifier[:8],signer_id[:8],is_external,result["chain_head"].identifier[:8],
                            new_block.status
                )
                LOGGER.info('on_block_validated: processing=%s heads=%s',self.blocks_processing,self._heads_list)
                

                # Remove this block from the pending queue, obtaining any
                # immediate descendants of this block in the process.
                descendant_blocks = self._blocks_pending.pop(new_block.identifier, [])
                LOGGER.info("on_block_validated: immediate descendants=%s",[block.identifier[:8] for block in descendant_blocks])
                # if the head has changed, since we started the work. For instance was commited own block for this branch and appeared external block
                # FIXME for DAG check branch relating to new block 
                # result["chain_head"] is value from BlockValidator  for DAG we should analize here corresponding BRANCH 
                # chain head could be changed - if block invalid don't send it for verification
                if result["chain_head"].identifier not in self._chain_heads: # OLD result["chain_head"].identifier != self._chain_head.identifier
                    LOGGER.info('Chain head updated from %s to %s while processing block: %s',
                        result["chain_head"],
                        self._chain_head,
                        new_block)

                    # If any immediate descendant blocks arrived while this
                    # block was being processed, then submit them for
                    # verification.  Otherwise, add this block back to the
                    # pending queue and resubmit it for verification.
                    if descendant_blocks:
                        LOGGER.debug('Verify descendant blocks: %s (%s)',new_block,[block.identifier[:8] for block in descendant_blocks])
                        self._submit_blocks_for_verification(descendant_blocks)

                    else:
                        # check may be the same block was already commited - ignore
                        if not commit_new_block: # new_block.status == BlockStatus.Invalid :
                            LOGGER.debug("ChainController:on_block_validated BLOCK=%s INVALID\n",new_block.identifier[:8])
                            on_block_invalid(new_block,descendant_blocks,is_external)
                        else:
                            real_head = self._is_the_same_block_commited(new_block,result["chain_head"].identifier)
                            if real_head is not None:
                                # if another block was already commited and new block was commited too - it means that new block has ID > OLD ID 
                                # and we should update previous block
                                LOGGER.debug("ChainController:on_block_validated THE SAME BLOCK=%s<-%s was commited\n",real_head.identifier[:8], new_block.identifier[:8])
                                #on_block_invalid(new_block,descendant_blocks)
                                bid = real_head.identifier 
                                on_block_commit(new_block,bid,descendant_blocks,is_external)
                            else:
                                LOGGER.debug('Verify block again:chain head changed block=%s', new_block)
                                self._blocks_pending[new_block.identifier] = []
                                self._submit_blocks_for_verification([new_block])

                # If the head is to be updated to the new block.
                elif commit_new_block:
                    bid = new_block.previous_block_id 
                    on_block_commit(new_block,bid,descendant_blocks,is_external)
                # If the block was determine to be invalid.
                elif new_block.status == BlockStatus.Invalid:
                    
                    on_block_invalid(new_block,descendant_blocks,is_external)
 
                # The block is otherwise valid, but we have determined we
                # don't want it as the chain head.
                else:
                    """
                    it could be in case consensus say ignore
                    """
                    LOGGER.info('Rejected new chain head: %s', new_block)
                    self._block_store.free_block_number(new_block.block_num,new_block.signer_id)
                    if self._consensus_notifier is not None:
                        # say external consensus 
                        self._consensus_notifier.notify_block_invalid(new_block.header_signature)
                    # Submit for verification any immediate descendant blocks
                    # that arrived while we were processing this block.
                    LOGGER.debug('Verify descendant blocks: %s (%s)',new_block,[block.identifier[:8] for block in descendant_blocks])
                    LOGGER.info('Rejected descendant_blocks num=%s',len(descendant_blocks))
                    self._submit_blocks_for_verification(descendant_blocks)
                    # update state
                    #LOGGER.info('RESTORE STATE=%s->%s',self._get_merkle_root()[:8],new_block.state_root_hash[:8]) 
                    #self._update_merkle_root(new_block.state_root_hash)   
                    #self._update_state(self._get_merkle_root(),new_block.state_root_hash)

        # pylint: disable=broad-except
        except Exception:
            LOGGER.exception(
                "Unhandled exception in ChainController.on_block_validated()")

    def on_block_received(self, block):
        """
        it could be from completer or from publisher
        """
        def try_append_by_num(block):
            prev_num = int(Federation.dec_feder_num(block.block_num))
            for pid,blocks in self._blocks_pending.items():
                for blk in blocks:
                    # inc block num in federation mode
                    if blk.block_num == prev_num:
                        # blk is predecessor of block by number
                        self._blocks_pending[blk.identifier] = [block]
                        LOGGER.debug('For block=%s.%s pending=[%s] by num',blk.block_num, blk.identifier[:8],block.identifier[:8])
                        return True
            return False

        try:
            with self._lock:
                if self.has_block(block.header_signature):
                    # do we already have this block
                    return

                if self.chain_head is None:
                    self._set_genesis(block)
                    LOGGER.debug("Block received: GENESIS DONE")
                    return

                # If we are already currently processing this block, then
                # don't bother trying to schedule it again.
                if block.identifier in self._blocks_processing:
                    return
                # keep info about first genesis federation block
                if block.block_num == GENESIS_FEDERATION_BLOCK:
                    LOGGER.debug('GENESIS_FEDERATION_BLOCK APPEARED!!')
                    self._is_genesis_federation_block = True 

                # count all recovery block 
                self._block_cache[block.identifier] = block
                self._blocks_pending[block.identifier] = []
                LOGGER.debug(f">> Block received: id={block.identifier[:8]} pending total={len(self._blocks_pending)}")
                if (block.previous_block_id in self._blocks_processing or block.previous_block_id in self._blocks_pending):
                    LOGGER.debug('Block pending: id=%s', block.identifier[:8])
                    """
                    if the previous block is being processed, put it in a
                    wait queue, Also need to check if previous block is
                    in the wait queue.
                    But first check maybe there is block with number before this block and add current block for it  
                    """
                    #if not try_append_by_num(block):
                    pending_blocks = self._blocks_pending.get(block.previous_block_id,[])
                    # Though rare, the block may already be in the
                    # pending_block list and should not be re-added.
                    if len(pending_blocks) == 0:
                        if block not in pending_blocks:
                            pending_blocks.append(block)
                        LOGGER.debug('For block=%s pending=%s', block.previous_block_id[:8],[blk.identifier[:8] for blk in pending_blocks])
                        self._blocks_pending[block.previous_block_id] = pending_blocks
                    else: 
                        # maybe this is branch point
                        if not try_append_by_num(block):
                            LOGGER.debug('Block pending: id=%s cant add by num!!!\n', block.identifier[:8])
                            if block not in pending_blocks:
                                pending_blocks.append(block)
                                LOGGER.debug('For block=%s pending=%s', block.previous_block_id[:8],[blk.identifier[:8] for blk in pending_blocks])
                                self._blocks_pending[block.previous_block_id] = pending_blocks

                else:
                    # schedule this block for validation.
                    self._submit_blocks_for_verification([block])
        # pylint: disable=broad-except
        except Exception:
            LOGGER.exception(
                "Unhandled exception in ChainController.on_block_received()")

    def has_block(self, block_id,block_num=None):
        with self._lock:
            if block_id in self._block_cache:
                """
                check MAYBE this is recovery mode
                """
                LOGGER.debug("ChainController: has_block in CACHE block_num=%s recovery=%s",block_num,self.is_recovery)
                #if block_num is not None:
                #    blk = self._block_cache[block_id]
                #    if :
                return  not self.is_recovery

            if block_id in self._blocks_processing:
                LOGGER.debug("ChainController: has_block in PROCESSING block_num=%s",block_num)
                return True

            if block_id in self._blocks_pending:
                LOGGER.debug("ChainController: has_block in PENDING block_num=%s",block_num)
                return True

            return False


    def _set_genesis(self, block):
        # This is used by a non-genesis journal when it has received the
        # genesis block from the genesis validator
        if block.previous_block_id == NULL_BLOCK_IDENTIFIER:
            chain_id = self._chain_id_manager.get_block_chain_id()
            if chain_id is not None and chain_id != block.identifier:
                LOGGER.warning("Block id does not match block chain id %s. "
                               "Cannot set initial chain head.: %s",
                               chain_id[:8], block.identifier[:8])
            else:
                state_view = self._state_view_factory.create_view()
                LOGGER.debug("ChainController: _set_genesis")
                consensus_module = \
                    ConsensusFactory.get_configured_consensus_module(
                        NULL_BLOCK_IDENTIFIER,
                        state_view)

                if self._block_manager:
                    # add NEW blkw into block manager 
                    LOGGER.debug("ChainController: _set_genesis ADD NEW BLOCK=%s\n",type(blkw))
                    blk = blkw.get_block()
                    self._block_manager.put([blk]) # set ref=1
                    # self._block_manager.ref_block(blk.header_signature)

                validator = BlockValidator(
                    consensus_module=consensus_module,
                    new_block=block,
                    block_cache=self._block_cache,
                    state_view_factory=self._state_view_factory,
                    done_cb=self.on_block_validated,
                    executor=self._transaction_executor,
                    squash_handler=self._squash_handler,
                    context_handlers=self._context_handlers, 
                    identity_signer=self._identity_signer,
                    data_dir=self._data_dir,
                    config_dir=self._config_dir,
                    permission_verifier=self._permission_verifier,
                    metrics_registry=self._metrics_registry,
                    block_manager=self._block_manager)

                valid = validator.validate_block(block)
                if valid:
                    if chain_id is None:
                        self._chain_id_manager.save_block_chain_id(block.identifier)

                    self._block_store.update_chain([block])
                    self._chain_head = block
                    LOGGER.debug("ChainController: _notify_on_chain_updated GENESIS ID=%s\n",self._chain_head.identifier[:8])
                    self._notify_on_chain_updated(self._chain_head)
                else:
                    LOGGER.warning("The genesis block is not valid. Cannot set chain head: %s", block)

        else:
            LOGGER.warning("Cannot set initial chain head, this is not a genesis block: %s", block)

    def _make_receipts(self, results):
        receipts = []
        for result in results:
            receipt = TransactionReceipt()
            receipt.data.extend([data for data in result.data])
            receipt.state_changes.extend(result.state_changes)
            receipt.events.extend(result.events)
            receipt.transaction_id = result.signature
            receipt.timestamp = int(time.time())
            receipts.append(receipt)
            #LOGGER.warning("_MAKE_RECEIPTS  tn_id=%s events=%s",result.signature,result.events)
        #LOGGER.warning("RECEIPTS  events=%s",receipts.signature)
        return receipts
