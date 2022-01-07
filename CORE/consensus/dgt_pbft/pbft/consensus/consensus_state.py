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
# ------------------------------------------------------------------------------

# pylint: disable=too-many-lines

import math
import logging
import collections
import itertools
import threading

import cbor

from pbft.consensus.utils import block_id_is_genesis
from pbft.consensus.pbft_settings_view import PbftSettingsView
from pbft.consensus.signup_info import SignupInfo

from pbft_common.validator_registry_view.validator_registry_view import ValidatorRegistryView
from dgt_sdk.protobuf.pbft_consensus_pb2 import PbftMessage,PbftMessageInfo,PbftBlockMessage
#from dgt_validator.protobuf.pbft_consensus_pb2 import PbftMessage,PbftMessageInfo,PbftBlockMessage,PbftViewChange,PbftSeal
#from pbft_common.protobuf.pbft_consensus_pb2 import PbftMessage,PbftMessageInfo,PbftBlockMessage
from pbft_common.utils import _short_id

LOGGER = logging.getLogger(__name__)

ValidatorState = collections.namedtuple('ValidatorState',['key_block_claim_count','pbft_public_key','total_block_claim_count'])
""" Instead of creating a full-fledged class, let's use a named tuple for
the validator state.  The validator state represents the state for a single
validator at a point in time.  A validator state object contains:

key_block_claim_count (int): The number of blocks that the validator has
claimed using the current PBFT public key
pbft_public_key (str): The current PBFT public key for the validator
total_block_claim_count (int): The total number of the blocks that the
    validator has claimed
"""


class ConsensusState:
    """Represents the consensus state at a particular point in time (i.e.,
    when the block that this consensus state corresponds to was committed to
    the block chain).

    Attributes:
        aggregate_local_mean (float): The sum of the local means for the PBFT
            blocks since the last non-PBFT block
        total_block_claim_count (int): The number of blocks that have been
            claimed by all validators
    """

    # MINIMUM_WAIT_TIME must match the constants in the enclaves
    MINIMUM_WAIT_TIME = 1.0
    STEP_LIST = ['NotStarted', 'PrePreparing', 'Preparing', 'Checking', 'Committing', 'Finished','Ignored','Commited']

    _BlockInfo = collections.namedtuple('_BlockInfo',['wait_certificate', 'validator_info', 'pbft_settings_view'])

    """ Instead of creating a full-fledged class, let's use a named tuple for
    the block info.  The block info represents the information we need to
    create consensus state.  A block info object contains:

    wait_certificate (WaitCertificate): The PBFT wait certificate object for
        the block
    validator_info (BgxValidatorInfo): The validator registry information for the
        validator that claimed the block
    pbft_settings_view (BgtSettingsView): The PBFT settings view associated
        with the block
    """

    _PopulationSample = collections.namedtuple('_PopulationSample', ['duration', 'local_mean'])

    """ Instead of creating a full-fledged class, let's use a named tuple for
    the population sample.  The population sample represents the information
    we need to create the population estimate, which in turn is used to compute
    the local mean.  A population sample object contains:

    duration (float): The duration from a wait certificate/timer
    local_mean (float): The local mean from a wait certificate/timer
    """

    _EstimateInfo = collections.namedtuple('_EstimateInfo',['population_estimate','previous_block_id','validator_id'])

    """ Instead of creating a full-fledged class, let's use a named tuple for
    the population estimates.  The population estimate represents what we need
    to help in computing zTest results.  A population estimate object contains:

    population_estimate (float): The population estimate for the corresponding
        block
    previous_block_id (str): The ID of the block previous to the one that this
        population estimate corresponds to
    validator_id (str): The ID of the validator that won the corresponding
        block
    """

    # The population estimate cache is a mapping of block ID to its
    # corresponding _EstimateInfo object.  This is used so that when building
    # the population list, we don't have to always walk back the entire list
    _population_estimate_cache = {}
    _population_estimate_cache_lock = threading.Lock()

    @staticmethod
    def consensus_state_for_block_id(block_id,
                                     block_cache,
                                     state_view_factory,
                                     consensus_state_store,
                                     node=None,force=True):
        """Returns the consensus state for the block referenced by block ID,
            creating it from the consensus state history if necessary.

        Args:
            block_id (str): The ID of the block for which consensus state will
                be returned.
            block_cache (BlockCache): The block store cache
            state_view_factory (StateViewFactory): A factory that can be used
                to create state view object corresponding to blocks
            consensus_state_store (ConsensusStateStore): The consensus state
                store that is used to store interim consensus state created
                up to resulting consensus state
            

        Returns:
            ConsensusState object representing the consensus state for the
                block referenced by block_id
        """
        #LOGGER.debug('ConsensusState: consensus_state_for_block_id for block_id=%s',block_id)
        consensus_state = None
        #previous_wait_certificate = None
        #blocks = collections.OrderedDict()

        # Starting at the chain head, walk the block store backwards until we
        # either get to the root or we get a block for which we have already
        # created consensus state
        current_id = block_id
        #block = ConsensusState._block_for_id(block_id=current_id,block_cache=block_cache)
        #LOGGER.debug("ConsensusState: BLOCK for block_id=%s block=%s",_short_id(current_id),block)
        #LOGGER.debug("ConsensusState: ASK STATE for block_id=%s",current_id)
        consensus_state = consensus_state_store.get(block_id=current_id)
        if consensus_state is not None:
            
            LOGGER.debug("ConsensusState: FOUND CONSENSUS_STATE for block_id=%s",_short_id(current_id))
            pass
        elif force :
            
            LOGGER.debug("ConsensusState: CREATE CONSENSUS_STATE node=%s for block_id=%s",node,_short_id(current_id))
            consensus_state = ConsensusState(node)
        else:
            return None

        return consensus_state
        """
        while True:
            LOGGER.debug("ConsensusState: ASK block for id=%s",current_id)
            block = ConsensusState._block_for_id(block_id=current_id,block_cache=block_cache)
            if block is None:
                LOGGER.debug("ConsensusState: walk to ROOT block_id=%s",current_id)
                break

            # Try to fetch the consensus state.  If that succeeds, we can
            # stop walking back as we can now build on that consensus
            # state.
            consensus_state = consensus_state_store.get(block_id=current_id)
            if consensus_state is not None:
                LOGGER.debug("ConsensusState: FOUND CONSENSUS_STATE=%s for block_id=%s",consensus_state,current_id)
                break
            # Move to the previous block
            current_id = block.previous_block_id

        # At this point, if we have not found any consensus state, we need to
        # create default state from which we can build upon
        if consensus_state is None:
            LOGGER.debug("ConsensusState: EMPTY CONSENSUS_STATE node=%s for block_id=%s",node,current_id)
            consensus_state = ConsensusState(node)

        # Now, walk through the blocks for which we were supposed to create
        # consensus state, from oldest to newest (i.e., in the reverse order in
        # which they were added), and store state for PBFT blocks so that the
        # next time we don't have to walk so far back through the block chain.
        LOGGER.debug("ConsensusState: return CONSENSUS_STATE=%s done",consensus_state)
        return consensus_state
        """

    def __init__(self,node=None):
        """
        Initialize a ConsensusState object

        Returns:
            None
        """
        self._aggregate_local_mean = 0.0
        self._local_mean = None
        self._population_samples = collections.deque()
        self._total_block_claim_count = 0
        self._validators = {}
        # pbft 
        self._is_own = False
        self._published = True
        self._step = 0 # NotStarted, PrePreparing, Preparing, Checking, Committing, Finished 
        self._mode = "Normal"     # Normal, ViewChanging, Checkpointing
        self._sequence_number = 0
        self._node = node if node else 'plink'
        self._block_id = None
        self._block = None
        self._block_valid = {}
        self._summary = 'None'
        self._unknown_block = False
        self._new_block = False
        self._wait_check = False
        self._committers = {}
        self._commits = 0
        self._blocks = []
        #LOGGER.debug("ConsensusState: __init__ node=%s",self._node)

    def set_consensus_state_for_block_id(self,block_id,consensus_state_store):
        consensus_state_store[block_id] = self
        

    def shift_sequence_number(self,block_id,consensus_state_store):
        self._sequence_number += 1
        self.set_consensus_state_for_block_id(block_id,consensus_state_store)

    @property
    def aggregate_local_mean(self):
        return self._aggregate_local_mean

    @property
    def total_block_claim_count(self):
        return self._total_block_claim_count

    @property
    def step(self):
        return ConsensusState.STEP_LIST[self._step]

    @property
    def node(self):
        return self._node

    @property
    def is_own(self):
        return self._is_own

    @property
    def published(self):
        return self._published


    @property
    def unknown_block(self):
        return self._unknown_block


    @property
    def block_id(self):
        return self._block_id


    @property
    def commits(self):
        return self._commits


    def block_valid(self,block_id):
        return block_id in self._block_valid


    @property
    def wait_check(self):
        return self._wait_check


    @property
    def new_block(self):
        return self._new_block

    @property
    def block(self):
        if self._block is None:
            return None
        #block = PbftBlockMessage().ParseFromString(self._block)
        dblock = cbor.loads(self._block)
        block = PbftBlockMessage(
                    block_id  = dblock['block_id'],
                    signer_id = dblock['signer_id'],
                    block_num = dblock['block_num'],
                    summary   = dblock['summary'] 
                )
        #LOGGER.debug("ConsensusState: get_block[%s] '%s'",type(block),dblock)
        return block 


    @property
    def summary(self):
        return self._summary

    def reset_step(self):
        self._step = 0

    def set_ignored_step(self):
        self._step = 6
    def set_commited_step(self):
        self._step = 7

    def next_step(self):
        self._step += 1
        self._step = self._step % (len(ConsensusState.STEP_LIST)-1)

    def set_published(self,val=False):
        """
        We need publish again for our own block
        """
        self._published = val

    def set_block_id(self,id=None):
        """
        Set external block id for summary map 
        """
        self._block_id = id

    def set_block_valid(self,block_id):
        
        if block_id not in self._block_valid:
            self._block_valid [block_id] = True

    def add_committer(self,signer_id):
        if signer_id not in self._committers:
            self._committers [signer_id] = True
            self._commits += 1

    def try_commit(self,block_id):
        self._blocks.append(block_id)
        LOGGER.debug("try_commit blocks=[%s]",self._blocks)
        for id in self._blocks:
            if id > block_id:
                return False
        
        return True
    def set_wait_check(self):
        self._wait_check = True


    def set_new_block(self):
        self._new_block = True

    def set_block(self,block=None):
        """
        Set external block  for summary map 
        """
        dblock = {'block_id' : block.block_id,
                  'signer_id' : block.signer_id,
                  'block_num' : block.block_num,
                  'summary' :  block.summary
                  }
        self._block = cbor.dumps(dblock) # block.SerializeToString()
        #LOGGER.debug("ConsensusState: set_block[%s] '%s'",type(block),self._block)

    def set_summary(self,summary='None'):
        self._summary = summary

    def set_node(self,node):
        self._node = node

    def set_unknown_block(self):
        self._unknown_block = True


    def mark_as_own(self):
        self._is_own = True
    
    @property
    def is_step_NotStarted(self):
        return self._step == 0
    @property
    def is_step_PrePreparing(self):
        return self._step == 1

    @property
    def is_step_Preparing(self):
        return self._step == 2

    @property
    def is_step_Checking(self):
        return self._step == 3

    @property
    def is_step_Committing(self):
        return self._step == 4
    @property
    def is_step_Finished(self):
        return self._step == 5

    @property
    def is_step_Ignored(self):
        return self._step == 6


    @property
    def is_step_Commited(self):
        return self._step == 7

    @step.setter
    def set_step(self, value):
        self._step = value 

    @property
    def mode(self):
        return self._mode

    @property
    def sequence_number(self):
        return self._sequence_number

    @property
    def aggregate_local_mean(self):
        return self._aggregate_local_mean

    @staticmethod
    def _check_validator_state(validator_state):
        if not isinstance(
                validator_state.key_block_claim_count, int) \
                or validator_state.key_block_claim_count < 0:
            raise \
                ValueError(
                    'key_block_claim_count ({}) is invalid'.format(
                        validator_state.key_block_claim_count))

        if not isinstance(
                validator_state.pbft_public_key, str) \
                or not validator_state.pbft_public_key:
            raise \
                ValueError(
                    'pbft_public_key ({}) is invalid'.format(
                        validator_state.pbft_public_key))

        if not isinstance(
                validator_state.total_block_claim_count, int) \
                or validator_state.total_block_claim_count < 0:
            raise \
                ValueError(
                    'total_block_claim_count ({}) is invalid'.format(
                        validator_state.total_block_claim_count))

        if validator_state.key_block_claim_count > \
                validator_state.total_block_claim_count:
            raise \
                ValueError(
                    'total_block_claim_count ({}) is less than '
                    'key_block_claim_count ({})'.format(
                        validator_state.total_block_claim_count,
                        validator_state.key_block_claim_count))

    @staticmethod
    def _block_for_id(block_id, block_cache):
        """A convenience method retrieving a block given a block ID. Takes
        care of the special case of NULL_BLOCK_IDENTIFIER.

        Args:
            block_id (str): The ID of block to retrieve.
            block_cache (BlockCache): Block cache from which block will be
                retrieved.

        Returns:
            BlockWrapper for block, or None for no block found.
        """
        block = None
        try:
            block = None if block_id_is_genesis(block_id) else block_cache[block_id]
        except KeyError:
            LOGGER.error('Failed to retrieve block: %s', block_id[:8])

        return block

    def get_validator_state(self, validator_info):
        """Return the validator state for a particular validator
        Args:
            validator_info (BgxValidatorInfo): The validator information for the
                validator for which validator or state information is being
                requested
        Returns:
            ValidatorState: The validator state if it exists or the default
                initial state if it does not
        """
        LOGGER.debug("ConsensusState: get_validator_state %s='%s' num=%s",validator_info.node,validator_info.name,len(self._validators))
        # Fetch the validator state.  If it doesn't exist, then create a
        # default validator state object and store it for further requests
        validator_state = self._validators.get(validator_info.id)

        if validator_state is None:
            validator_state = ValidatorState(
                    key_block_claim_count=0,
                    pbft_public_key=validator_info.signup_info.
                    pbft_public_key,
                    total_block_claim_count=0)
            self._validators[validator_info.id] = validator_state
            LOGGER.debug("ConsensusState: add validator %s='%s' num=%s",validator_info.node,validator_info.name,len(self._validators))
        else:
            LOGGER.debug("ConsensusState: validator %s='%s' already in list",validator_info.node,validator_info.name)
        return validator_state


    def signup_attempt_timed_out(self,
                                 signup_nonce,
                                 pbft_settings_view,
                                 block_cache):
        """Checks whether too many blocks have elapsed since
        since the registration attempt.

        Args:
            signup_nonce (string): nonce (~ block id) used in signup
            pbft_settings_view (BgtSettingsView): The current Bgt config view
            block_cache (BlockCache): The block store cache

        Returns:
            bool: True if too many blocks have elapsed; False if you just need
            to chill out a little while longer.
        """
        # It's tempting to set this timeout as the lesser of retry_delay
        # and signup_commit_maximum_delay, but then we can't individually
        # control this timeout behavior. Consider behavior as a new node joins
        # an old network.
        depth = pbft_settings_view.registration_retry_delay

        i = 0
        for block in block_cache.block_store.get_block_iter(reverse=True):
            if i > depth:
                return True
            block_id = block.identifier
            if signup_nonce == SignupInfo.block_id_to_nonce(block_id):
                return False
            i += 1
        return False

    def validator_has_claimed_block_limit(self,validator_info,pbft_settings_view):
        """
        Determines if a validator has already claimed the maximum number of
        blocks allowed with its PBFT key pair.
        Args:
            validator_info (BgxValidatorInfo): The current validator information
            pbft_settings_view (BgtSettingsView): The current Bgt config view
        Returns:
            bool: True if the validator has already claimed the maximum
                number of blocks with its current PBFT key pair, False
                otherwise
        """
        key_block_claim_limit = pbft_settings_view.key_block_claim_limit
        validator_state = self.get_validator_state(validator_info=validator_info)

        if validator_state.pbft_public_key == \
                validator_info.signup_info.pbft_public_key:
            if validator_state.key_block_claim_count >= key_block_claim_limit:
                LOGGER.info(
                    'Validator %s (ID=%s...%s): Reached block claim limit '
                    'for PBFT keys %d >= %d',
                    validator_info.name,
                    validator_info.id[:8],
                    validator_info.id[-8:],
                    validator_state.key_block_claim_count,
                    key_block_claim_limit)
                return True

            LOGGER.debug(
                'Validator %s (ID=%s...%s): Claimed %d block(s) out of %d',
                validator_info.name,
                validator_info.id[:8],
                validator_info.id[-8:],
                validator_state.key_block_claim_count,
                key_block_claim_limit)

        else:
            LOGGER.debug(
                'Validator %s (ID=%s...%s): Claimed 0 block(s) out of %d',
                validator_info.name,
                validator_info.id[:8],
                validator_info.id[-8:],
                key_block_claim_limit)

        return False

    def serialize_to_bytes(self):
        """Serialized the consensus state object to a byte string suitable
        for storage

        Returns:
            bytes: serialized version of the consensus state object
        """
        # For serialization, the easiest thing to do is to convert ourself to
        # a dictionary and convert to CBOR.  The deque object cannot be
        # automatically serialized, so convert it to a list first.  We will
        # reconstitute it to a deque upon parsing.
        self_dict = {
            '_aggregate_local_mean': self._aggregate_local_mean,
            '_population_samples': list(self._population_samples),
            '_total_block_claim_count': self._total_block_claim_count,
            '_mode': self._mode,
            '_step': self._step,
            '_node': self._node,
            '_is_own': self._is_own,
            '_block_id': self._block_id,
            '_block_valid': self._block_valid,
            '_block' : self._block,
            '_summary' : self._summary,
            '_wait_check' : self._wait_check,
            '_unknown_block' : self._unknown_block,
            '_new_block' : self._new_block,
            '_sequence_number': self._sequence_number,
            '_validators': self._validators,
            '_committers':self._committers,
            '_commits': self._commits,
            '_blocks': self._blocks
        }
        return cbor.dumps(self_dict)

    def parse_from_bytes(self, buffer):
        """Returns a consensus state object re-created from the serialized
        consensus state provided.

        Args:
            buffer (bytes): A byte string representing the serialized
                version of a consensus state to re-create.  This was created
                by a previous call to serialize_to_bytes

        Returns:
            ConsensusState: object representing the serialized byte string
                provided

        Raises:
            ValueError: failure to parse into a valid ConsensusState object
        """
        try:
            # Deserialize the CBOR back into a dictionary and set the simple
            # fields, doing our best to check validity.
            self_dict = cbor.loads(buffer)

            if not isinstance(self_dict, dict):
                raise ValueError('buffer is not a valid serialization of a ConsensusState object')


            self._mode = self_dict['_mode']
            self._step = self_dict['_step']
            self._node = self_dict['_node']
            self._is_own = self_dict['_is_own']
            self._block_id = self_dict['_block_id']
            self._block_valid = self_dict['_block_valid']
            self._block = self_dict['_block']
            self._summary = self_dict['_summary']
            self._unknown_block = self_dict['_unknown_block']
            self._new_block = self_dict['_new_block']
            self._wait_check = self_dict['_wait_check']
            self._commits = self_dict['_commits']
            self._committers = self_dict['_committers']
            self._blocks = self_dict['_blocks']

            self._sequence_number = int(self_dict['_sequence_number'])
            self._aggregate_local_mean = float(self_dict['_aggregate_local_mean'])
            self._local_mean = None
            self._population_samples = collections.deque()
            for sample in self_dict['_population_samples']:
                (duration, local_mean) = [float(value) for value in sample]
                if not math.isfinite(duration) or duration < 0:
                    raise \
                        ValueError(
                            'duration ({}) is invalid'.format(duration))
                if not math.isfinite(local_mean) or local_mean < 0:
                    raise \
                        ValueError(
                            'local_mean ({}) is invalid'.format(local_mean))
                self._population_samples.append(
                    ConsensusState._PopulationSample(
                        duration=duration,
                        local_mean=local_mean))
            self._total_block_claim_count = \
                int(self_dict['_total_block_claim_count'])
            validators = self_dict['_validators']

            if not math.isfinite(self.aggregate_local_mean) or \
                    self.aggregate_local_mean < 0:
                raise ValueError('aggregate_local_mean ({}) is invalid'.format(self.aggregate_local_mean))
            if self.total_block_claim_count < 0:
                raise ValueError('total_block_claim_count ({}) is invalid'.format(self.total_block_claim_count))

            if not isinstance(validators, dict):
                raise ValueError('_validators is not a dict')

            # Now walk through all of the key/value pairs in the the
            # validators dictionary and reconstitute the validator state from
            # them, again trying to validate the data the best we can.  The
            # only catch is that because the validator state objects are named
            # tuples, cbor.dumps() treated them as tuples and so we lost the
            # named part.  When re-creating the validator state, are going to
            # leverage the namedtuple's _make method.

            self._validators = {}
            for key, value in validators.items():
                validator_state = ValidatorState._make(value)

                self._check_validator_state(validator_state)
                self._validators[str(key)] = validator_state

        except (LookupError, ValueError, KeyError, TypeError) as error:
            raise \
                ValueError(
                    'Error parsing ConsensusState buffer: {}'.format(error))

    def __str__(self):
        validators = \
            ['{}: {{KBCC={}, PPK={}, TBCC={} }}'.format(
                key[:8],
                value.key_block_claim_count,
                value.pbft_public_key[:8],
                value.total_block_claim_count) for
             key, value in self._validators.items()]

        return \
            'mode={},step={},node={},SEQNUM={},ID={},CHECK={},PEERS={}'.format(
                self._mode,
                self.step,
                self._node,
                self._sequence_number,
                'None' if self._block is None else 'block',
                self._wait_check,
                validators
                )
