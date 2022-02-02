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

from base64 import b64encode
import logging
import hashlib
import time
import json
import random
import base64
try:
    import dgt_sdk.protobuf.transaction_pb2 as txn_pb
except TypeError:
    import dgt_validator.protobuf.transaction_pb2 as txn_pb

from pbft.journal.block_wrapper import BlockWrapper
from pbft.journal.consensus.consensus import BlockPublisherInterface
from pbft.state.settings_view import SettingsView
#from pbft.consensus import pbft_enclave_factory as factory
from pbft.consensus.consensus_state import ConsensusState
from pbft.consensus.consensus_state_store import ConsensusStateStore
from pbft.consensus.pbft_settings_view import PbftSettingsView
from pbft.consensus.signup_info import SignupInfo
from pbft.consensus.pbft_key_state_store import PbftKeyState
from pbft.consensus.pbft_key_state_store import PbftKeyStateStore

#import pbft.enclave.pbft_enclave as PBFT_ENCLAVE_MODULE
#from pbft.consensus.wait_timer import WaitTimer
#from pbft.consensus.wait_certificate import WaitCertificate
from pbft.consensus import utils
from pbft_common.utils import json2dict
from pbft_common.utils import dict2json
#import dgt_validator.protobuf.bgx_validator_registry_pb2 as vr_pb
import pbft_common.protobuf.bgx_validator_registry_pb2 as vr_pb
from pbft_common.validator_registry_view.validator_registry_view import ValidatorRegistryView
from pbft_common.utils import _short_id

from  dgt_settings.protobuf.settings_pb2 import SettingProposal
from  dgt_settings.protobuf.settings_pb2 import SettingsPayload

LOGGER = logging.getLogger(__name__)

SETTINGS_NAMESPACE = '000000'
_VREG_ = False
_MIN_PRINT_WIDTH = 15
_MAX_KEY_PARTS = 4
_ADDRESS_PART_SIZE = 16

def _short_hash(in_str):
    return hashlib.sha256(in_str.encode()).hexdigest()[:_ADDRESS_PART_SIZE]

def _key_to_address(key):
    """Creates the state address for a given setting key.
    """
    key_parts = key.split('.', maxsplit=_MAX_KEY_PARTS - 1)
    key_parts.extend([''] * (_MAX_KEY_PARTS - len(key_parts)))

    return SETTINGS_NAMESPACE + ''.join(_short_hash(x) for x in key_parts)

def _config_inputs(key):
    """Creates the list of inputs for a sawtooth_settings transaction, for a
    given setting key.
    """
    return [
        _key_to_address('sawtooth.settings.vote.proposals'),
        _key_to_address('sawtooth.settings.vote.authorized_keys'),
        _key_to_address('sawtooth.settings.vote.approval_threshold'),
        _key_to_address(key)
    ]


def _config_outputs(key):
    """Creates the list of outputs for a sawtooth_settings transaction, for a
    given setting key.
    """
    return [
        _key_to_address('sawtooth.settings.vote.proposals'),
        _key_to_address(key)
    ]


class PbftBlockPublisher(BlockPublisherInterface):
    """Consensus objects provide the following services to the Journal:
    1) Build candidate blocks ( this temporary until the block types are
    combined into a single block type)
    2) Check if it is time to claim the current candidate blocks.
    3) Provide the data a signatures required for a block to be validated by
    other consensus algorithms
    """

    _previous_block_id = None

    _validator_registry_namespace = hashlib.sha256('validator_registry'.encode()).hexdigest()[0:6]
    _validator_map_address = _validator_registry_namespace + hashlib.sha256('validator_map'.encode()).hexdigest()

    def __init__(self,
                 block_cache,
                 state_view_factory,
                 batch_publisher,
                 data_dir,
                 config_dir,
                 validator_id,
                 node):
        """Initialize the object, is passed (read-only) state access objects.
            Args:
                block_cache (BlockCache): Dict interface to the block cache.
                    Any predecessor block to blocks handed to this object will
                    be present in this dict.
                state_view_factory (StateViewFactory): A factory that can be
                    used to create read-only views of state for a particular
                    merkle root, in particular the state as it existed when a
                    particular block was the chain head.
                batch_publisher (BatchPublisher): An interface implementing
                    send(txn_list) which wrap the transactions in a batch and
                    broadcast that batch to the network.
                data_dir (str): path to location where persistent data for the
                    consensus module can be stored.
                config_dir (str): path to location where configuration for the
                    consensus module can be found.
                validator_id (str): A unique ID for this validator
            Returns:
                none.
        """
        super().__init__(
            block_cache,
            state_view_factory,
            batch_publisher,
            data_dir,
            config_dir,
            validator_id)

        self._block_cache = block_cache
        self._state_view_factory = state_view_factory
        self._batch_publisher = batch_publisher
        self._data_dir = data_dir
        self._config_dir = config_dir
        self._validator_id = validator_id
        self._node = node if node else 'plink'
        LOGGER.debug('PbftBlockPublisher:: CREATE ConsensusStateStore')
        self._consensus_state_store = ConsensusStateStore(data_dir=self._data_dir,validator_id=self._validator_id)
        self._pbft_key_state_store = PbftKeyStateStore(data_dir=self._data_dir,validator_id=self._validator_id)
        self._wait_timer = None
        self._block_id = None

    def _create_proposal(self, block_header, pbft_enclave_module):
        """
        proposal request
        """
        public_key_hash = hashlib.sha256(block_header.signer_public_key.encode()).hexdigest()
        nonce = SignupInfo.block_id_to_nonce(block_header.previous_block_id)

        setting = 'dgt.consensus.pbft.max_log_size'
        if False:
            # try to set pbft params
            
            proposal = SettingProposal(
                 setting=setting,
                 value='1003',
                 nonce=nonce)
            payload = SettingsPayload(data=proposal.SerializeToString(),action=SettingsPayload.PROPOSE)
            serialized = payload.SerializeToString()
            input_addresses = _config_inputs(setting) 
            output_addresses = _config_outputs(setting)

            header = txn_pb.TransactionHeader(
                signer_public_key=block_header.signer_public_key,
                family_name='sawtooth_settings',
                family_version='1.0',
                inputs=input_addresses,
                outputs=output_addresses,
                dependencies=[],
                payload_sha512=hashlib.sha512(serialized).hexdigest(),
                batcher_public_key=block_header.signer_public_key,
                nonce=hex(random.randint(0, 2**64))).SerializeToString()

            signature = self._batch_publisher.identity_signer.sign(header)

            transaction = txn_pb.Transaction(
                    header=header,
                    payload=serialized,
                    header_signature=signature)

            LOGGER.info('payload action=%s nonce=%s',
                payload.action,
                nonce)

            self._batch_publisher.send([transaction])
        else:
            # get setting
            pass


    def _register_signup_information(self, block_header, pbft_enclave_module=None):
        # Create signup information for this validator, putting the block ID
        # of the block previous to the block referenced by block_header in the
        # nonce.  Block ID is better than wait certificate ID for testing
        # freshness as we need to account for non-BGT blocks.
        LOGGER.debug('PbftBlockPublisher::_register_signup_information: TRY to REGISTER')
        public_key_hash = hashlib.sha256(block_header.signer_public_key.encode()).hexdigest()
        nonce = SignupInfo.block_id_to_nonce(block_header.previous_block_id)
        pbft_public_key = self._validator_id
        anti_sybil_id = hashlib.sha256(pbft_public_key.encode()).hexdigest()
        signup_data = {
                'pbft_public_key': pbft_public_key,
            }
        sealed_signup_data = base64.b64encode(dict2json(signup_data).encode()).decode('utf-8')
        """
        signup_info = SignupInfo.create_signup_info(
                pbft_enclave_module=pbft_enclave_module,
                originator_public_key_hash=public_key_hash,
                nonce=nonce)
        """
        # Create the validator registry payload
        payload = vr_pb.BgxValidatorRegistryPayload(
                verb='register',
                name='validator-{}'.format(block_header.signer_public_key[:8]),
                id=block_header.signer_public_key,
                node = self._node,
                signup_info=vr_pb.BgxSignUpInfo(
                    pbft_public_key=pbft_public_key, # signup_info.pbft_public_key,
                    anti_sybil_id= anti_sybil_id, # signup_info.anti_sybil_id,
                    nonce=nonce),
            )
        serialized = payload.SerializeToString()

        # Create the address that will be used to look up this validator
        # registry transaction.  Seems like a potential for refactoring..
        validator_entry_address = PbftBlockPublisher._validator_registry_namespace + hashlib.sha256(block_header.signer_public_key.encode()).hexdigest()

        # Create a transaction header and transaction for the validator
        # registry update amd then hand it off to the batch publisher to
        # send out.
        output_addresses = [validator_entry_address,PbftBlockPublisher._validator_map_address]
        input_addresses = output_addresses + \
            [SettingsView.setting_address('sawtooth.pbft.report_public_key_pem'),
             SettingsView.setting_address('sawtooth.pbft.valid_enclave_measurements'),
             SettingsView.setting_address('sawtooth.pbft.valid_enclave_basenames')
            ]

        header = txn_pb.TransactionHeader(
                signer_public_key=block_header.signer_public_key,
                family_name='bgx_validator_registry',
                family_version='1.0',
                inputs=input_addresses,
                outputs=output_addresses,
                dependencies=[],
                payload_sha512=hashlib.sha512(serialized).hexdigest(),
                batcher_public_key=block_header.signer_public_key,
                nonce=hex(random.randint(0, 2**64))).SerializeToString()

        signature = self._batch_publisher.identity_signer.sign(header)

        transaction = txn_pb.Transaction(
                header=header,
                payload=serialized,
                header_signature=signature)

        LOGGER.info(
            'PbftBlockPublisher::Register Validator Name=%s, ID=%s...%s,Nonce=%s',
            payload.name,
            payload.id[:8],
            payload.id[-8:],
            nonce)

        self._batch_publisher.send([transaction])

        # Store the key state so that we can look it up later if need be and
        # set the new key as our active key
        self._pbft_key_state_store[pbft_public_key] = PbftKeyState(
                sealed_signup_data=sealed_signup_data,
                has_been_refreshed=False,
                signup_nonce=nonce)
        self._pbft_key_state_store.active_key = pbft_public_key
        LOGGER.debug('PbftBlockPublisher::_register_signup_information: REGISTER DONE')

    def _handle_registration_timeout(self, block_header, pbft_enclave_module,
                                     state_view, signup_nonce,
                                     pbft_public_key):
        # See if a registration attempt has timed out. Assumes the caller has
        # checked for a committed registration and did not find it.
        # If it has timed out then this method will re-register.
        LOGGER.debug("PbftBlockPublisher::_handle_registration_timeout:ADD CONSENSUS_STATE for block_id=%s",block_header.previous_block_id)
        consensus_state = ConsensusState.consensus_state_for_block_id(
                block_id=block_header.previous_block_id,
                block_cache=self._block_cache,
                state_view_factory=self._state_view_factory,
                consensus_state_store=self._consensus_state_store,
                pbft_enclave_module=None #pbft_enclave_module
            )
        """
        # for getting PBFT settings from chain
        pbft_settings_view = PbftSettingsView(state_view)

        if consensus_state.signup_attempt_timed_out(signup_nonce, pbft_settings_view, self._block_cache):
            LOGGER.error('My pbft registration using PPK %s has not committed by block %s. Create new registration',
                         pbft_public_key,
                         block_header.previous_block_id)

            del self._pbft_key_state_store[pbft_public_key]
            self._register_signup_information(
                block_header=block_header,
                pbft_enclave_module=pbft_enclave_module
                )
        """

    def initialize_block(self, block_header):
        """Do initialization necessary for the consensus to claim a block,
        this may include initiating voting activities, starting proof of work
        hash generation, or create a PBFT wait timer.

        Args:
            block_header (BlockHeader): The BlockHeader to initialize.
        Returns:
            Boolean: True if the candidate block should be built. False if
            no candidate should be built.
        """
        LOGGER.debug('PbftBlockPublisher::initialize_block previous_block_id=%s (%s)',_short_id(block_header.previous_block_id),block_header)
        # If the previous block ID matches our cached one, that means that we
        # have already determined that even if we initialize the requested
        # block we would not be able to claim it.  So, instead of wasting time
        # doing all of the checking again, simply short-circuit the failure so
        # that the validator can go do something more useful.
        if block_header.previous_block_id == PbftBlockPublisher._previous_block_id:
            LOGGER.debug("PbftBlockPublisher::initialize_block block_header.previous_block_id == PbftBlockPublisher._previous_block_id TRUE")
            return False
        PbftBlockPublisher._previous_block_id = block_header.previous_block_id
        # Using the current chain head, we need to create a state view so we
        # can create a PBFT enclave.
        if False:
            state_view = BlockWrapper.state_view_for_block(
                    block_wrapper=self._block_cache.block_store.chain_head,
                    state_view_factory=self._state_view_factory)

            pbft_settings_view = PbftSettingsView(state_view)
            LOGGER.debug("PbftBlockPublisher::pbft_settings_view node=%s",pbft_settings_view.pbft_node)
        #self._node = pbft_settings_view.pbft_node
        
        consensus_state = ConsensusState.consensus_state_for_block_id(
                block_id=block_header.previous_block_id,
                block_cache=self._block_cache,
                state_view_factory=self._state_view_factory,
                consensus_state_store=self._consensus_state_store,
                node=self._node
                )
        # shift into PrePrepare state
        consensus_state.next_step()
        #consensus_state.mark_as_own()
        consensus_state.set_consensus_state_for_block_id(block_header.previous_block_id,self._consensus_state_store)
        self._block_id = block_header.previous_block_id
        #consensus_state.set_node(self._node)
        LOGGER.debug("PbftBlockPublisher::initialize_block GET CONSENSUS_STATE=%s for block_id=%s ",consensus_state,_short_id(block_header.previous_block_id))
        # start 
        # Get our validator registry entry to see what PBFT public key
        # other validators think we are using.

        if _VREG_:
            validator_registry_view = ValidatorRegistryView(state_view)
            validator_info = None

            try:
                validator_id = block_header.signer_public_key
                validator_info = validator_registry_view.get_validator_info(validator_id=validator_id)
            except KeyError:
                pass

            # If we don't have a validator registry entry, then check the active
            # key.  If we don't have one, then we need to sign up.  If we do have
            # one, then our validator registry entry has not percolated through the
            # system, so nothing to to but wait.
            active_pbft_public_key = self._pbft_key_state_store.active_key
            if validator_info is None:
                if active_pbft_public_key is None:
                    LOGGER.debug('PbftBlockPublisher::initialize_block No public key found, so going to register new signup information')
                    self._register_signup_information(block_header=block_header)

                else:  # Check if we need to give up on this registration attempt
                    try:
                        nonce = self._pbft_key_state_store[active_pbft_public_key].signup_nonce
                    except (ValueError, AttributeError):
                        self._pbft_key_state_store.active_key = None
                        LOGGER.warning('PbftBlockPublisher::initialize_block Pbft Key State Store had inaccessible or '
                                       'corrupt active key [%s] clearing '
                                       'key.', active_pbft_public_key)
                        return False
                    LOGGER.debug('PbftBlockPublisher::initialize_block Check if we need to give up on this registration attempt')
                    self._handle_registration_timeout(
                        block_header=block_header,
                        pbft_enclave_module=None,#pbft_enclave_module,
                            state_view=state_view,
                        signup_nonce=nonce,
                        pbft_public_key=active_pbft_public_key
                    )
                LOGGER.debug("PbftBlockPublisher::initialize_block validator_info NONE")
                return True #False

                # Retrieve the key state corresponding to the PBFT public key in our
                # validator registry entry.
                pbft_key_state = None
                try:
                    pbft_key_state = self._pbft_key_state_store[validator_info.signup_info.pbft_public_key]
                except (ValueError, KeyError):
                    pass

                # If there is no key state associated with the PBFT public key that
                # other validators think we should be using, then we need to create
                # new signup information as we have no way whatsoever to publish
                # blocks that other validators will accept.
                LOGGER.debug("PbftBlockPublisher::check pbft_key_state=%s",pbft_key_state)
                if pbft_key_state is None:
                    LOGGER.debug('PbftBlockPublisher::initialize_block PBFT public key %s...%s in validator registry not found in key state store.  Sign up again',
                        validator_info.signup_info.pbft_public_key[:8],
                        validator_info.signup_info.pbft_public_key[-8:])
                    self._register_signup_information(block_header=block_header)

                    # We need to put fake information in the key state store for the
                    # PBFT public key the other validators think we are using so that
                    # we don't try to keep signing up.  However, we are going to mark
                    # that key state store entry as being refreshed so that we will
                    # never actually try to use it.
                    dummy_data = b64encode(b'No sealed signup data').decode('utf-8')
                    self._pbft_key_state_store[validator_info.signup_info.pbft_public_key] = PbftKeyState(
                            sealed_signup_data=dummy_data,
                            has_been_refreshed=True,
                            signup_nonce='unknown')

                    return False

        # Check the key state.  If it is marked as being refreshed, then we are
        # waiting until our PBFT public key is updated in the validator
        # registry and therefore we cannot publish any blocks.
        if _VREG_ and pbft_key_state.has_been_refreshed:
            LOGGER.debug(
                'PBFT public key %s...%s has been refreshed.  Wait for new '
                'key to show up in validator registry.',
                validator_info.signup_info.pbft_public_key[:8],
                validator_info.signup_info.pbft_public_key[-8:])

            # Check if we need to give up on this registration attempt
            self._handle_registration_timeout(
                block_header=block_header,
                pbft_enclave_module=pbft_enclave_module,
                state_view=state_view,
                signup_nonce=pbft_key_state.signup_nonce,
                pbft_public_key=active_pbft_public_key
            )
            return False

        # If the PBFT public key in the validator registry is not the active
        # one, then we need to switch the active key in the key state store.
        if _VREG_:
            if validator_info.signup_info.pbft_public_key != active_pbft_public_key:
                active_pbft_public_key = validator_info.signup_info.pbft_public_key
                self._pbft_key_state_store.active_key = active_pbft_public_key

            # Ensure that the enclave is using the appropriate keys
            try:
                    signup_data = json2dict(base64.b64decode(pbft_key_state.sealed_signup_data.encode()).decode())
                    unsealed_pbft_public_key = signup_data.get('pbft_public_key')
            except SystemError:
                # Signup data is unuseable
                LOGGER.error(
                    'Could not unseal signup data associated with PPK: %s..%s',
                    active_pbft_public_key[:8],
                    active_pbft_public_key[-8:])
                self._pbft_key_state_store.active_key = None
                return False
            LOGGER.debug("PbftBlockPublisher::unsealed_pbft_public_key=%s ~ %s signup_data=%s",unsealed_pbft_public_key,active_pbft_public_key,signup_data)
            assert active_pbft_public_key == unsealed_pbft_public_key

            LOGGER.debug('Using PBFT public key: %s...%s',active_pbft_public_key[:8],active_pbft_public_key[-8:])
            LOGGER.debug('Unseal signup data: %s...%s',pbft_key_state.sealed_signup_data[:8],pbft_key_state.sealed_signup_data[-8:])
            """
            LOGGER.debug("PbftBlockPublisher::initialize_block  ADD CONSENSUS_STATE for block_id=%s",block_header.previous_block_id)
            consensus_state = ConsensusState.consensus_state_for_block_id(
                    block_id=block_header.previous_block_id,
                    block_cache=self._block_cache,
                    state_view_factory=self._state_view_factory,
                    consensus_state_store=self._consensus_state_store,
                    pbft_enclave_module=None,
                    )
            """
            #pbft_settings_view = PbftSettingsView(state_view)
            #LOGGER.debug("PbftBlockPublisher::pbft_settings_view node=%s",pbft_settings_view.pbft_node)

            # If our signup information does not pass the freshness test, then we
            # know that other validators will reject any blocks we try to claim so
            # we need to try to sign up again.

                # Using the consensus state for the block upon which we want to
            # build, check to see how many blocks we have claimed on this chain
            # with this PBFT key.  If we have hit the key block claim limit, then
            # we need to check if the key has been refreshed.
                # We need to create a wait timer for the block...this is what we
            # will check when we are asked if it is time to publish the block
            pbft_key_state = self._pbft_key_state_store[active_pbft_public_key]
            sealed_signup_data = pbft_key_state.sealed_signup_data

            # At this point, we know that if we are able to claim the block we are
            # initializing, we will not be prevented from doing so because of PBFT
            # policies.

            self._wait_timer = 20
        self._wait_timer = 20
        PbftBlockPublisher._previous_block_id = None
        block_header.consensus = b"pbft"
        LOGGER.debug('PbftBlockPublisher::initialize_block DONE _wait_timer=%s',self._wait_timer)
        self._block_header = block_header
        return True

    def check_publish_block(self, block_header):
        """Check if a candidate block is ready to be claimed.

        Args:
            block_header (BlockHeader): The block header for the candidate
                block that is checked for readiness for publishing.
        Returns:
            Boolean: True if the candidate block should be claimed. False if
            the block is not ready to be claimed.
        """
        if block_header is not None:
            pass
            #LOGGER.debug("PbftBlockPublisher::check_publish_block block_header(%s)=%s",type(block_header),block_header)
            """
            consensus_state = ConsensusState.consensus_state_for_block_id(
                    block_id=block_header.previous_block_id,
                    block_cache=self._block_cache,
                    state_view_factory=self._state_view_factory,
                    consensus_state_store=self._consensus_state_store
                    )
            if not consensus_state.is_step_NotStarted:
                LOGGER.debug("PbftBlockPublisher::check_publish_block state=%s",consensus_state)
            return not consensus_state.is_step_NotStarted
            """
        # Only claim readiness if the wait timer has expired
        if self._wait_timer > 0:
            self._wait_timer -= 1
            return False
        # wait_timer has expired
        return True 

    def finalize_block(self, block_header):
        """Finalize a block to be claimed. Provide any signatures and
        data updates that need to be applied to the block before it is
        signed and broadcast to the network.

        Args:
            block_header (BlockHeader): The block header for the candidate
                block that needs to be finalized.
        Returns:
            Boolean: True if the candidate block good and should be generated.
            False if the block should be abandoned.
        """
        summary = block_header.hex()
        LOGGER.debug('FINALIZE BLOCK CANDIDATE: block_id=%s summary=%s',_short_id(self._block_id),_short_id(summary))
        if isinstance(block_header, bytes):
            """
            At this point _block_id is previous and summary for current block
            save state with block_header key
            """
            """
            state = ConsensusState.consensus_state_for_block_id(
                    block_id=summary,
                    block_cache=self._block_cache,
                    state_view_factory=self._state_view_factory,
                    consensus_state_store=self._consensus_state_store,
                    force=True
                    )


            LOGGER.debug('FINALIZE BLOCK CANDIDATE: state=%s',state)
            # save in store
            state.set_consensus_state_for_block_id(summary,self._consensus_state_store)
            """
            """
            state_view = BlockWrapper.state_view_for_block(
                    block_wrapper=self._block_cache.block_store.chain_head,
                    state_view_factory=self._state_view_factory)
            """
            # We need to create a wait certificate for the block and
            # then serialize that into the block header consensus field.
            if _VREG_:
                active_key = self._pbft_key_state_store.active_key
                pbft_key_state = self._pbft_key_state_store[active_key]
                sealed_signup_data = pbft_key_state.sealed_signup_data
            consensus = b'pbft' 
            LOGGER.debug('PbftBlockPublisher::finalize_block isinstance DONE')
            return consensus

        # To compute the block hash, we are going to perform a hash using the
        # previous block ID and the batch IDs contained in the block
        hasher = hashlib.sha256(block_header.previous_block_id.encode())
        for batch_id in block_header.batch_ids:
            hasher.update(batch_id.encode())
        block_hash = hasher.hexdigest()

        # Using the current chain head, we need to create a state view so we
        # can create a PBFT enclave.
        state_view = BlockWrapper.state_view_for_block(
                block_wrapper=self._block_cache.block_store.chain_head,
                state_view_factory=self._state_view_factory)
        if _VREG_:
            # We need to create a wait certificate for the block and then serialize
            # that into the block header consensus field.
            active_key = self._pbft_key_state_store.active_key
            pbft_key_state = self._pbft_key_state_store[active_key]
            sealed_signup_data = pbft_key_state.sealed_signup_data

        #block_header.consensus = b'pbft' 
        LOGGER.debug('PbftBlockPublisher::finalize_block: DONE')

        return True


