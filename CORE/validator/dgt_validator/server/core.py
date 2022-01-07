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

import hashlib
import logging
import os
import signal
import time
import threading

from dgt_validator.concurrent.threadpool import InstrumentedThreadPoolExecutor
from dgt_validator.execution.context_manager import ContextManager
from dgt_validator.consensus.notifier import ConsensusNotifier
from dgt_validator.consensus.proxy import ConsensusProxy
from dgt_validator.database.indexed_database import IndexedDatabase
from dgt_validator.database.lmdb_nolock_database import LMDBNoLockDatabase
from dgt_validator.journal.publisher import BlockPublisher
from dgt_validator.journal.chain import ChainController
from dgt_validator.journal.genesis import GenesisController
from dgt_validator.journal.batch_sender import BroadcastBatchSender
from dgt_validator.journal.block_sender import BroadcastBlockSender
from dgt_validator.journal.block_store import BlockStore
from dgt_validator.journal.block_cache import BlockCache
from dgt_validator.journal.block_manager import BlockManager
from dgt_validator.journal.completer import Completer
from dgt_validator.journal.responder import Responder
from dgt_validator.journal.batch_injector import \
    DefaultBatchInjectorFactory
from dgt_validator.networking.dispatch import Dispatcher
from dgt_validator.journal.chain_id_manager import ChainIdManager
from dgt_validator.execution.executor import TransactionExecutor
from dgt_validator.state.batch_tracker import BatchTracker
from dgt_validator.state.settings_view import SettingsViewFactory
from dgt_validator.state.settings_cache import SettingsObserver
from dgt_validator.state.settings_cache import SettingsCache
from dgt_validator.state.identity_view import IdentityViewFactory
from dgt_validator.state.state_view import StateViewFactory
from dgt_validator.gossip.permission_verifier import PermissionVerifier
from dgt_validator.gossip.permission_verifier import IdentityCache
from dgt_validator.gossip.identity_observer import IdentityObserver
from dgt_validator.networking.interconnect import Interconnect
from dgt_validator.gossip.gossip import Gossip

from dgt_validator.server.events.broadcaster import EventBroadcaster

from dgt_validator.journal.receipt_store import TransactionReceiptStore

from dgt_validator.server import network_handlers
from dgt_validator.server import component_handlers
from dgt_validator.server import consensus_handlers

LOGGER = logging.getLogger(__name__)


class Validator(object):
    def __init__(self,
                 bind_network,
                 bind_component,
                 bind_consensus,
                 endpoint,
                 peering,
                 seeds_list,
                 peer_list,
                 data_dir,
                 config_dir,
                 identity_signer,
                 scheduler_type,
                 permissions,
                 minimum_peer_connectivity,
                 maximum_peer_connectivity,
                 max_dag_branch,
                 network_public_key=None,
                 network_private_key=None,
                 roles=None,
                 metrics_registry=None,
                 signed_consensus=False):
        """Constructs a validator instance.

        Args:
            bind_network (str): the network endpoint
            bind_component (str): the component endpoint
            endpoint (str): the zmq-style URI of this validator's
                publically reachable endpoint
            peering (str): The type of peering approach. Either 'static'
                or 'dynamic'. In 'static' mode, no attempted topology
                buildout occurs -- the validator only attempts to initiate
                peering connections with endpoints specified in the
                peer_list. In 'dynamic' mode, the validator will first
                attempt to initiate peering connections with endpoints
                specified in the peer_list and then attempt to do a
                topology buildout starting with peer lists obtained from
                endpoints in the seeds_list. In either mode, the validator
                will accept incoming peer requests up to max_peers.
            seeds_list (list of str): a list of addresses to connect
                to in order to perform the initial topology buildout
            peer_list (list of str): a list of peer addresses
            data_dir (str): path to the data directory
            config_dir (str): path to the config directory
            identity_signer (str): cryptographic signer the validator uses for
                signing
        """

        # -- Setup Global State Database and Factory -- #
        if signed_consensus:
            LOGGER.debug('SIGNED CONSENSUS MODE')
        global_state_db_filename = os.path.join(
            data_dir, 'merkle-{}.lmdb'.format(bind_network[-2:]))
        LOGGER.debug('global state database file is %s', global_state_db_filename)
        global_state_db = LMDBNoLockDatabase(global_state_db_filename, 'c')
        state_view_factory = StateViewFactory(global_state_db)

        # -- Setup Receipt Store -- #
        receipt_db_filename = os.path.join(
            data_dir, 'txn_receipts-{}.lmdb'.format(bind_network[-2:]))
        LOGGER.debug('txn receipt store file is %s', receipt_db_filename)
        #receipt_db = LMDBNoLockDatabase(receipt_db_filename, 'c')
        receipt_db = IndexedDatabase(
            receipt_db_filename,
            TransactionReceiptStore.serialize_receipt,
            TransactionReceiptStore.deserialize_receipt,
            flag='c',dupsort=True,
            indexes=TransactionReceiptStore.create_index_configuration())

        receipt_store = TransactionReceiptStore(receipt_db)

        # -- Setup Block Store -- #
        block_db_filename = os.path.join(
            data_dir, 'block-{}.lmdb'.format(bind_network[-2:]))
        LOGGER.debug('block store file is %s', block_db_filename)
        block_db = IndexedDatabase(
            block_db_filename,
            BlockStore.serialize_block,
            BlockStore.deserialize_block,
            flag='c',
            indexes=BlockStore.create_index_configuration())
        block_store = BlockStore(block_db)
        # for DAG set mercle db 
        block_store.set_global_state_db(global_state_db)
        block_cache = BlockCache(block_store, keep_time=300, purge_frequency=30)
        # The cache keep time for the journal's block cache must be greater
        # than the cache keep time used by the completer.
        base_keep_time = 1200

        block_manager = BlockManager()
        block_manager.add_store("commit_store", block_store)


        # -- Setup Thread Pools -- #
        component_thread_pool = InstrumentedThreadPoolExecutor(max_workers=10, name='Component',metrics_registry=metrics_registry)
        network_thread_pool = InstrumentedThreadPoolExecutor(max_workers=10, name='Network',metrics_registry=metrics_registry)
        sig_pool = InstrumentedThreadPoolExecutor(max_workers=3, name='Signature',metrics_registry=metrics_registry)

        # -- Setup Dispatchers -- #
        self._metrics_registry = metrics_registry
        component_dispatcher = Dispatcher(metrics_registry=metrics_registry)
        network_dispatcher = Dispatcher(metrics_registry=metrics_registry)

        # -- Setup Services -- #
        component_service = Interconnect(
            bind_component,
            component_dispatcher,
            secured=False,
            heartbeat=False,
            max_incoming_connections=20,
            monitor=True,
            max_future_callback_workers=10,
            metrics_registry=metrics_registry)

        zmq_identity = hashlib.sha512(
            time.time().hex().encode()).hexdigest()[:23]

        secure = False
        if network_public_key is not None and network_private_key is not None:
            secure = True

        network_service = Interconnect(
            bind_network,
            dispatcher=network_dispatcher,
            zmq_identity=zmq_identity,
            secured=secure,
            server_public_key=network_public_key,
            server_private_key=network_private_key,
            heartbeat=True,
            public_endpoint=endpoint,
            connection_timeout=120,
            max_incoming_connections=100,
            max_future_callback_workers=10,
            authorize=True,
            signer=identity_signer,
            roles=roles,
            metrics_registry=metrics_registry)

        # -- Setup Transaction Execution Platform -- #
        context_manager = ContextManager(global_state_db)

        batch_tracker = BatchTracker(block_store)

        settings_cache = SettingsCache(
            SettingsViewFactory(state_view_factory),
        )

        executor = TransactionExecutor(
            service=component_service,
            context_manager=context_manager,
            settings_view_factory=SettingsViewFactory(state_view_factory),
            scheduler_type=scheduler_type,
            invalid_observers=[batch_tracker],
            metrics_registry=metrics_registry)

        component_service.set_check_connections(executor.check_connections)

        event_broadcaster = EventBroadcaster(
            component_service, block_store, receipt_store)

        # -- Consensus Engine -- #
        consensus_thread_pool = InstrumentedThreadPoolExecutor(max_workers=3,name='Consensus',metrics_registry=metrics_registry)
        consensus_dispatcher = Dispatcher()
        consensus_service = Interconnect(
            bind_consensus,
            consensus_dispatcher,
            secured=False,
            heartbeat=False,
            max_incoming_connections=20,
            monitor=True,
            max_future_callback_workers=10)

        consensus_notifier = ConsensusNotifier(consensus_service,signed_consensus=signed_consensus)

        # -- Setup P2P Networking -- #
        gossip = Gossip(
            network_service,
            settings_cache,
            block_store.chain_head_state_root,
            block_store.get_recovery_mode,
            block_store.get_chain_heads,
            consensus_notifier,
            endpoint=endpoint,
            component=bind_component, # for DASHBOARD 
            peering_mode=peering,
            initial_seed_endpoints=seeds_list,
            initial_peer_endpoints=peer_list,
            minimum_peer_connectivity=minimum_peer_connectivity,
            maximum_peer_connectivity=maximum_peer_connectivity,
            topology_check_frequency=1 # signer=identity_signer own key
        )

        completer = Completer(block_store, gossip)

        block_sender = BroadcastBlockSender(completer, gossip)
        batch_sender = BroadcastBatchSender(completer, gossip)
        chain_id_manager = ChainIdManager(data_dir)

        identity_view_factory = IdentityViewFactory(
            StateViewFactory(global_state_db))

        id_cache = IdentityCache(identity_view_factory)

        # -- Setup Permissioning -- #
        permission_verifier = PermissionVerifier(
            permissions,
            block_store.chain_head_state_root,
            id_cache)

        identity_observer = IdentityObserver(
            to_update=id_cache.invalidate,
            forked=id_cache.forked)

        settings_observer = SettingsObserver(
            to_update=settings_cache.invalidate,
            forked=settings_cache.forked)

        # -- Setup Journal -- #
        batch_injector_factory = DefaultBatchInjectorFactory(
            block_store=block_store,
            state_view_factory=state_view_factory,
            signer=identity_signer)

        block_publisher = BlockPublisher(
            transaction_executor=executor,
            block_cache=block_cache,
            state_view_factory=state_view_factory,
            settings_cache=settings_cache,
            block_sender=block_sender,
            batch_sender=batch_sender,
            squash_handler=context_manager.get_squash_handler(),
            context_handlers=context_manager.get_context_handlers(),
            chain_head=block_store.chain_head,
            identity_signer=identity_signer,
            data_dir=data_dir,
            config_dir=config_dir,
            permission_verifier=permission_verifier,
            check_publish_block_frequency=0.1,
            batch_observers=[batch_tracker],
            batch_injector_factory=batch_injector_factory,
            metrics_registry=metrics_registry,
            consensus_notifier=consensus_notifier) # for external engine control

        chain_controller = ChainController(
            block_sender=block_sender,
            block_cache=block_cache,
            state_view_factory=state_view_factory,
            transaction_executor=executor,
            chain_head_lock=block_publisher.chain_head_lock,
            on_chain_updated=block_publisher.on_chain_updated,
            on_head_updated=block_publisher.on_head_updated,
            on_topology_updated=block_publisher.on_topology_updated,
            get_recompute_context=block_publisher.get_recompute_context,
            belong_cluster = block_publisher.belong_cluster,
            squash_handler=context_manager.get_squash_handler(),
            context_handlers=context_manager.get_context_handlers(),
            chain_id_manager=chain_id_manager,
            identity_signer=identity_signer,
            data_dir=data_dir,
            config_dir=config_dir,
            permission_verifier=permission_verifier,
            chain_observers=[
                event_broadcaster,
                receipt_store,
                batch_tracker,
                identity_observer,
                settings_observer
            ],
            metrics_registry=metrics_registry,
            consensus_notifier=consensus_notifier,
            block_manager=block_manager,
            max_dag_branch=max_dag_branch)# for external engine control

        genesis_controller = GenesisController(
            context_manager=context_manager,
            transaction_executor=executor,
            completer=completer,
            block_manager=block_manager,
            block_store=block_store,
            state_view_factory=state_view_factory,
            identity_signer=identity_signer,
            data_dir=data_dir,
            config_dir=config_dir,
            chain_id_manager=chain_id_manager,
            batch_sender=batch_sender,
            signed_consensus=signed_consensus)

        responder = Responder(completer)

        completer.set_on_batch_received(block_publisher.queue_batch)
        completer.set_on_block_received(chain_controller.queue_block)
        completer.set_chain_has_block(chain_controller.has_block,chain_controller.has_genesis_federation_block,chain_controller.is_nests_ready)

        # -- Register Message Handler -- #
        network_handlers.add(
            network_dispatcher, network_service, gossip, completer,
            responder, network_thread_pool, sig_pool,
            chain_controller.has_block, block_publisher.has_batch,
            permission_verifier, block_publisher, consensus_notifier,signed_consensus=signed_consensus)

        component_handlers.add(
            component_dispatcher, gossip, context_manager, executor, completer,
            block_store, batch_tracker, global_state_db,
            self.get_chain_head_state_root_hash, receipt_store,
            event_broadcaster, permission_verifier, component_thread_pool,
            sig_pool, block_publisher, metrics_registry)

        # -- Store Object References -- #
        self._component_dispatcher = component_dispatcher
        self._component_service = component_service
        self._component_thread_pool = component_thread_pool

        self._network_dispatcher = network_dispatcher
        self._network_service = network_service
        self._network_thread_pool = network_thread_pool
        #block_manager = None
        LOGGER.debug("ConsensusProxy: INIT scheduler_type=%s",scheduler_type)
        consensus_proxy = ConsensusProxy(
            block_manager=block_manager,
            chain_controller=chain_controller,
            block_publisher=block_publisher,
            gossip=gossip,
            identity_signer=identity_signer,
            settings_view_factory=SettingsViewFactory(state_view_factory),
            state_view_factory=state_view_factory,
            signed_consensus=signed_consensus)

        consensus_handlers.add(
            consensus_dispatcher,
            consensus_thread_pool,
            consensus_proxy,
            consensus_notifier)

        self._consensus_dispatcher = consensus_dispatcher
        self._consensus_service = consensus_service
        self._consensus_thread_pool = consensus_thread_pool

        self._sig_pool = sig_pool

        self._context_manager = context_manager
        self._executor = executor
        self._genesis_controller = genesis_controller
        self._gossip = gossip

        self._block_publisher = block_publisher
        self._chain_controller = chain_controller

    def start(self):
        self._component_dispatcher.start()
        self._component_service.start()
        if self._genesis_controller.requires_genesis():
            # START in genesis mode
            self._genesis_controller.start(self._start)
        else:
            self._start()

    def _start(self):
        """
        load topology before peer's attempts to connect
        """
        self._gossip.load_topology()
        self._consensus_dispatcher.start()
        self._consensus_service.start()
        self._network_dispatcher.start()
        self._network_service.start()

        self._gossip.start()
        self._block_publisher.start()
        self._chain_controller.start()

        signal_event = threading.Event()

        signal.signal(signal.SIGTERM,lambda sig, fr: signal_event.set())
        #signal.signal(signal.SIGINT,lambda sig, fr: signal_event.set())
        
        # This is where the main thread will be during the bulk of the
        # validator's life.
        """
        if self._metrics_registry:
            pass
            LOGGER.debug("->DUMP METRICS=%s",self._metrics_registry.dump_metrics)
        """
        
        while not signal_event.is_set():
            signal_event.wait(timeout=20)

        LOGGER.debug("After while SIGNAL\n")
        """
        if self._metrics_registry:
            pass
            LOGGER.debug("<-DUMP METRICS=%s",self._metrics_registry.dump_metrics)
        """
    def stop(self):
        self._gossip.stop()
        self._component_dispatcher.stop()
        self._network_dispatcher.stop()
        self._network_service.stop()

        self._component_service.stop()

        self._consensus_service.stop()
        self._consensus_dispatcher.stop()

        self._network_thread_pool.shutdown(wait=True)
        self._component_thread_pool.shutdown(wait=True)
        self._sig_pool.shutdown(wait=True)

        self._executor.stop()
        self._context_manager.stop()

        self._block_publisher.stop()
        self._chain_controller.stop()

        threads = threading.enumerate()

        # This will remove the MainThread, which will exit when we exit with
        # a sys.exit() or exit of main().
        threads.remove(threading.current_thread())

        while threads:
            if len(threads) < 4:
                LOGGER.info("remaining threads: %s",
                    ", ".join(
                        ["{} ({})".format(x.name, x.__class__.__name__)
                         for x in threads]))
            for t in threads.copy():
                if not t.is_alive():
                    t.join()
                    threads.remove(t)
                if threads:
                    time.sleep(1)

        LOGGER.info("All threads have been stopped and joined")
        

    def get_chain_head_state_root_hash(self):
        return self._chain_controller.chain_head.state_root_hash
