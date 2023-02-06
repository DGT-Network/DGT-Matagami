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
import logging
import copy
import time
import datetime
import random
import os
import subprocess
import binascii
import json

from urllib.parse import urlparse
import http.client
import requests

from threading import Lock
from functools import partial
from collections import namedtuple
from enum import Enum

from dgt_validator.concurrent.thread import InstrumentedThread
from dgt_validator.protobuf.network_pb2 import DisconnectMessage
from dgt_validator.protobuf.network_pb2 import GossipMessage
from dgt_validator.protobuf.network_pb2 import GossipConsensusMessage
from dgt_validator.protobuf.network_pb2 import GossipBatchByBatchIdRequest
from dgt_validator.protobuf.network_pb2 import GossipBatchByTransactionIdRequest
from dgt_validator.protobuf.network_pb2 import GossipBlockRequest
from dgt_validator.protobuf.network_pb2 import EndpointItem,EndpointList
from dgt_validator.protobuf import validator_pb2
from dgt_validator.protobuf.network_pb2 import PeerRegisterRequest
from dgt_validator.protobuf.network_pb2 import PeerUnregisterRequest
from dgt_validator.protobuf.network_pb2 import GetPeersRequest
from dgt_validator.protobuf.network_pb2 import GetPeersResponse
from dgt_validator.protobuf.network_pb2 import NetworkAcknowledgement
from dgt_validator.protobuf.consensus_pb2 import ConsensusNotifyPeerConnected
from dgt_validator.protobuf.client_peers_pb2 import  ClientPeersControlRequest
from dgt_validator.exceptions import PeeringException
from dgt_validator.networking.interconnect import get_enum_name
# FBFT topology
from dgt_validator.gossip.fbft_topology import (PeerSync,PeerRole,PeerAtr,FbftTopology,
                                                TOPOLOGY_SET_NM,DGT_TOPOLOGY_MAP_NM,TOPO_GENESIS,DGT_NET_NEST,
                                                DGT_SELF_CERT,DGT_KYC_DID,IS_DID,GET_DID_UID
                                                )
from dgt_cli.make_set_txn import _create_batch,_create_topology_txn
from x509_cert.client_cli.create_batch import create_xcert_txn

LOGGER = logging.getLogger(__name__)


class PeerStatus(Enum):
    CLOSED = 1
    TEMP = 2
    PEER = 3


class EndpointStatus(Enum):
    # Endpoint will be used for peering
    PEERING = 1
    # Endpoint will be used to request peers
    TOPOLOGY = 2

EndpointInfo = namedtuple('EndpointInfo',
                          ['status', 'time', "retry_threshold","network"])

StaticPeerInfo = namedtuple('StaticPeerInfo',
                            ['time', 'retry_threshold', 'count'])

INITIAL_RETRY_FREQUENCY = 10
MAXIMUM_RETRY_FREQUENCY = 300
SYNC_CHECK_TOUT         = 10
   
MAXIMUM_STATIC_RETRY_FREQUENCY = 3600
MAXIMUM_STATIC_RETRIES = 24

TIME_TO_LIVE = 3
TIME_TO_LIVE_NM       = "dgt.net.time_to_live"
MAX_PUBLIC_CLUSTER_NM = 'dgt.fbft.max_public_cluster'
AUTO_CLUSTER_NM       = 'dgt.fbft.auto_cluster'
MAX_FEDER_PEER_NM     = 'dgt.fbft.max_feder_peer'
_PARAM_DEFAULT_ = {
    TIME_TO_LIVE_NM      : 3,
    MAX_PUBLIC_CLUSTER_NM: 2,
    MAX_FEDER_PEER_NM    : 7,
    AUTO_CLUSTER_NM      : True,
    }

FIFO_PATH = '/project/peer/data/.peers_ctrl'
REAL_SEED_URL_SCHEME = ['tcp']
PUBLIC_NET_ZONE = "public"
PRIVATE_NET_ZONE = "private"
DYN_NEST = "DYN"

def load_peer_config_file(fname=DGT_NET_NEST):
    try:                                                    
        with open(fname, 'r') as file:                 
            val_str = file.read().strip()             
    except IOError as e:                                    
        print(f"Could not load file: {e}")             
        return None 
    return val_str                                        

def download_file_from_google_drive(url):                                         
    CHUNK_SIZE = 32768                                                                        
    URL = "https://docs.google.com/uc?export=download"                                        
    def get_confirm_token(response):                                                          
        for key, value in response.cookies.items():                                           
            if key.startswith('download_warning'):                                            
                return value                                                                  
                                                                                              
        return None                                                                           
    # get file_id from url
    ids = url.split("/")
    file_id = ids[5] 
    #
    LOGGER.debug(f"download_file_from_google_drive from {url} file_id={file_id}\n")
    session = requests.Session()                                                              
    try:
        response = session.get(URL, params = { 'id' : file_id }, stream = True)                        
        token = get_confirm_token(response)                                                       
                                                                                                  
        if token:                                                                                 
            params = { 'id' : file_id, 'confirm' : token }                                             
            response = session.get(URL, params = params, stream = True)                           
        data = bytearray()                                                                        
        for chunk in response.iter_content(CHUNK_SIZE):                                           
            if chunk: # filter out keep-alive new chunks                                          
                data += chunk                                                                     
                                                                                                  
        data = data.decode('utf-8') 
        endpoints = json.loads(data) 
    except Exception as ex:
        LOGGER.debug(f"Gossip: cant load seed endpoint from {url} - err={ex}\n")
        endpoints = {PRIVATE_NET_ZONE:[],PUBLIC_NET_ZONE:[]}

    return endpoints



class Gossip(object):
    def __init__(self, network,
                 settings_cache,
                 current_root_func,
                 is_recovery_func,
                 get_heads_func,
                 consensus_notifier,
                 endpoint=None,
                 component=None,
                 peering_mode='static',
                 initial_seed_endpoints=None,
                 initial_peer_endpoints=None,
                 minimum_peer_connectivity=3,
                 maximum_peer_connectivity=10,
                 topology_check_frequency=1
                 ):
        """Constructor for the Gossip object. Gossip defines the
        overlay network above the lower level networking classes.

        Args:
            network (networking.Interconnect): Provides inbound and
                outbound network connections.
            endpoint (str): The publically accessible zmq-style uri
                endpoint for this validator.
            peering_mode (str): The type of peering approach. Either 'static'
                or 'dynamic'. In 'static' mode, no attempted topology
                buildout occurs -- the validator only attempts to initiate
                peering connections with endpoints specified in the
                peer_list. In 'dynamic' mode, the validator will first
                attempt to initiate peering connections with endpoints
                specified in the peer_list and then attempt to do a
                topology buildout starting with peer lists obtained from
                endpoints in the seeds_list. In either mode, the validator
                will accept incoming peer requests up to max_peers.
            initial_seed_endpoints ([str]): A list of initial endpoints
                to attempt to connect and gather initial topology buildout
                information from. These are specified as zmq-compatible
                URIs (e.g. tcp://hostname:port).
            initial_peer_endpoints ([str]): A list of initial peer endpoints
                to attempt to connect and peer with. These are specified
                as zmq-compatible URIs (e.g. tcp://hostname:port).
            minimum_peer_connectivity (int): If the number of connected
                peers is below this threshold, the topology builder will
                continue to attempt to identify new candidate peers to
                connect with.
            maximum_peer_connectivity (int): The validator will reject
                new peer requests if the number of connected peers
                reaches this threshold.
            topology_check_frequency (int): The time in seconds between
                topology update checks.
        """
        self._peering_mode = peering_mode
        self._lock = Lock()
        self._network = network
        self._endpoint = endpoint
        self._initial_seed_endpoints = initial_seed_endpoints if initial_seed_endpoints else []
        self._initial_peer_endpoints = initial_peer_endpoints if initial_peer_endpoints else []
        self._static_peer_endpoints = list(self._initial_peer_endpoints)
        self._minimum_peer_connectivity = minimum_peer_connectivity
        self._maximum_peer_connectivity = maximum_peer_connectivity
        self._topology_check_frequency = topology_check_frequency
        self._settings_cache = settings_cache
        self._current_root_func = current_root_func # block_store.chain_head_state_root
        self._is_recovery_func = is_recovery_func   # check recovery mode
        self._get_heads_func = get_heads_func
        self._consensus_notifier = consensus_notifier

        self._topology = None
        self._peers = {}
        self._peer_id = int(time.time())
        self._signer = self._network.signer # for sign transaction

        # feder topology
        self._is_private = True # by default
        self._own_topo_nest = self.get_own_topology_nest()    # get own topology nest
        self._settings = {}                    # DAG settings
        self._is_federations_assembled = False # point of assemble
        self._fbft = FbftTopology(self._own_topo_nest)            # F-BFT topology
        self._stopology = None                 # string 
        self._ftopology = None                 # json 
        self._nosync    = True #False                # need sync with other net 
        self._own_sync  = False                # say about own sync
        self._genesis_sync = False             # sync with genesis peer or with cluster leader
        self._num_nosync_peer = 0              # number of non sync peer 
        self._incomplete = False               # status of own nests 
        self._is_nests_ready = False           # 
        self._is_send_block_request = False
        self._malicious = ConsensusNotifyPeerConnected.NORMAL 
        self._unsync_peers = {}                # list unsync  peers
        self._notvalid_peers = {}               # list unsync  peers
        self._add_batch = None
        self._join_cluster = None
        self._batch        = None
        self._my_ip = None
        self._extpoint = None
        self._try_sync_net = False
        
        """
        initial_peer_endpoints - peers from own cluster
        also we should know own atrbiter
        """
        self._peers_control_init()
        
        endpoints = os.environ.get('ENDPOINTS')
        
        if endpoints != '':
            self.update_endpoints(endpoints)
        
        self.set_single_mode()
        # make component 
        url = urlparse(component)
        comp_scheme,comp_port = url.scheme, url.port
        url = urlparse(self.endpoint)
        end_host = url.hostname
        self._component = "{}://{}:{}".format(comp_scheme,end_host,comp_port)

        LOGGER.debug("Gossip: %s endpoint=%s->%s component=%s is_recovery=%s single=%s",peering_mode,endpoint,self.endpoint,self._component,self._is_recovery_func(),self.is_single)
        if self.is_dynamic:
            # TODO check - in case url is tcp:: -use it directly in others case get real urls list from google drive using this url
            # it could be peer for private zone and for public 
             
            if self._own_topo_nest == DYN_NEST:
                zone = PUBLIC_NET_ZONE
                self._is_private = False
            else:
                zone =  PRIVATE_NET_ZONE
            LOGGER.debug(f"Gossip: DYNAMIC zone={zone} init seeds={self._initial_seed_endpoints}\n")
            self.make_real_initial_seeds(self._initial_seed_endpoints,zone_access=zone)

        else:
            LOGGER.debug("Gossip: peers=%s\n",self._initial_peer_endpoints)

    def get_own_topology_nest(self):
        # load from config /peer/etc/dgt.net.nest
        nest = load_peer_config_file()
        LOGGER.debug(f"Gossip: OWN NEST={nest}\n")
        if self._peering_mode == 'static':
            return DYN_NEST if nest is None else nest
        else:
            return DYN_NEST if nest is None else nest

    def make_real_initial_seeds(self,seed_endpoints,zone_access=PUBLIC_NET_ZONE):
        # check url into seeds list 
        real_seed_endpoints = []
        for seed in seed_endpoints:
            url = urlparse(seed)
            LOGGER.debug(f"Gossip:ENDPOINT URL={url.scheme} : {url.hostname}")
            if url.scheme in REAL_SEED_URL_SCHEME:
                # keep this endpoint
                real_seed_endpoints.append(seed)
                continue
            # google disk - "https://drive.google.com/file/d/1o6SEUvogow432pIKQEL8-EEzNBinzW9R/view?usp=sharing"
            if url.scheme == "https" and url.hostname == "drive.google.com":
                # get real list from disk
                endpoints = download_file_from_google_drive(seed)
                LOGGER.debug(f"Gossip: GOOGLE ENDPOINTS={endpoints}")
                zone_endpoints = endpoints[zone_access]
                real_seed_endpoints += zone_endpoints
            else:
                LOGGER.debug(f"Gossip: SKIP unrecognized seed url={seed}")
        self._initial_seed_endpoints = real_seed_endpoints
        LOGGER.debug(f"Gossip: REAL SEEDS={self._initial_seed_endpoints}")

    def _peers_control_init(self):
        plist = os.environ.get('PCONTROL')
        self._pcontrol = plist != ''
        self._pfifo = None
        self._peers_ctrl = []
        if self._pcontrol:
            self._peers_ctrl = plist.split(',')
            LOGGER.debug("Gossip: peers control list=%s\n",self._peers_ctrl)
                        
            try:
                os.mkfifo(FIFO_PATH)
                LOGGER.debug("Gossip: CREATE FIFO %s",FIFO_PATH)
            except Exception as ex:
                LOGGER.debug("Gossip: CREATE FIFO=%s ERROR(%s)",FIFO_PATH,ex)

            self._pfifo = open(FIFO_PATH, "w")
            self._pfifo.write("Peer {} ready\n".format(self.validator_id[:8]))
            self._pfifo.flush()

    def peers_control(self,cname,pname,mode):
        """
        Start stop peer 
        """
        PREF_CLUST = 'Dgt' # 
        pkey = '{}.{}'.format(cname,pname)
        if mode == ClientPeersControlRequest.INFO:
            # send status peer
            if cname.isdigit() and pname.isdigit():
                pname = '{}{}'.format(cname,pname)
                cname = '{}{}'.format(PREF_CLUST,cname) if cname != '1' else TOPO_GENESIS
                
            LOGGER.debug("peers_control INFO =%s.%s",cname,pname)
            peer,key = self._fbft.get_peer_by_name(cname,pname)
            if peer:
                state = peer[PeerAtr.node_state] if PeerAtr.node_state in peer else PeerSync.inactive
                net = peer[PeerAtr.network] if PeerAtr.network in peer else 'undef'
                endpoint = peer[PeerAtr.endpoint] if PeerAtr.endpoint in peer else 'undef'

                return 1,'Peer={} state={} net={} endpoint={}'.format(key[:8],state,net,endpoint)
            else:
                return 1,'Peer {} undefined in toology'.format(pkey)

        if self._pcontrol and self._pfifo:
            
            if pkey not in self._peers_ctrl:
                return 1,'Cant control peer {}'.format(pkey)
            # get status of peer 
            if cname[:3] != 'dyn':
                peer,key = self._fbft.get_peer_by_name('{}{}'.format(PREF_CLUST,cname),'{}{}'.format(cname,pname))
                if peer:
                    LOGGER.debug("peer=%s key=%s",peer,key[:8]) #PeerAtr.node_state
                    if mode == ClientPeersControlRequest.UP :
                        if PeerAtr.node_state in peer and peer[PeerAtr.node_state] == PeerSync.active:
                            return 1,'Peer {}({}) already started'.format(pkey,key[:8])
                    else:
                        if PeerAtr.node_state not in peer or peer[PeerAtr.node_state] != PeerSync.active:
                            return 1,'Peer {}({}) not started'.format(pkey,key[:8])
                else:
                    return 1,'Peer {} undefined in toology'.format(pkey)
            else:
                key = 'dynamic'
            cmd = 'upCluster.sh {} {} \n'.format(cname,pname) if mode == ClientPeersControlRequest.UP else 'downCluster.sh {} {} \n'.format(cname,pname)
            LOGGER.debug("peers_control=%s",cmd)
            try:
                self._pfifo.write(cmd)
                self._pfifo.flush()
                return 0,'Peer={} succefully {} '.format(key[:8],'started' if mode == ClientPeersControlRequest.UP else 'stopped')
            except Exception as ex:
                return 0,'Incorrect request({})'.format(ex)
        else:
            return 1,'Service unavailable(try next gateway)'

        

    def endpoint_to_expoint(self,endpoint,my_ip,port=''):
        url = urlparse(endpoint)
        expoint = "{}://{}:{}".format(url.scheme,my_ip,(port if port != '' else url.port))
        return expoint

    def set_single_mode(self):
        #endport = os.environ.get('ENDPORT')
        self._single = self._network.single
        self._extpoint = self._network.extpoint
        self._own_network  = self._network.network
        LOGGER.debug("Gossip: set SINGLE=%s  EXTPOINT=%s NETWORK=%s",self._single,self._extpoint,self._own_network)
        

    def update_endpoints(self,val):
        """
        update list of peers which defined into config
        """
        #LOGGER.debug("Gossip use external ENDPOINTS='%s'",val)
        try:
            endpoints = json.loads(val)
            LOGGER.debug("Load external ENDPOINTS='%s'",endpoints)
            peers = enumerate(self._initial_peer_endpoints, 0)
            for endp in endpoints:
                #LOGGER.debug("Check ENDPOINT '%s'",endp)
                url = urlparse(endp)
                nscheme,host,nport = url.scheme, url.hostname, url.port
                is_update = False
                for num, peer in peers:
                    url = urlparse(peer)
                    if url.hostname == host:
                        self._initial_peer_endpoints[num] = "{}://{}:{}".format(url.scheme,host,nport)
                        is_update = True
                        LOGGER.debug("Update ENDPOINT '%s'",host)
                        break
                if not is_update:
                    self._initial_peer_endpoints.append("{}://{}:{}".format(nscheme,host,nport))

            LOGGER.debug("New  ENDPOINTS='%s'",self._initial_peer_endpoints)
        except Exception as ex:
            LOGGER.debug("Cant load ENDPOINTS from '%s'(%s)",val,ex)

    @property
    def component(self):
        return self._component

    @property
    def f_topology(self):
        return self._fbft
    @property
    def is_registered_engines(self):
        return self._consensus_notifier._registered_engines
    @property
    def is_genesis_peer(self):
        return self._fbft.genesis_node == self.validator_id
    @property
    def is_ready_for_assemble(self):
        return self.is_registered_engines and not self._is_recovery_func() and (self._is_nests_ready or not self.is_genesis_peer)

    @property
    def is_federations_assembled(self):
        return self._is_federations_assembled  
    @property
    def is_sync(self):
        return not (self._nosync or (not self.is_genesis_peer and not self._genesis_sync)) # or not genesis peer
    @property
    def peer_id(self):
        return self._peer_id
    @property
    def malicious(self):
        return self._malicious

    @property
    def validator_id(self):
        return self._network.validator_id
    @property
    def is_arbiter(self):
        return self._fbft.is_arbiter
    
    @property
    def heads_summary(self):
        return self._get_heads_func(summary=True)

    @property
    def peering_mode(self):
        return self._peering_mode

    @property
    def is_dynamic(self):
        return self._peering_mode == 'dynamic'

    @property
    def is_single(self):
        return self._single
    @property
    def network(self):
        return self._own_network

    @property
    def join_cluster(self):
        return None

    @property
    def KYC(self):
        return None

    @property
    def endpoint(self):
        return self._endpoint if not self._single else self._extpoint 

    @property
    def extpoint(self):
        return self._extpoint

    @property
    def peers_info(self):
        return [cid[:8]+":"+endpoint for cid,endpoint in self._peers.items()]

    @property
    def auto_cluster_mode(self):
        return self.get_fbft_setting(AUTO_CLUSTER_NM)
    @property
    def max_public_cluster(self):
        return self.get_fbft_setting(MAX_PUBLIC_CLUSTER_NM)
    @property
    def max_feder_peer(self):
        return int(self.get_fbft_setting(MAX_FEDER_PEER_NM))

    def get_join_cluster(self):
        # set cluster for entering into SEED segment
        if self._own_topo_nest != DYN_NEST:
            # find nest description 
            # get own certificate 

            self_cert = load_peer_config_file(fname= DGT_KYC_DID if os.path.isfile(DGT_KYC_DID) else DGT_SELF_CERT) if self._is_private else None
            return f"{self._own_topo_nest}:",self_cert
        return None,None
        
    def set_add_batch(self,add_batch):
        self._add_batch = add_batch

    def set_nests_ready(self):
        self._is_nests_ready = True

    def set_cluster(self,topology):
        self._fbft = topology
        LOGGER.debug("set cluster=%s arbiters=%s",self._fbft.cluster,self._fbft.arbiters)

    def get_exclude(self,check_own_peer = True):
        # get list of peers not from our cluster or arbiters ring
        #LOGGER.debug("get_exclude peers=%s",self._peers)
        exclude = []

        check_peer = self._fbft.is_own_peer if check_own_peer else self._fbft.peer_is_arbiter
        with self._lock:
            for peer in self._peers.keys() :
                public_key = self._network.connection_id_to_public_key(peer)
                if public_key is None:
                    LOGGER.debug(f"SKIP CONNECT PEER={peer}")
                    continue
                if not check_peer(public_key):
                    LOGGER.debug(f"EXCLUDE={public_key[0:8]}")
                    exclude.append(peer)
                else:
                    LOGGER.debug(f"INFORM PEER={public_key[0:8]}")
        #LOGGER.debug("get_exclude exclude=%s",[self._peers[cid] for cid in exclude])
        return None if len(exclude) == 0 else exclude

    def update_federation_topology(self,key,endpoint,mode=True,sync=False,force=False,pid=None):
        LOGGER.debug("update federation_topology peer=%s %s mode=%s sync=%s ns:gs=%s:%s SYNC=%s",key[:8],endpoint,mode,sync,self._nosync,self._genesis_sync,self.is_sync)
        if not sync:
            # in case only one unsync peer mark this peer as unsync
            self._nosync = True
        elif self._genesis_sync :
            self._nosync = False
        LOGGER.debug("update federation_topology peer=%s %s unsync=%s SYNC=%s DONE",key[:8],endpoint,self._nosync,self.is_sync)
        self._fbft.update_peer_activity(key,endpoint,mode,sync,force,pid)
        LOGGER.debug("update federation_topology peer=%s %s nosync=%s DONE",key[:8],endpoint,self._nosync)

    def myself_sync(self,sync=True):
        if not self._own_sync:
            self.update_federation_topology(self.validator_id,None,sync = sync)
            self.notify_peer_connected(self.validator_id,assemble=sync)
            self._own_sync = True

    def get_conn_expoint(self,cid,ext=True):
        pkey = self._network.connection_id_to_public_key(cid)
        peer = self._fbft.get_peer(pkey)
        try:
            return peer[PeerAtr.extpoint if ext else PeerAtr.intpoint] if peer else None
        except KeyError:
            return None

    def _peer_sync_callback(self, request, result, connection_id, endpoint=None):
        """
        ->> REPLY ON my own SYNC request
        """
        LOGGER.debug("REPLY ON my own SYNC request endpoint=%s",endpoint)
        with self._lock:
            ack = NetworkAcknowledgement()
            ack.ParseFromString(result.content)
            if ack.status == ack.ERROR:
                LOGGER.debug("SYNC request to %s was NOT successful",endpoint)
                
            elif ack.status == ack.OK:
                if endpoint:
                    try:
                        """
                        in case (ack.sync == TRUE) peer was synchronized 
                        and inform them after synchronization
                        """
                        peer_key = self._network.connection_id_to_public_key(connection_id)
                        LOGGER.debug("SYNC request to %s(%s) was successful. Peer=%s(%s) SYNC=%s _incomplete=%s",connection_id[:8],endpoint,peer_key[:8],ack.pid,ack.sync,self._incomplete)
                        self.update_federation_topology(peer_key,endpoint,sync=ack.sync,pid=ack.pid)
                        if ack.sync:
                            self._num_nosync_peer -= 1
                            if endpoint in self._unsync_peers:
                                self._unsync_peers.pop(endpoint)
                            if self._num_nosync_peer == 0 and not self.is_sync:
                                # set OWN SYNC 
                                self._nosync = False

                            self.notify_peer_connected(peer_key,assemble=True)          # peer status

                            if  peer_key != self._fbft.genesis_node and self._fbft.is_leader: 
                                # inform static or dynamic peer about registred dynamic peers
                                # use info about endpoint's networks
                                self.send_dynamic_peers_info(endpoint,connection_id,peer_key)
                                
                            
                            if peer_key == self._fbft.genesis_node or self._fbft.is_cluster_leader(peer_key):
                                # sync with genesis peer was done - say consensus that our peer already sync 
                                LOGGER.debug("SYNC request SET OWN STATUS sync=%s incomplete=%s\n",ack.sync,self._incomplete)
                                if not self._incomplete:
                                    # not sync at this moment
                                    self._genesis_sync = True # mark as synced with genesis
                                    self.update_federation_topology(self.validator_id,None,sync=ack.sync)
                                    self.notify_peer_connected(self.validator_id,assemble=True) # OWN status
                                    LOGGER.debug("REPLY ON MY REQ -  SWITCH MYSELF TO SYNC\n")
                        else:
                            LOGGER.debug("SYNC request to=%s incomplete=%s WAS WRONG(check heads)",endpoint,self._incomplete)
                            self._unsync_peers[endpoint] = time.time()
                            if not self._incomplete and peer_key == self._fbft.genesis_node:
                                # ask head
                                #self.send_block_request("HEAD", connection_id) 
                                pass

                    except PeeringException as e:
                        # Remove unsuccessful peer
                        LOGGER.warning('Unable to successfully SYNC peer with endpoint: %s, due to %s',endpoint, str(e))
            
                else:
                    LOGGER.debug("Cannot SYNC peer with no endpoint for connection_id: %s",connection_id)
        LOGGER.debug("_peer_sync_callback endpoint=%s DONE",endpoint)
                    

    def sync_to_peer_with_endpoint(self, endpoint,connection_id=None):
        """
        <-- make sync request to peer with endpoint 
        <-- DO IT after DAG sync - we should make sync with own cluster and with arbiters for leader
        """
        LOGGER.debug("Attempting to sync peer with endpoint=%s heads_sum=%s peers=%s", endpoint,self.heads_summary,self.peers_info)

        # check if the connection exists, if it does - send,
        # otherwise create it
        try:
            if connection_id is None:
                connection_id = self._network.get_connection_id_by_endpoint(endpoint) 
            network = self._network.get_connection_network(connection_id)    
            register_request = PeerRegisterRequest(endpoint=(self.extpoint if network != self.network else self._endpoint),mode=PeerRegisterRequest.SYNC,pid=self.peer_id,hid=self.heads_summary)

            self._network.send(
                validator_pb2.Message.GOSSIP_REGISTER,
                register_request.SerializeToString(),
                connection_id,
                callback=partial(
                    self._peer_sync_callback,
                    endpoint=endpoint,
                    connection_id=connection_id))
            self._num_nosync_peer += 1
        except KeyError:
            # if the connection uri wasn't found in the network's
            # connections, it raises a KeyError and we need to add
            # a new outbound connection
            LOGGER.debug("Error attempting to sync peer with %s NO CONNECTION", endpoint)    


    def try_to_sync_with_net(self):
        """
        try:to sync in case we are out of sync
        peer which started first - don't know all peer's endpoint because its didn't connected yet
        """
        if not self.is_sync and not self._try_sync_net:
            LOGGER.debug(f"TRY_TO_SYNC_WITH_NET is dynamic={self.is_dynamic} cluster={self._join_cluster}....\n")
            if self.is_dynamic and self._join_cluster is not None:
                # force join cluster for PBFT engine - for recovery mode 
                self.force_join_own_cluster()

            self._try_sync_net = True
            self._incomplete = False
            self._num_nosync_peer = 0
            for key,peer in self._fbft.get_topology_iter():
                # send message to all unsync peers and peer[PeerAtr.node_state] == PeerSync.nosync
                if key != self.validator_id and PeerAtr.node_state in peer  and PeerAtr.endpoint in peer:
                    #self._num_nosync_peer += 1
                    LOGGER.debug("SYNC PEER=%s endpoint=%s node_state=%s",key[:8],peer[PeerAtr.endpoint],peer[PeerAtr.node_state])
                    self.sync_to_peer_with_endpoint(peer[PeerAtr.endpoint])
                else:
                    #LOGGER.debug("SKIP SYNC PEER=%s(%s)",key[:8],peer[PeerAtr.name] if PeerAtr.name in peer else '')
                    pass
            if self._num_nosync_peer == 0:
                self._nosync = False
                if self.is_genesis_peer:
                    self.myself_sync(True)
            LOGGER.debug("TRY_TO_SYNC_WITH_NET DONE SYNC=%s unsync peers=%s\n",self.is_sync,self._num_nosync_peer)

    def check_unsync_peer(self):
        with self._lock:
            if len(self._unsync_peers) > 0:
                #LOGGER.debug("Check unsync peers\n")
                ctime = time.time()

                for endpoint,stime in self._unsync_peers.items():
                    if (ctime - stime) > SYNC_CHECK_TOUT:
                        if endpoint not in self._notvalid_peers:
                            LOGGER.debug("TRY SYNC WITH peer=%s\n",endpoint)
                            self.sync_to_peer_with_endpoint(endpoint)
                        else:
                            LOGGER.debug(f"PEER={endpoint} NOT VALID NOT SYNC\n")

    def peer_is_visible_for_me(self,public_key):
        is_arbiter = self._fbft.peer_is_arbiter(public_key)
        return self._fbft.is_own_peer(public_key) or is_arbiter or (self._fbft.is_arbiter and self._fbft.peer_is_leader(public_key))

    def update_peer_dashboard(self,pkey,status,network):
        """
        update peer status for dashboard
        """
        LOGGER.debug("Inform DASBOARD network=%s peers=%s status=%s",network,pkey[:8],status)
        peer,_ = self._fbft.key_to_peer(pkey)
        if peer:
            peer[PeerAtr.network] = network
            peer[PeerAtr.node_state] = (PeerSync.active if status else PeerSync.nosync)

    def notify_dashboard(self,pkey,status,network):
        """
        send info about not leader peer to dashboard
        """
        LOGGER.debug("Inform DASBOARD about peer=%s network=%s status=%s\n",pkey[:8],network,status)
        cid = self._network.public_key_to_connection_id(self._fbft.genesis_node)
        if cid :
            # send info
            try:
                peers_response = GetPeersResponse(status=GetPeersResponse.PEERSTAT,
                                              cluster=network,
                                              peer_endpoints=[pkey,str(status) ]
                                              )
            
                # Send a one_way message because the connection will be closed
                # if this is a temp connection.
                self._network.send(
                    validator_pb2.Message.GOSSIP_GET_PEERS_RESPONSE,
                    peers_response.SerializeToString(),
                    cid,
                    one_way=True)
            
            except Exception as ex:
                LOGGER.debug("notify_dashboard except(%s)", ex)
            except ValueError:
                LOGGER.debug("Connection disconnected: %s", cid)

    def notify_peer_connected(self,public_key,assemble=False,mode=ConsensusNotifyPeerConnected.NORMAL):
        """
        Use topology for restrict peer notification
        """
        is_arbiter = self._fbft.peer_is_arbiter(public_key)
        is_own_peer = self._fbft.is_own_peer(public_key)
        
        if is_own_peer or is_arbiter or (self._fbft.is_arbiter and self._fbft.peer_is_leader(public_key)):
            """
            own cluster or arbiters
            if is_arbiter:
                arbiter = self._fbft.arbiters[public_key]
            if not is_arbiter or PeerAtr.endpoint in arbiter[2]:
            In case of leader change this request could be appeared before new leader will be set into topology 
            so we should inform consensus later 
            """
            if self.is_arbiter and not self.is_genesis_peer and is_own_peer and public_key != self.validator_id:
                pinfo = self._fbft.get_own_peer(public_key)
                try:
                    self.notify_dashboard(public_key,assemble,pinfo[PeerAtr.network])
                except Exception as ex:
                    LOGGER.debug("notify_dashboard except(%s)", ex)

            LOGGER.debug("Inform engine ADD peer=%s assemble=%s mode=%s is_arbiter=%s",public_key[:8],assemble,mode,is_arbiter)
            self._consensus_notifier.notify_peer_connected(public_key,assemble,mode)
            if public_key == self.validator_id and not self._genesis_sync:
                # FIXME - why we do it ?
                self._nosync = assemble
            #else:
            #    LOGGER.debug("Arbiter=%s for %s not connected",arbiter[2],arbiter[1])
        else:
            # set into self._fbft activity of peer - for dashboard
            LOGGER.debug("Inform engine IGNORE peer=%s\n",public_key[:8])

    def notify_peer_disconnected(self,public_key):
        """
        Use topology for restrict peer notification
        """
        if self._fbft.is_own_peer(public_key) or public_key in self._fbft.arbiters:
            # own cluster or arbiters
            LOGGER.debug("Inform engine DEL peer=%s",public_key[:8])
            self._consensus_notifier.notify_peer_disconnected(public_key)

    def send_peers(self, connection_id):
        """
        Dynamic topology mode
        Sends a message containing our peers to the
        connection identified by connection_id.

        Args:
            connection_id (str): A unique identifier which identifies an
                connection on the network server socket.
            
        """
        with self._lock:
            """
             Needs to actually be the list of advertised endpoints of
             our peers
            """
            peer_endpoints = list(self._peers.values())
            if self.endpoint:
                peer_endpoints.append(self.endpoint)
            LOGGER.debug("Send peers ENDPOINTS: %s\n", peer_endpoints)
            peers_response = GetPeersResponse(peer_endpoints=peer_endpoints)
            try:
                # Send a one_way message because the connection will be closed
                # if this is a temp connection.
                self._network.send(
                    validator_pb2.Message.GOSSIP_GET_PEERS_RESPONSE,
                    peers_response.SerializeToString(),
                    connection_id,
                    one_way=True)
            except ValueError:
                LOGGER.debug("Connection disconnected: %s", connection_id)

    def get_dynamic_peers_info(self,endpoint,connection_id,is_own,is_arb=False):
        dyn_endpoints = [] 
        # get network of peer for which we preparing info                                                                                             
        net = self._network.get_connection_network(connection_id)                                                                                                                      
        for cid,endp in self._peers.items():                                                                                                     
            if  endp == endpoint:   #endp not in self._static_peer_endpoints  
                continue
            dnet = self._network.get_connection_network(cid)                                                                                 
            pid = self._network.connection_id_to_public_key(cid)                                                                             
            if is_own:                                                                                                                       
                # for own cluster peer send only other cluster peers                                                                         
                if not self._fbft.is_own_peer(pid):                                                                                            
                    continue                                                                                                                 
            else:                                                                                                                            
                # it could be leader or arbiter - send other known arbiters  
                # and  endpoint should be leader or arbiter too !                                                               
                if not is_arb or pid not in self._fbft.arbiters:                                                                                           
                    continue                                                                                                                 
                                                                                                                                             
            if net == self.network:                                                                                                          
                dendp = endp                                                                                                                 
            else:                                                                                                                            
                if dnet == self.network:                                                                                                     
                    dendp = self.get_conn_expoint(cid)                                                                                       
                else:                                                                                                                        
                    if dnet != net:                                                                                                          
                        dendp = endp                                                                                                         
                    else:                                                                                                                    
                        # dnet and net the same network                                                                                      
                        dendp = self.get_conn_expoint(cid,ext=False)                                                                         
                                                                                                                                             
            if dendp and dendp not in dyn_endpoints:                                                                                         
                dyn_endpoints.append(dendp)                                                                                                  
                dyn_endpoints.append(dnet)                                                                                                   
                LOGGER.debug("ADD DYN peer=%s dendp=%s net=%s network=%s ext=%s",endp,dendp,dnet,self.network,self.get_conn_expoint(cid))    
        return dyn_endpoints



    def send_dynamic_peers_info(self,endpoint,connection_id,pkey):
        # for static peer send info about dynamic peers
        # inform static peer about registred dynamic                                                                                          
        # use info about endpoint's networks   
        is_own = self._fbft.is_own_peer(pkey)  
        is_arb = pkey in self._fbft.arbiters
        dyn_endpoints = self.get_dynamic_peers_info(endpoint,connection_id,is_own,is_arb)                                                                                                                    
                          
        if len(dyn_endpoints) > 0:
            LOGGER.debug("INFORM static peer=%s is_own=%s is_arb=%s about dynamic=%s",endpoint,is_own,is_arb,dyn_endpoints)
            peers_response = GetPeersResponse(status=GetPeersResponse.DYNPEERS,
                                              cluster=None,
                                              peer_endpoints=dyn_endpoints
                                             )
            try:
                # Send a one_way message because the connection will be closed
                # if this is a temp connection.
                self._network.send(
                    validator_pb2.Message.GOSSIP_GET_PEERS_RESPONSE,
                    peers_response.SerializeToString(),
                    connection_id,
                    one_way=True)
            except ValueError:
                LOGGER.debug("Connection disconnected: %s", connection_id)

    def add_me_into_peer_info(self,peer_endpoints,network):
        peer_endpoints.append(self.extpoint if network != self.network else self._endpoint)
        peer_endpoints.append(self.network)

    def get_peer_info_for_leader(self,network):
        """
        new leader - get list of peer which it should know
        """
        peer_endpoints = []
        self.add_me_into_peer_info(peer_endpoints,network)
        
    
        for key,arbiter in self._fbft.arbiters.items():
            #arb = arbiter[2][key] 
            arb = self._fbft.get_own_peer(key,cluster=arbiter[2])
            LOGGER.debug("info_for_leader arbiter: %s.%s active=%s network=%s", key[:8],arb[PeerAtr.name],PeerAtr.endpoint in arb,network)
            if PeerAtr.endpoint in arb:
                endpoint = arb[PeerAtr.endpoint]
                net = self._network.endpoint_to_network(endpoint)
                try:
                    real_endpoint = arb[PeerAtr.intpoint if network == net else PeerAtr.extpoint]
                    peer_endpoints.append(real_endpoint)
                    peer_endpoints.append(net)
                    LOGGER.debug("add active peer=%s %s(%s) into info list endp=%s", key[:8],endpoint,net,real_endpoint)
                except Exception as ex:
                    LOGGER.debug("Cant add active peer=%s %s(%s) into info list (%s)", key[:8],endpoint,net,ex)

        return peer_endpoints

    def send_fbft_peers(self, connection_id,pid,endpoint,cluster=None,KYC=None,network='net0',pbatch=None):
        """
        Dynamic Fbft topology mode
        Sends a message containing our peers to the
        connection identified by connection_id.

        Args:
            connection_id (str): A unique identifier which identifies an
                connection on the network server socket.
            pid - public key of peer
            endpoint - peer endpoint
            cluster - desire cluster
            KYC     - KYC of new peer
        """
        peer,parent = self._fbft.key_to_peer(pid)
        if peer is None:
            # try to find position into public cluster or into private cluster with KYC control
            status = GetPeersResponse.PENDING
            if KYC == '':
                # find place into public cluster
                cname,parent = self._fbft.get_position_in_public(self.max_feder_peer)
                if cname is None :
                    status = GetPeersResponse.NOSPACE
                    if self.auto_cluster_mode:
                        if pbatch == '':
                            batch = self.add_public_cluster_batch(pid,KYC)
                            if batch:
                                LOGGER.debug("TRY CREATE NEW PUBLIC CLUSTER batch=%s",batch.header_signature)
                                status = GetPeersResponse.WAITING
                                self._add_batch(batch,('',0,0))
                        else:
                            LOGGER.debug("WAITING UNTIL NEW CLUSTER WAS CREATED pbatch=%s",pbatch)
                            status = GetPeersResponse.WAITING
                    else:
                        LOGGER.debug("There are no space into PUBLIC CLUSTER!")
                else:
                    batch = self.add_peer_batch(parent,cname,pid,KYC)                  
                    LOGGER.debug("batch add peer=%s",batch.header_signature)               
                    self._add_batch(batch,('',0,0))  
                    LOGGER.debug("Undefined new peer=%s cluster=%s\n", pid[:8],cname)                                  
            else:
                # cluster name should be set and certificate should be registred
                cname = None
                if cluster is not None:
                    url = cluster.split(':')
                    if url[0] != '':
                        # update map 
                        xcert = self.get_xcert_cache(KYC,pid)
                        cert_oper = 'set'
                        if xcert and not self.is_xcert_valid(xcert,pid):
                            # TRY TO UPDATE OLD CERT 
                            LOGGER.debug(f"OLD CERT NOT VALID - UPDATE XCERT {xcert.not_valid_after}\n")
                            xcert = None
                            self._settings_cache.invalidate(pid)
                            cert_oper = 'upd'
                             
                        is_valid = self.check_xcert(KYC,pid) if xcert is None else True
                        
                        if is_valid:
                            # KYC correct or already registred cert 
                            if endpoint in self._notvalid_peers:
                                del self._notvalid_peers[endpoint]
                            LOGGER.debug(f"UPDATE MAP={url[0]} XCERT={xcert}\n")
                            batch = self.add_nest_batch(url[0],pid,KYC,xcert=(xcert==None),oper=cert_oper)
                            self._add_batch(batch,('',0,0))  
                            cname,parent = self._fbft.nest2cluster(url[0])
                            LOGGER.debug(f"Add peer={pid[:8]} into MAP={url[0]} clust={cname}\n") 
                        else:
                            status = GetPeersResponse.NOT_VALID_CERT

            
        else:
            status = GetPeersResponse.OK
            if KYC is not None:
                xcert = self.get_xcert_cache(KYC,pid)
                if xcert:
                    if not self.is_xcert_valid(xcert,pid):
                        status = GetPeersResponse.NOT_VALID_CERT
                    
                else:
                    LOGGER.debug(f"New peer={pid[:8]} UNDEF XCERT !!!!\n")
                    status = GetPeersResponse.NOT_VALID_CERT

            cname = parent[PeerAtr.name]
            LOGGER.debug("New peer=%s(%s) cluster=%s(%s) (%s)\n",endpoint, pid[:8],cname,self._fbft.nest_colour,peer)
            

        with self._lock:
            """
             check pid into topology and in case of success make list of peer for peer position into topology
             Needs to actually be the list of advertised endpoints of
             our peers
            """
            if cname == self._fbft.nest_colour:
                # this is own cluster of new peer
                if peer:
                    """
                    There is position for peer add all known peer into list
                    and inform about new peer all rest peers of this cluster
                    """
                    peer_endpoints =  self.get_dynamic_peers_info(endpoint,connection_id,True) #list(set(self._peers.values()))
                    LOGGER.debug("peer_endpoints=%s", peer_endpoints)
                    self.add_me_into_peer_info(peer_endpoints,network)

                    """
                    extpoints = []
                    if network != self.network:
                        # change endpoint on extpoint
                        #LOGGER.debug("change endpoint=%s on extpoint", peer_endpoints)
                        for pend in peer_endpoints:
                            
                            pkey = self._network.endpoint_to_public_key(pend)
                            #LOGGER.debug("GET PKEY=%s endpoint=%s",pkey,pend)
                            if pkey :
                                epeer,_ = self._fbft.key_to_peer(pkey)
                                if epeer and PeerAtr.extpoint in epeer:
                                    LOGGER.debug("ADD PEER extpoint=%s",epeer[PeerAtr.extpoint])
                                    extpoints.append(epeer[PeerAtr.extpoint])
                                else:
                                    LOGGER.debug("Can't get expoint from %s", epeer)
                            else:
                                LOGGER.debug("Can't get KEY for %s", pend)
                    """ 
                    
                    
                    
                else:
                    peer_endpoints = []
            else:
                # send redirect to cluster node - which know all registered peers
                peer_endpoints = []
                if cname is not None:
                    
                    leader,key = self._fbft.get_cluster_leader(parent)
                    LOGGER.debug("CLUSTER=%s LEADER KEY=(%s)\n", cname,key)
                    if leader :
                        if key == pid :
                            # send info about known leader and arbiters
                            LOGGER.debug("FIRST PEER IN NEW CLUSTER=%s\n", cname)
                            peer_endpoints = self.get_peer_info_for_leader(network)
                        elif PeerAtr.endpoint in leader:
                            endpoint = leader[PeerAtr.extpoint if network != self.network else PeerAtr.endpoint] 
                            net = self._network.endpoint_to_network(leader[PeerAtr.endpoint])
                            LOGGER.debug("REDIRECT EXPOINT=%s(%s)\n", endpoint,net)
                            peer_endpoints.append(endpoint) 
                            peer_endpoints.append(net)
                            status = GetPeersResponse.REDIRECT 
                        else:
                            status = GetPeersResponse.PENDING
                            LOGGER.debug("LEADER=%s of CLUSTER=%s KEY=%s NOT READY PENDING\n",leader is not None,cname,key)
                            self.add_me_into_peer_info(peer_endpoints,network)
                            #peer_endpoints.append(self.extpoint if network != self.network else self._endpoint)

                    elif self.endpoint: 
                        # continue ask my node 
                        status = GetPeersResponse.PENDING
                        LOGGER.debug("LEADER=%s of CLUSTER=%s NOT READY FOR REDIRECT ON IT\n",leader is not None,cname)
                        self.add_me_into_peer_info(peer_endpoints,network)
                        #peer_endpoints.append(self.extpoint if network != self.network else self._endpoint)
                else:
                    #
                    if status not in [GetPeersResponse.NOSPACE,GetPeersResponse.NOT_VALID_CERT]: # GetPeersResponse.NOT_VALID_CERT
                        # wait place into new cluster and ask me
                        LOGGER.debug(f"WAIT PLACE INTO CLUSTER={cname} network={network}\n")
                        self.add_me_into_peer_info(peer_endpoints,network)
                        #peer_endpoints.append(self.extpoint if network != self.network else self._endpoint)
                    else:
                        LOGGER.debug("CANT JOIN PEER=%s WITH NET - %s\n",endpoint,"NOSPACE" if status == GetPeersResponse.NOSPACE else "NOT_VALID_CERT")
                        if endpoint not in self._notvalid_peers:
                            #
                            LOGGER.debug(f"ADD PEER={endpoint} INTO NOT VALID")
                            self._notvalid_peers[endpoint] = True 
            
                
            LOGGER.debug("Send peers cluster=%s status=%s ENDPOINTS: %s\n",cname,status, peer_endpoints) 
            peers_response = GetPeersResponse(status=status,
                                              cluster=cname if status != GetPeersResponse.WAITING else (pbatch if pbatch != '' else batch.header_signature),
                                              peer_endpoints=peer_endpoints
                                              )
            try:
                # Send a one_way message because the connection will be closed
                # if this is a temp connection.
                self._network.send(
                    validator_pb2.Message.GOSSIP_GET_PEERS_RESPONSE,
                    peers_response.SerializeToString(),
                    connection_id,
                    one_way=True)
            except ValueError:
                LOGGER.debug("Connection disconnected: %s", connection_id)

    def add_candidate_peer_endpoints(self, peer_endpoints,status=None,cluster=None):
        """
        Adds candidate endpoints to the list of endpoints to
        attempt to peer with.

        Args:
            peer_endpoints ([str]): A list of public uri's which the
                validator can attempt to peer with.
        """
        if status == GetPeersResponse.DYNPEERS or status == GetPeersResponse.PEERSTAT:
            LOGGER.debug("add_candidate_peer_endpoints: DYNAMIC peers=%s",peer_endpoints)
            for i in  range(len(peer_endpoints)):
                if i % 2 == 0:
                    endp = peer_endpoints[i]
                    if status == GetPeersResponse.DYNPEERS:
                        if endp not in self._initial_peer_endpoints:
                            self._topology.add_visible_peer(endp,peer_endpoints[i+1])
                    else:
                        self.update_peer_dashboard(endp,peer_endpoints[i+1] == 'True',cluster)

            return
        

        LOGGER.debug("add_candidate_peer_endpoints: cluster=%s  status=%s",cluster,status)
        if cluster:
            if status == GetPeersResponse.WAITING:
                self._batch = cluster
            else:
                self._join_cluster = cluster
        if self._topology:
            self._topology.add_candidate_peer_endpoints(peer_endpoints,status)
        else:
            LOGGER.debug("Could not add peer endpoints to topology. ConnectionManager does not exist.")

    def get_peers(self,mode = ConsensusNotifyPeerConnected.NORMAL):
        """
        Returns a copy of the gossip peers.
        """
        
        if self._malicious != mode:
            # say engine about new mode
            LOGGER.debug("GET PEERS MODE=%s->%s\n",self._malicious,mode)
            self._malicious = mode
            self.notify_peer_connected(self.validator_id,assemble=True,mode=mode)

        with self._lock:
            curr_peer =  copy.copy(self._peers)
        curr_peer["own"] = self.endpoint
        return curr_peer

    def is_peers(self):
        """
        use for check peer registration - we should waiting until some arbiter or own cluster peers appeared
        """
        with self._lock:
            peer_keys = [self._network.connection_id_to_public_key(cid) for cid in self._peers]
        for key  in set(peer_keys):
            if self._fbft.is_own_peer(key) or key in self._fbft.arbiters: #FIXME check arbiters is None or not
                return True
        return False
        #return max(peer_keys, key = lambda pk: 1 if pk in self._fbft.cluster or pk in self._fbft.arbiters  else 0) > 0

    def remove_peer(self,endpoint):
        LOGGER.debug("remove_peer endpoint=%s...\n",endpoint)
        public_key = self._fbft.update_peer_activity(None,endpoint,True,sync=False,force=True)
        # inform consensus about new peer status
        if public_key:
            # inactive now
            self.notify_peer_connected(public_key,assemble=False)

    def make_endpoint_mess(self,nkey):
        """
        make message with arbiter list for new arbiter or leader
        """
        endpoints = []                                                                                                                                          
        for key,peer in self._fbft.arbiters.items():                                                                                                            
            LOGGER.debug("CHECK ARBITER=%s %s",key[:8],peer[1])                                                                                                 
            if key in peer[2] :
                # peer[2] = cluster                                                                                                                                 
                arbiter = peer[2][key]                                                                                                                          
                if PeerAtr.endpoint in arbiter and PeerAtr.delegate in arbiter and arbiter[PeerAtr.delegate] and key != nkey:                                                   
                    LOGGER.debug("SAY ARBITER'S=%s(%s) endpoint=%s to new LEADER=%s",key[:8],arbiter[PeerAtr.name],arbiter[PeerAtr.endpoint],nkey[:8])          
                    endpoint = EndpointItem(peer_id=bytes.fromhex(key),endpoint=arbiter[PeerAtr.endpoint])                                                      
                    endpoints.append(endpoint)                                                                                                                  
                else:                                                                                                                                           
                    LOGGER.debug("SKIP ARBITER'S=%s(%s) %s NO endpoint or old or itself",key[:8],arbiter[PeerAtr.name],peer[1])                                           
            else:                                                                                                                                               
                LOGGER.debug("NO ARBITER=%s IN CLUSTER %s",key[:8],peer[1]) 

        for key,peer in self._fbft.leaders.items():                                                                                                            
            LOGGER.debug("CHECK LEADERS=%s %s",key[:8],peer[1])
            if key not in self._fbft.arbiters and key in peer[2]:
                leader = peer[2][key]
                if PeerAtr.endpoint in leader:
                    endpoint_url = leader[PeerAtr.endpoint]
                    LOGGER.debug("SAY LEADER'S=%s endpoint=%s to new LEADER=%s",key[:8],endpoint_url,nkey[:8])          
                    endpoint = EndpointItem(peer_id=bytes.fromhex(key),endpoint=endpoint_url)                                                      
                    endpoints.append(endpoint)
            else:
                LOGGER.debug("LEADERS IS ARBITER=%s SKIP",key[:8]) 
        return endpoints                                                                                            


    def update_cluster_leader(self,cluster,npeer):
        """
        new cluster leader
        """
        own_role = self._fbft.own_role # my current role                                                                                                                               
        changed,nkey = self._fbft.change_cluster_leader(cluster,npeer)                                                                                                                 
        if not changed : 
            return
        # was changed                                                                                                                                                                  
        LOGGER.debug("UPDATE topology NEW LEADER %s.%s key=%s LEADER=%s!!!\n",cluster,npeer,nkey[:8],(own_role == PeerRole.leader))                                                
        self._consensus_notifier.notify_peer_change_role(nkey,cluster) #PeerRole.leader)                                                                                           
        if cluster == self._fbft.nest_colour:                                                                                                                                      
            """                                                                                                                                                                    
            in case of own cluster we should inform new leader about arbiter's endpoint                                                                                            
            """                                                                                                                                                                    
            if own_role == PeerRole.leader:                                                                                                                                        
                # I was leader before change role                                                                                                                                  
                endpoints = self.make_endpoint_mess(nkey)                                                                                                                                                     
                if len(endpoints) > 0:                                                                                                                                             
                    # make message for new leader                                                                                                                                  
                    self.send_endpoint_message(endpoints,nkey)                                                                                                                     
                                                                                                                                                                                   
        else:                                                                                                                                                                      
            # other cluster change leader - but arbiters stay the same                                                                                                             
            if own_role == PeerRole.leader:                                                                                                                                        
                # check maybe new leader already connected - so we should say consensus about it                                                                                   
                LOGGER.debug("OTHER CLUSTER=%s change LEADER",cluster)                                                                                                             
                """                                                                                                                                                                
                if nkey in self._fbft.arbiters:                                                                                                                                    
                    arbiter = self._fbft.arbiters[nkey]                                                                                                                            
                    LOGGER.debug("NEW ARBITER=%s in other cluster %s",nkey[:8],cluster)                                                                                            
                    if PeerAtr.endpoint in arbiter[2]:                                                                                                                             
                        self.check_leader_outbound(arbiter[2][PeerAtr.endpoint])                                                                                                   
                        self.notify_peer_connected(nkey,assemble=True)                                                                                                             
                """                                                                                                                                                                
            if self._fbft.is_arbiter:                                                                                                                                              
                # inform consensus engine about new leader into other cluster                                                                                                      
                peer = self._fbft.get_peer(nkey)                                                                                                                                   
                LOGGER.debug("I AM ARBITER - OTHER CLUSTER=%s change LEADER=%s\n",cluster,nkey[:8])                                                                                
                if peer and PeerAtr.endpoint in peer:                                                                                                                              
                    self.notify_peer_connected(nkey,assemble=True)                                                                                                                 



    def update_cluster_arbiter(self,cname,npeer):
        """
        new cluster arbiter
        """
        LOGGER.debug("NEW ARBITER INTO CLUSTER=%s.%s",cname,npeer)
        was_arbiter = self._fbft.is_arbiter # old arbiter
        changed,nkey = self._fbft.change_cluster_arbiter(cname,npeer)                                                                                                                 
        if not changed :
            return
        # arbiter was changed                                                                                                                                                                   
        LOGGER.debug("UPDATED topology - NEW ARBITER %s.%s key=%s!!!\n",cname,npeer,nkey[:8])
        self._consensus_notifier.notify_peer_change_role(nkey,cname,is_arbiter=True) 
        if cname == self._fbft.nest_colour:
            # in my cluster
            if was_arbiter:
                # I was arbiter
                endpoints = self.make_endpoint_mess(nkey)                                                                                                                                                     
                if len(endpoints) > 0:                                                                                                                                             
                    # make message for new arbiter                                                                                                                                  
                    self.send_endpoint_message(endpoints,nkey)
        else:
            # in others cluster
            if self._fbft.is_leader:
                # as leader I should connect with new arbiter 
                # self._topology._attempt_to_peer_with_endpoint(endpoint.endpoint)
                cluster = self._fbft.arbiters[nkey][2]
                if nkey in cluster:
                    arbiter = cluster[nkey]
                    if PeerAtr.endpoint in arbiter:
                         LOGGER.debug("NEW ARBITER=%s in other cluster endpoint=%s",nkey[:8],arbiter[PeerAtr.endpoint])
        
    def add_cluster(self,cname,pname,list):
        changed,err = self._fbft.add_new_cluster(cname,pname,list)
        if changed :
            _,pkey = self._fbft.get_peer_by_name(cname,pname)
            self._consensus_notifier.notify_topology_cluster(pkey,list)
        else:
            LOGGER.debug("Can't add cluster %s.%s (%s)\n",cname,pname,err)

    def del_cluster(self,cname,pname):
        changed,err = self._fbft.del_cluster(cname,pname)
        if changed:
            _,pkey = self._fbft.get_peer_by_name(cname,pname)
            self._consensus_notifier.notify_topology_cluster(pkey)
            
        else:
            LOGGER.debug("Can't del cluster %s.%s (%s)\n",cname,pname,err)

    def add_peer(self,cname,list):
        """
        new peer 
        """
        changed,err = self._fbft.add_new_peers(cname,list)
        if changed != -1:
            self._consensus_notifier.notify_topology_peer(self._fbft.get_cluster_owner(cname),list)
            LOGGER.debug("Add peers into cluster %s DONE\n",cname)
        else:
            LOGGER.debug("Can't add peers into cluster %s (%s)\n",cname,err)

    def del_peer(self,cname,list):                                                                      
        """                                                                                             
        del peers                                                                                        
        """                                                                                             
        changed,err = self._fbft.del_peers(cname,list)                                              
        if changed:                                                                                     
            self._consensus_notifier.notify_topology_peer(self._fbft.get_cluster_owner(cname),list,oper=ConsensusNotifyPeerConnected.DEL_PEER)     
            LOGGER.debug("DEL peers into cluster %s DONE\n",cname)                                      
        else:                                                                                           
            LOGGER.debug("Can't del peers from cluster %s (%s)\n",cname,err)                            

    def map_topo_nest(self,nlist):                                                                          
        """                                                                                                 
        set map for nest                                                                                            
        """                                                                                                 
        changed,err = self._fbft.set_nest_map(nlist)                                                  
        if changed :                                                                                   
            
            self._consensus_notifier.notify_topology_peer(self.validator_id,nlist,oper=ConsensusNotifyPeerConnected.SET_NEST)        
            LOGGER.debug("SET MAP TOPO NEST %s DONE\n",nlist)                                          
        else:                                                                                               
            LOGGER.debug("Can't add peers into cluster %s (%s)\n",nlist,err)                                


    def force_join_own_cluster(self):
        self._consensus_notifier.notify_peer_join_cluster(self.validator_id,self._join_cluster)
        self.update_topology_params(TOPOLOGY_SET_NM,self.get_topology_cache())

    def update_topology_map(self,nlist=None):
        
        LOGGER.debug(f"UPDATE topology MAP={nlist}!!!\n")
        if nlist:
            self.map_topo_nest(nlist)

    def update_topology(self,attributes=None):
        """
        topology was update
        """
        LOGGER.debug("UPDATE topology attributes=%s!!!\n",attributes)
        if len(attributes) == 0:
            # full update
            topo_map = self.get_topology_map()
            LOGGER.debug(f"JOIN CLUSTER={self._join_cluster} MAP={topo_map}!!!\n")
            
            new_topology = self.reload_topology(self._join_cluster)
            #self._consensus_notifier.notify_topology_peer(self.validator_id,topo_map,oper=ConsensusNotifyPeerConnected.SET_NEST)
            self._consensus_notifier.notify_peer_join_cluster(self.validator_id,self._join_cluster)
            #self.update_topology_params(DGT_TOPOLOGY_MAP_NM,topo_map)
            self.update_topology_params(TOPOLOGY_SET_NM,new_topology) 
            
            self.refresh_topology_peers()
        elif attributes[0].key == 'oper':
            oper = attributes[0].value
            if oper in ['lead','arbiter','cluster','cdel']:
                if attributes[1].key == 'cluster' and attributes[2].key == 'peer': 
                    cluster,npeer =  attributes[1].value,attributes[2].value
                    if oper == 'lead':
                        self.update_cluster_leader(cluster,npeer)
                    elif oper == 'arbiter':
                        self.update_cluster_arbiter(cluster,npeer)
                    elif oper == 'cluster' :
                        if attributes[3].key == 'list':
                            list = attributes[3].value
                            self.add_cluster(cluster,npeer,list)
                            
                    elif oper == 'cdel':
                        self.del_cluster(cluster,npeer)
                    

            elif oper == 'add' or oper == 'del':
                # add/del peer 
                if attributes[1].key == 'cluster' and attributes[2].key == 'list':
                    if oper == 'add':
                        self.add_peer(attributes[1].value,attributes[2].value)
                    else:
                        self.del_peer(attributes[1].value,attributes[2].value)
            elif oper == 'map':
                if attributes[1].key == 'list':
                    self.update_topology_map(attributes[1].value)
            else:
                LOGGER.debug("UPDATE topology OPERATION=%s not implemented!\n",oper)

        else:
            LOGGER.debug("UPDATE topology UNDEFINED OPERATION!!!\n")

    def refresh_topology_peers(self):
        peers = self.get_peers()                                                             
        for conn_id in peers:
            try:
                endpoint = peers[conn_id]
                cid = self._network.get_connection_id_by_endpoint(endpoint)
                pid = self._network.connection_id_to_public_key(cid)
                LOGGER.debug("Refresh: Peer %s(%s) conn=%s\n",endpoint,pid[:8],cid[:8])
                self._fbft.update_peer_activity(pid,endpoint,True,False,force=True)
            except KeyError:
                LOGGER.debug("peer %s went away",peers[conn_id])

    def update_topology_params(self,attributes=None,val=None):
        LOGGER.debug("UPDATE topology params='%s' !!!\n",attributes)
        self._consensus_notifier.notify_peer_param_update(self.validator_id,attributes,val)

    def _make_new_nest_tnx(self,nest,pid,KYC):                                                                              
        # make batch for adding new nest's key into topology - gateway dynamic mode                                                        
        nest_val = '{"'+nest+'":"'+str(pid)+'"}'               
        param = {'oper':'map','cluster':"Genesis",'list':nest_val}                                                                          
        LOGGER.debug("ADD NEST={} PID={} FOR JOIN WITH PRIVATE NET".format(nest_val,pid[0:8]))                                                                                                                            
        val = json.dumps(param, sort_keys=True, indent=4)                                                                            
        return _create_topology_txn(self._signer, (TOPOLOGY_SET_NM,val))                                                             


    def _make_peer_xcert_tnx(self,pid,KYC,oper):
        LOGGER.debug(f"ADD XCERT={pid[0:8]} FOR JOIN WITH PRIVATE NET OP={oper}")
        return create_xcert_txn(self._signer,pid,KYC,oper)

    def _make_new_peer_tnx(self,cluster,cname,pid,KYC):
        # make batch for adding new peer into topology - gateway dynamic mode
        child_num = len(cluster[PeerAtr.children])
        pname = "{}_{}".format(cname,child_num+1)
        prole = 'plink' if child_num > 0 else 'leader'
        pdelegate = 'false' if child_num > 0 else 'true'
        npeer = "{'"+str(pid)+"':{'role':'"+ prole + "','delegate':"+pdelegate+",'type':'peer','name':'"+pname+"'}}"
        param = {'oper':'add','cluster':cname,'list':npeer}
        
        val = json.dumps(param, sort_keys=True, indent=4)
        return _create_topology_txn(self._signer, (TOPOLOGY_SET_NM,val))

    def _make_new_cluster_tnx(self,cname=None,cowner=None,powner=None):
        # make tnx for adding new cluster into topology 
        cl_name = "dyn{}".format(len(self._fbft.publics)) if cname is None else cname
        
        if cowner is None:
            cowner,powner = self._fbft.get_public_extent_point()
        if cowner is None:
            return None
        LOGGER.debug("_make_new_cluster_tnx new cluster='%s' point=%s.%s",cl_name,cowner,powner)
        nclust = "{'type':'cluster','public':true,'dynamic':true,'name':'"+cl_name+"'}"
        param = {'oper':'cluster','cluster':cowner,'peer':powner,'list':nclust}
      
        val = json.dumps(param, sort_keys=True, indent=4)
        LOGGER.debug("_make_new_cluster_tnx params='%s' !!!\n",val)
        return _create_topology_txn(self._signer, (TOPOLOGY_SET_NM,val))

    def add_peer_batch(self,cluster,cname,pid,KYC):
        # make batch for adding new peer into topology - gateway dynamic mode
        txns = []

        txns.append(self._make_new_peer_tnx(cluster,cname,pid,KYC))
        batch = _create_batch(self._signer, txns)
        return batch

    def add_nest_batch(self,nest,pid,KYC,xcert=False,oper='set'):                                    
        # make batch for adding new peer into topology - gateway dynamic mode   
        txns = [] 
        if xcert:
            # add cert 
            if IS_DID(KYC):
                LOGGER.debug("CANT ADD XCERT AUTOMATICALY IN NOTARY MODE KYC='%s' !!!\n",KYC)
            else:
                txns.append(self._make_peer_xcert_tnx(pid,KYC,oper))
          
        txns.append(self._make_new_nest_tnx(nest,pid,KYC))                        
        batch = _create_batch(self._signer, txns)                                      
        return batch                                                                   

    def add_public_cluster_batch(self,pid,KYC):
        # make batch for adding new public cluster and peer into this cluster - gateway dynamic mode
        clust_txn = self._make_new_cluster_tnx()
        if clust_txn is None:
            return None
        
        txns = [clust_txn]
        batch = _create_batch(self._signer, txns)
        return batch

    def get_topology_cache(self):
        topology = self._settings_cache.get_setting(
                TOPOLOGY_SET_NM,
                self._current_root_func(),
                default_value='{}'
            ).replace("'",'"')
        return topology 

    def get_xcert_cache(self,KYC,pid):
        if IS_DID(KYC):
            key = GET_DID_UID(KYC)
        else:
            key = pid
        xcert_pem = self._settings_cache.get_xcert(             
                key,                                 
                self._current_root_func(),                       
                default_value=None                               
            ) 
        xcert = self._signer.context.load_x509_certificate(xcert_pem)  if  xcert_pem is not None else None                             
        return xcert     
                                         
    def is_xcert_valid(self,xcert,pid):
        curr = datetime.datetime.now()
        valid = curr > xcert.not_valid_before and curr < xcert.not_valid_after
        LOGGER.debug(f"New peer={pid[:8]} CHECK XCERT={xcert} VALID={valid} {xcert.not_valid_before}->{xcert.not_valid_after} PUB={xcert.public_key()}")
        return valid

    def check_xcert(self,xcert_pem,pid):
        # startswith
        if IS_DID(xcert_pem):
            # 
            return True
        else:
            xcert = self._signer.context.load_x509_certificate(xcert_pem.encode('utf-8'))
            LOGGER.debug(f"CHECK XCERT={xcert} peer={pid[:8]} ")
            return self.is_xcert_valid(xcert,pid)

    def get_topology_map(self):                          
        topo_map = self._settings_cache.get_setting(       
                DGT_TOPOLOGY_MAP_NM,                           
                self._current_root_func(),                 
                default_value='{}'                         
            )                            
        return topo_map                                    

    def load_full_topology(self,fbft,inherit_map={},cluster=None):
        self._stopology = self.get_topology_cache()     
        self._ftopology = json.loads(self._stopology) 
        """  
        self._topo_map  = self.get_topology_map() 
        if inherit_map != {}:
            fbft.load_topo_map(inherit_map)
        fbft.load_topo_map(self._topo_map)
        """
        fbft.get_topology(self._ftopology,self.validator_id,self.endpoint,self._peering_mode,self.network,cluster)
        fbft.set_peers_control(self._peers_ctrl)
         
             
    def reload_topology(self,cluster):
        # this for dynamic peer -  topology nest we can take from map using self.validator_id
        fbft = FbftTopology()
        inherit_map = self._fbft.nest_map2str if self._fbft is not None else {}
        self.load_full_topology(fbft,inherit_map,cluster)

        with self._lock:
            self._fbft = fbft
        LOGGER.debug("RELOAD topology=%s\n",self._fbft.topology)
        return self._stopology

    def load_topology(self):
        if self._stopology is not None :
            LOGGER.debug("LOAD topology - already loaded\n")
            return
        LOGGER.debug("LOAD topology ...\n")
        self.load_full_topology(self._fbft)
        
        self._settings_cache.add_handler(TOPOLOGY_SET_NM,self.update_topology)
        #self._settings_cache.add_handler(DGT_TOPOLOGY_MAP_NM,self.update_topology_map)
        self._settings_cache.add_handler("dgt.fbft.",self.update_topology_params)
        self._settings_cache.add_handler("dgt.consensus.",self.update_topology_params)
        
        LOGGER.debug("LOAD topology DONE SYNC=%s",self.is_sync)
        

    def get_topology(self):
        """
        topology with cluster  
        FIXME - we should extend base version with information about status peers
        """
        if self._fbft is None:
            stopology = self.get_topology_cache()
            return stopology.encode("utf-8")
        # 
        stopology = json.dumps(
                self._fbft.topology,
                indent=2,
                separators=(',', ': '),
                sort_keys=True)        
        
        #LOGGER.debug("get topology=%s",stopology.encode("utf-8")) 
        return stopology.encode("utf-8")

    def get_gates(self):                                                           
        """                                                                           
        topology with cluster                                                         
        FIXME - we should extend base version with information about status peers     
        """                                                                           
        
        sgates = json.dumps(                                                       
                self._fbft.gates,                                                  
                indent=2,                                                             
                separators=(',', ': '),                                               
                sort_keys=True)                                                       
                                                                                      
        #LOGGER.debug("get topology=%s",stopology.encode("utf-8"))                    
        return sgates.encode("utf-8")                                              


    def peer_to_public_key(self, peer):
        """Returns the public key for the associated peer."""
        with self._lock:
            return self._network.connection_id_to_public_key(peer)

    def sync_peer(self, connection_id,pid, intpoint,nests=None):
        """
        ->> peer with endpoint ask sync him with this validator
        FIXME - we should compare own nests with that peer nests
        """
        is_not_diff = (nests == self.heads_summary) if nests is not None else True
        with self._lock:
            public_key = self._network.connection_id_to_public_key(connection_id)
            endpoint   = self._network.connection_id_to_endpoint(connection_id)
            is_sync = self.is_sync
            LOGGER.debug("sync_peer: Peer=%s key=%s ASK SYNC with ME incomplete=%s SYNC=%s hid=%s~%s", endpoint, public_key[:8], self._incomplete,is_sync, nests, self.heads_summary)
            if is_not_diff:
                # set peer with endpoint into sync mode 
                # FIXME - check maybe peer already sync
                if self._fbft.get_peer_state(public_key) != PeerSync.active:
                    LOGGER.debug("SYNC REQUEST FROM PEER=%s SET PEER STATUS SYNC=%s\n",endpoint,is_sync)
                    self.update_federation_topology(public_key,endpoint,sync = True,pid=pid)
                    self.notify_peer_connected(public_key,assemble=True)
                if self._fbft.get_peer_state(self.validator_id) != PeerSync.active :
                    # set own sync status but check maybe own DAG incompleted yet
                    LOGGER.debug("SYNC REQUEST FROM PEER=%s SET OWN STATUS incomplete=%s\n",endpoint,self._incomplete)
                    if not self._incomplete:
                        self.update_federation_topology(self.validator_id,None,sync = True)
                        self.notify_peer_connected(self.validator_id,assemble=True)
                        LOGGER.debug("PEER ASK SYNC - SWITCH MYSELF TO SYNC\n")
                if not is_sync:
                    # appeared peer which has the same head's summary
                    # set own sync
                    self.myself_sync(True)
                    
                    LOGGER.debug("APPEARED PEER SYNC WITH ME - SWITCH MYSELF TO SYNC\n")

            else:
                # if peer was in sync mode we should reset him into unsync
                pass
        # answer for endpoint peer 
        return is_not_diff

    def register_peer(self, connection_id,pid, intpoint,sync=None,component=None,extpoint=None):
        """
        Registers a connected connection_id.

        Args:
            connection_id (str): A unique identifier which identifies an
                connection on the network server socket.
            endpoint (str): The publically reachable endpoint of the new peer
            sync - if sync == None this is request from other peer if sync == (true|false) this is reply on our request
            sync == true - means that we connected after point of assemble - so we must do sync 
            sync == false - means that we connected in time 
        """
        
        with self._lock:
            endpoint = self._network.connection_id_to_endpoint(connection_id)
            if len(self._peers) < self._maximum_peer_connectivity:
                LOGGER.debug("Register endpoint=%s component=%s assembled=%s sync=%s SYNC=%s incomplete=%s peers=%s",endpoint,component,self.is_federations_assembled,sync,self.is_sync,self._incomplete,self.peers_info)
                self._peers[connection_id] = endpoint
                if self._topology:
                    self._topology.set_connection_status(connection_id,PeerStatus.PEER)
                else:
                     LOGGER.debug("Can't set connection status for  endpoint=%s(TOO EARLY)\n",endpoint)
                LOGGER.debug("Added connection_id %s with endpoint %s, connected identities are now=%s",connection_id[:8], endpoint, self.peers_info)
            else:
                raise PeeringException("At maximum configured number of peers: {} Rejecting peering request from {}.".format(self._maximum_peer_connectivity,endpoint))

        public_key = self.peer_to_public_key(connection_id)
        if public_key:
            """
            send message about peer to consensus engine
            in case timeout for waiting peers is expired
            """
             
            peer = self._fbft.get_peer(public_key)
            #if self._fbft.own_role == PeerRole.leader and peer and peer[PeerAtr.role] == PeerRole.leader:
            #    # check maybe this is new leader
            #    self.check_leader_outbound(endpoint)
            status_updated = False
            peer_state = self._fbft.get_peer_state(public_key,peer)
            LOGGER.debug("Register endpoint=%s STATE=%s",endpoint,peer_state) 
            if sync is None and peer_state != PeerSync.nosync:
                # set unsync until SYNC request
                LOGGER.debug("Register endpoint=%s set STATE=unsync",endpoint)
                self._fbft.update_peer_activity(public_key,None,True,False,force=True,pid=pid)
                status_updated = True
                

            if component is not None:
                network = self._network.get_connection_network(connection_id)
                self._fbft.update_peer_component(public_key, component,pid=pid,extpoint=extpoint,intpoint=intpoint,network=network)
                if peer and self.peer_is_visible_for_me(public_key) and endpoint not in self._initial_peer_endpoints:
                    # if this peer belonge our cluster make connection with them 
                    
                    LOGGER.debug("PEER=%s %s VISIBLE FOR US - ADD THIS PEER network=%s inet=%s", public_key[:8], endpoint,network,intpoint)
                    self._topology.add_visible_peer(endpoint,network)
            else:
                # This is Reply on my REGISTER request
                if not self._incomplete:
                    """
                    in case broken connection with this peer we should check DAG's hash of this peer and understand sync status of this peer
                    """
                    self.sync_to_peer_with_endpoint(endpoint,connection_id)

            if self.is_federations_assembled and peer_state != PeerSync.nosync and (status_updated or component is not None):
                self.notify_peer_connected(public_key,assemble=False) #(sync== True)) # CHECKME
            
            if self._is_federations_assembled and not self._is_send_block_request and self._fbft.genesis_node == public_key and not self._is_recovery_func():
                # after point of assemble we can have no connected peers - so if this is Genesis ask HEAD
                self.send_block_request("HEAD", connection_id)
        return self.is_federations_assembled
            
                

    def unregister_peer(self, connection_id):
        """Removes a connection_id from the registry.

        Args:
            connection_id (str): A unique identifier which identifies an
                connection on the network server socket.
        """
        public_key = self.peer_to_public_key(connection_id)
        
        if public_key:
            LOGGER.debug("Unregister peer=%s connection_id=%s\n",public_key[:8],connection_id[:8])
            net = self._network.get_connection_network(connection_id)
            self.notify_dashboard(public_key,False,net)
            self.notify_peer_disconnected(public_key)
            self.update_federation_topology(public_key,self._peers[connection_id] if connection_id in self._peers else None,False,force=True)

        with self._lock:
            if connection_id in self._peers:
                del self._peers[connection_id]
                LOGGER.debug("Removed connection_id %s, connected identities are now=%s",connection_id, self._peers)
                self._topology.set_connection_status(connection_id,PeerStatus.TEMP)
            else:
                LOGGER.debug("Connection unregister failed as connection was not registered: %s",connection_id)

    def check_leader_outbound(self,endpoint):
        
        n = 0
        with self._lock:
            for uri in self._peers.values():
                if endpoint == uri:
                    n += 1
        LOGGER.debug("CHECK maybe this endpoint=%s is new leader n=%s",endpoint,n)
        if n == 1:
            LOGGER.debug("TRY ADD OUTBOUND for endpoint=%s\n",endpoint)
            self._topology._attempt_to_peer_with_endpoint(endpoint)

        
        
    def switch_on_federations(self):
        """
        inform consensus engine about peers and 
        send request about block HEAD
        that topology point of assemble after that we suppose all appeared peers inconsistent 
        """
        self._is_federations_assembled = True
        LOGGER.debug("switch_on_federations peers=%s",len(self._peers))
        with self._lock:
            peer_keys = [self._network.connection_id_to_public_key(cid) for cid in self._peers]
            keys_cid  = {self._network.connection_id_to_public_key(cid) : cid for cid in self._peers} 
        LOGGER.debug("switch_on_federations peers=%s SYNC=%s (ns:gs=%s,%s) non SYNC=%s",peer_keys,self.is_sync,self._nosync,self._genesis_sync,self._num_nosync_peer)
        if not self.is_sync and not self._genesis_sync and not self._own_sync:
            # in case not genesis peer should first make nests
            # and not self._own_sync - say about sync after dag recovery
            self._fbft.update_peer_activity(self.validator_id,None,True,False,force=True)
            self._fbft.update_peer_activity(self._fbft.genesis_node,None,True,False,force=True)
            self.notify_peer_connected(self.validator_id,assemble=False)
            LOGGER.debug("switch_on_federations SWITCH MYSELF TO UNSYNC\n")
        for public_key in set(peer_keys):
            if public_key:
                cid = keys_cid[public_key]
                is_recovery = self._is_recovery_func() #FIXME may be better do it before cicle
                LOGGER.debug("Switch on federations peer=%s send HEAD request cid=%s SYNC=%s recovery=%s",public_key[:8],cid[:8],not self.is_sync,is_recovery)
                
                if self._fbft.genesis_node == public_key :
                    #self._incomplete = True # we should get current DAG
                    if not is_recovery :
                        # if recovery from local database complited - send request to other cluster
                        self.send_block_request("HEAD", cid)
                    else:
                        self._incomplete = True # we should get current DAG
                self.notify_peer_connected(public_key,assemble=True)
                
        if self._fbft.genesis_node == self.validator_id :
            # this is genesis peer - make nests 
            LOGGER.debug("switch_on_federations make NESTS for genesis=%s SYNC=%s",self.validator_id[:8],self.is_sync)

    def dyn_switch_on_federations(self,endpoint):
        """
        send request about block HEAD
        that topology point of assemble after that we suppose all appeared peers inconsistent 
        """
        leader_cid = None
        with self._lock:
            for cid,endp in self._peers.items():
                if endp == endpoint or endpoint is None:
                    leader_cid = cid
                    break
        if leader_cid:
            # ask head from leader
            self._is_federations_assembled = True
            self.send_block_request("HEAD", cid)

    def get_fbft_setting(self,param):
        if param not in self._settings:
            self._settings[param] = \
            self._settings_cache.get_setting(
                param,
                self._current_root_func(),
                default_value=_PARAM_DEFAULT_[param]
            )
        return self._settings[param]

    def get_time_to_live(self):
        time_to_live = \
            self._settings_cache.get_setting(
                TIME_TO_LIVE_NM,
                self._current_root_func(),
                default_value=TIME_TO_LIVE
            )
        return int(time_to_live)

    def broadcast_block(self, block, exclude=None, time_to_live=None):
        if time_to_live is None:
            time_to_live = self.get_time_to_live()
        LOGGER.debug("broadcast BLOCK=%s",block.header_signature[:8])
        gossip_message = GossipMessage(
            content_type=GossipMessage.BLOCK,
            content=block.SerializeToString(),
            time_to_live=time_to_live)

        self.broadcast(gossip_message, validator_pb2.Message.GOSSIP_MESSAGE, exclude)

    def broadcast_block_request(self, block_id,block_num=None):
        """
        for DAG send current block num too - it helps reconstruct DAG chain without gap 
        """
        time_to_live = self.get_time_to_live()
        block_request = GossipBlockRequest(
            block_id=block_id if block_num is None else "N{}.{}".format(block_num,block_id),
            nonce=binascii.b2a_hex(os.urandom(16)),
            time_to_live=time_to_live)
        self.broadcast(block_request,validator_pb2.Message.GOSSIP_BLOCK_REQUEST)

    def send_block_request(self, block_id, connection_id):
        self._is_send_block_request = True
        time_to_live = self.get_time_to_live()
        LOGGER.debug("gossip:send_block_request block_id=%s time_to_live=%s conn=%s",block_id,time_to_live,self._peers[connection_id])
        block_request = GossipBlockRequest(
            block_id=block_id,
            nonce=binascii.b2a_hex(os.urandom(16)),
            time_to_live=time_to_live)
        self.send(validator_pb2.Message.GOSSIP_BLOCK_REQUEST,
                  block_request.SerializeToString(),
                  connection_id,
                  one_way=True)

    def broadcast_batch(self, batch, exclude=None, time_to_live=None,candidate_id = None):
        if time_to_live is None:
            time_to_live = self.get_time_to_live()
        gossip_message = GossipMessage(
            content_type=GossipMessage.BATCH,
            content=batch.SerializeToString(),
            time_to_live=time_to_live,
            candidate_id=bytes.fromhex(candidate_id) if candidate_id is not None else None
            )
        LOGGER.debug("Gossip::broadcast_batch for candidate=%s",candidate_id[:8] if candidate_id is not None else None)

        self.broadcast(gossip_message, validator_pb2.Message.GOSSIP_MESSAGE, exclude)

    def broadcast_batches(self, batches, exclude=None, time_to_live=None):
        if time_to_live is None:
            time_to_live = self.get_time_to_live()
        gossip_message = GossipMessage(
            content_type=GossipMessage.BATCHES,
            content=batches.SerializeToString(),
            time_to_live=time_to_live,
            #candidate_id=bytes.fromhex(candidate_id) if candidate_id is not None else None,
            #block_num = block_num
            )
        LOGGER.debug("Gossip::broadcast_batches...")

        self.broadcast(gossip_message, validator_pb2.Message.GOSSIP_MESSAGE, exclude)


    def broadcast_batch_by_transaction_id_request(self, transaction_ids):
        time_to_live = self.get_time_to_live()
        batch_request = GossipBatchByTransactionIdRequest(
            ids=transaction_ids,
            nonce=binascii.b2a_hex(os.urandom(16)),
            time_to_live=time_to_live)
        self.broadcast(
            batch_request,
            validator_pb2.Message.GOSSIP_BATCH_BY_TRANSACTION_ID_REQUEST)

    def broadcast_batch_by_batch_id_request(self, batch_id):
        time_to_live = self.get_time_to_live()
        batch_request = GossipBatchByBatchIdRequest(
            id=batch_id,
            nonce=binascii.b2a_hex(os.urandom(16)),
            time_to_live=time_to_live)
        self.broadcast(
            batch_request,
            validator_pb2.Message.GOSSIP_BATCH_BY_BATCH_ID_REQUEST)

    def send_endpoint_message(self,endpoints,peer_id):
        """
        send list of endpoints for new leader
        """
        connection_id = self._network.public_key_to_connection_id(peer_id)
        time_to_live = self.get_time_to_live()
        endpoint_list = EndpointList()
        endpoint_list.endpoints.extend(endpoints)
        gossip_message = GossipMessage(
            content_type=GossipMessage.ENDPOINTS,
            content=endpoint_list.SerializeToString(),
            time_to_live=time_to_live
            )
        self.send(validator_pb2.Message.GOSSIP_MESSAGE,
                  gossip_message.SerializeToString(),
                  connection_id,
                  one_way=True)
        LOGGER.debug("Gossip::send_endpoint_message total=%s",len(endpoints))

    def endpoint_list(self,endpoints):
        """
        Info from old leader about endpoints
        """
        LOGGER.debug("Gossip::GET endpoint_list total=%s",len(endpoints.endpoints))
        for endpoint in endpoints.endpoints:
            pid = endpoint.peer_id.hex()
            if pid != self.validator_id and self._topology:
                LOGGER.debug("GossipBroadcastHandler: ADD ENDPOINT=%s->%s",pid,endpoint.endpoint)
                self._topology._attempt_to_peer_with_endpoint(endpoint.endpoint)

    def send_consensus_message(self, peer_id, message, public_key):
        """
        for instance ATRBITRATE message directly one peer
        FIXME - for speed reason make it like broadcast_consensus_message but send message only topology arbiters arbiter_consensus_message()
        """
        connection_id = self._network.public_key_to_connection_id(peer_id)
        if connection_id is None:
            LOGGER.debug('Gossip: send_consensus_message Disconnected peer=%d',peer_id[:8])
            return

        self.send(
            validator_pb2.Message.GOSSIP_CONSENSUS_MESSAGE,
            GossipConsensusMessage(
                message=message,
                sender_id=public_key,
                time_to_live=0).SerializeToString(),
            connection_id)

    def broadcast_consensus_message(self, message, public_key):
        """
        we should isolate other cluster from some message 
        """
        LOGGER.debug('Gossip: broadcast_consensus_message peers=%d',len(self._peers))
        self.broadcast(
            GossipConsensusMessage(
                message=message,
                time_to_live=self.get_time_to_live()),
            validator_pb2.Message.GOSSIP_CONSENSUS_MESSAGE)

    def broadcast_arbiter_consensus_message(self, message, public_key):
        # make exclude
        exclude = self.get_exclude(check_own_peer=False) #self._fbft.is_arbiter) if self._fbft.arbiters else None
        LOGGER.debug('Gossip: broadcast_arbiter_consensus_message exclude=%s',exclude)
        self.broadcast(
            GossipConsensusMessage(
                message=message,
                time_to_live=self.get_time_to_live()),
            validator_pb2.Message.GOSSIP_CONSENSUS_MESSAGE,
            exclude=exclude)

    def broadcast_cluster_consensus_message(self, message, public_key):
        # make exclude
        exclude = self.get_exclude(check_own_peer=True) #self._fbft.is_own_peer if self._fbft.cluster else None
        LOGGER.debug('Gossip: broadcast_cluster_consensus_message exclude=%s',exclude)
        self.broadcast(
            GossipConsensusMessage(
                message=message,
                time_to_live=self.get_time_to_live()),
            validator_pb2.Message.GOSSIP_CONSENSUS_MESSAGE,
            exclude=exclude)

    def send(self, message_type, message, connection_id, one_way=False):
        """Sends a message via the network.

        Args:
            message_type (str): The type of the message.
            message (bytes): The message to be sent.
            connection_id (str): The connection to send it to.
        """
        try:
            self._network.send(message_type, message, connection_id,one_way=one_way)
        except ValueError:
            LOGGER.debug("Connection %s is no longer valid. Removing from list of peers.",connection_id)
            if connection_id in self._peers:
                del self._peers[connection_id]

    def broadcast(self, gossip_message, message_type, exclude=None):
        """Broadcast gossip messages.

        Broadcast the message to all peers unless they are in the excluded
        list.

        Args:
            gossip_message: The message to be broadcast.
            message_type: Type of the message.
            exclude: A list of connection_ids that should be excluded from this
                broadcast.
        """
        LOGGER.debug("broadcast...")
        with self._lock:
            LOGGER.debug("broadcast start peers=%d",len(self._peers))
            if exclude is None:
                exclude = []
            for connection_id in self._peers.copy():
                if connection_id not in exclude:
                    #LOGGER.info("gossip:broadcast: send %s to %s",get_enum_name(message_type),self._peers[connection_id])
                    self.send(
                        message_type,
                        gossip_message.SerializeToString(),
                        connection_id,
                        one_way=True)

    def connect_success(self, connection_id):
        """
        Notify topology that a connection has been properly authorized

        Args:
            connection_id: The connection id for the authorized connection.

        """
        if self._topology:
            self._topology.connect_success(connection_id)
        else:
            LOGGER.debug("connect_success TOPOLOGY UNDEF\n")

    def remove_temp_endpoint(self, endpoint):
        """
        Remove temporary endpoints that never finished authorization.

        Args:
            endpoint: The endpoint that is not authorized to connect to the
                network.
        """
        if self._topology:
            LOGGER.debug("Remove_temp_endpoint=%s\n",endpoint)
            self._topology.remove_temp_endpoint(endpoint)

    def start(self):
        # load topology
        self.load_topology()
        self._topology = ConnectionManager(
            gossip=self,
            network=self._network,
            endpoint=self.endpoint,
            initial_peer_endpoints=self._initial_peer_endpoints,
            initial_seed_endpoints=self._initial_seed_endpoints,
            peering_mode=self._peering_mode,
            min_peers=self._minimum_peer_connectivity,
            max_peers=self._maximum_peer_connectivity,
            check_frequency=self._topology_check_frequency
            # take from topology federations_timeout
            )

        self._topology.start()

    def stop(self):
        for peer in self.get_peers():
            request = PeerUnregisterRequest()
            try:
                self._network.send(validator_pb2.Message.GOSSIP_UNREGISTER,
                                   request.SerializeToString(),
                                   peer)
            except ValueError:
                pass
        if self._topology:
            self._topology.stop()
        LOGGER.debug("Stop gossip!!!\n")

class ConnectionManager(InstrumentedThread):
    def __init__(self, gossip, network, endpoint,
                 initial_peer_endpoints, initial_seed_endpoints,
                 peering_mode, min_peers=3, max_peers=10,
                 check_frequency=1,federations_timeout=10):
        """Constructor for the ConnectionManager class.

        Args:
            gossip (gossip.Gossip): The gossip overlay network.
            network (network.Interconnect): The underlying network.
            endpoint (str): A zmq-style endpoint uri representing
                this validator's publically reachable endpoint.
            initial_peer_endpoints ([str]): A list of static peers
                to attempt to connect and peer with.
            initial_seed_endpoints ([str]): A list of endpoints to
                connect to and get candidate peer lists to attempt
                to reach min_peers threshold.
            peering_mode (str): Either 'static' or 'dynamic'. 'static'
                only connects to peers in initial_peer_endpoints.
                'dynamic' connects to peers in initial_peer_endpoints
                and gets candidate peer lists from initial_seed_endpoints.
            min_peers (int): The minimum number of peers required to stop
                attempting candidate connections.
            max_peers (int): The maximum number of active peer connections
                to allow.
            check_frequency (int): How often to attempt dynamic connectivity.
        """
        super().__init__(name="ConnectionManager")
        self._lock = Lock()
        self._stopped = False
        self._gossip = gossip
        self._network = network
        self._endpoint = endpoint
        self._initial_peer_endpoints = initial_peer_endpoints
        self._initial_seed_endpoints = initial_seed_endpoints
        self._redirect_seed_endpoints = []  # seed which is leared of our cluster
        self._peering_mode = peering_mode
        self._min_peers = min_peers
        self._max_peers = max_peers
        self._check_frequency = check_frequency

        self._candidate_peer_endpoints = []
        self._candidate_net = {}
        # Seconds to wait for messages to arrive
        self._response_duration = 2
        self._connection_statuses = {}
        self._temp_endpoints = {}
        self._static_peer_status = {}
        # federation
        self._federations_timeout = federations_timeout
        self._check_time = 0
        self._peer_timeout = 0
        self._dstatus = None
        self._err_msg = None

    @property
    def is_federations_assembled(self):
        return self._gossip.is_federations_assembled
    @property
    def networks_info(self):
        return [endp+"<-"+net for endp,net in self._candidate_net.items()]

    def add_visible_peer(self,endpoint,network):
        """
        appeared new peer which is visible
        """
        with self._lock:
            self._initial_peer_endpoints.append(endpoint)
            self._static_peer_status[endpoint] = StaticPeerInfo(
                    time=0,
                    retry_threshold=INITIAL_RETRY_FREQUENCY,
                    count=0)
            self._network.add_outbound_connection(endpoint,self._gossip.extpoint if network != self._gossip.network else None)
            self._temp_endpoints[endpoint] = EndpointInfo(
                        EndpointStatus.PEERING,
                        time.time(),
                        INITIAL_RETRY_FREQUENCY,
                        network)
            # keep network info
            self._candidate_net[endpoint] = network
        LOGGER.debug("ADD VISIBLE PEER=%s(%s)",endpoint,network)

    def start(self):
        # First, attempt to connect to explicit peers
        
        for endpoint in self._initial_peer_endpoints:
            self._static_peer_status[endpoint] = \
                StaticPeerInfo(
                    time=0,
                    retry_threshold=INITIAL_RETRY_FREQUENCY,
                    count=0)

        super().start()

    def run(self):
        while not self._stopped:
            try:
                if self._peering_mode == 'dynamic':
                    self.dynamic_peering()
                elif self._peering_mode == 'static':
                    self.retry_static_peering()
                elif self._peering_mode == 'sdynamic':
                    # sawtooth dynamic peering
                    self._refresh_peer_list(self._gossip.get_peers())
                    peers = self._gossip.get_peers()
                    peer_count = len(peers)
                    if peer_count < self._min_peers:
                        LOGGER.debug("Number of peers (%s) below minimum peer threshold (%s). Doing topology search.",
                            peer_count,
                            self._min_peers)

                        self._reset_candidate_peer_endpoints()
                        self._refresh_peer_list(peers)
                        # Cleans out any old connections that have disconnected
                        self._refresh_connection_list()
                        self._check_temp_endpoints()

                        peers = self._gossip.get_peers()

                        self._get_peers_of_peers(peers)
                        self._get_peers_of_endpoints(peers,self._initial_seed_endpoints)

                        # Wait for GOSSIP_GET_PEER_RESPONSE messages to arrive
                        time.sleep(self._response_duration)

                        peered_endpoints = list(peers.values())

                        with self._lock:
                            unpeered_candidates = list(
                                set(self._candidate_peer_endpoints) -
                                set(peered_endpoints) -
                                set([self._endpoint]))

                        LOGGER.debug("Peers are: %s. Unpeered candidates are: %s",peered_endpoints,unpeered_candidates)

                        if unpeered_candidates:
                            # connect with new peers in PEERING mode not TOPOLOGY
                            self._attempt_to_peer_with_endpoint(random.choice(unpeered_candidates))

                

                time.sleep(self._check_frequency)
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception("Unhandled exception during peer refresh")

    def stop(self):
        self._stopped = True
        for connection_id in self._connection_statuses:
            try:
                if self._connection_statuses[connection_id] == \
                        PeerStatus.CLOSED:
                    continue

                msg = DisconnectMessage()
                self._network.send(
                    validator_pb2.Message.NETWORK_DISCONNECT,
                    msg.SerializeToString(),
                    connection_id)
                self._connection_statuses[connection_id] = PeerStatus.CLOSED
            except ValueError:
                # Connection has already been disconnected.
                pass

    def dynamic_peering(self):
        """
        Fbft dynamic peering  
        first step we connect to gateway and get position into topology or REDIRECT or DENIED or PENDING (for instance in case our cluster not ready yet)
        next step we connect to own cluster leader and get all peers which we should know
        in case if gateway is leader we after first step will get info about own cluster
        """   
        
        self._refresh_peer_list(self._gossip.get_peers())                                                              
        peers = self._gossip.get_peers()                                                                               
        peer_count = len(peers)                                                                                        
        if self._dstatus not in [GetPeersResponse.JOINED,GetPeersResponse.NOSPACE,GetPeersResponse.NOT_VALID_CERT] :                                                                               
            LOGGER.debug("Number of peers (%s) below minimum peer threshold (%s). Doing topology search status=%s.",peer_count,self._min_peers,self._dstatus)                                                                                       
            if self._dstatus not in [GetPeersResponse.OK,GetPeersResponse.PENDING,GetPeersResponse.WAITING,GetPeersResponse.REDIRECT]:                                                                                                           
                self._reset_candidate_peer_endpoints()                                                                     
            self._refresh_peer_list(peers)                                                                             
            # Cleans out any old connections that have disconnected  
                                                              
            self._refresh_connection_list()                                                                            
            self._check_temp_endpoints()                                                                               
                                                                                                                       
            peers = self._gossip.get_peers()                                                                           
                                                                                                                       
            self._get_peers_of_peers(peers)  
            if self._dstatus is None:
                self._get_peers_of_endpoints(peers,self._initial_seed_endpoints)                                           
                                                                                                                       
            # Wait for GOSSIP_GET_PEER_RESPONSE messages to arrive                                                     
            time.sleep(self._response_duration)                                                                        
                                                                                                                       
            peered_endpoints = list(peers.values())                                                                    
                                                                                                                       
            with self._lock: 
                status = self._dstatus                                                                                          
                unpeered_candidates = list(                                                                            
                    set(self._candidate_peer_endpoints) -                                                              
                    set(peered_endpoints) -                    # already known peers                                                        
                    set([self._endpoint]))                                                                             
                                                                                                                       
            LOGGER.debug("Status=%s Peers are: %s.candidates=%s Unpeered candidates are: %s",status,peered_endpoints,self._candidate_peer_endpoints,unpeered_candidates)            
                                                                                                                       
            #if unpeered_candidates: 
                # connect with new peers in PEERING mode not TOPOLOGY  
                # in case   we have position in topology  
            if status == GetPeersResponse.OK:
                LOGGER.debug("JOINED to cluster success unpeered=%s candidate=%s!!!\n",unpeered_candidates,self._candidate_peer_endpoints) 
                with self._lock:
                    self._dstatus = GetPeersResponse.JOINED
                if unpeered_candidates:
                    for candidate in unpeered_candidates:
                        net = self._candidate_net[candidate]
                        self._attempt_to_peer_with_endpoint(candidate,net) # random.choice(unpeered_candidates)) 
                

            elif status == GetPeersResponse.REDIRECT :
                # go to cluster which promise give me position into topology
                LOGGER.debug("REDIRECT to cluster %s for position into topology!\n",unpeered_candidates)
                if len(unpeered_candidates) > 0:
                    self._redirect_seed_endpoints.append(unpeered_candidates[0])
                if unpeered_candidates:
                    self._get_peers_of_endpoints(peers,unpeered_candidates)

            elif status == GetPeersResponse.PENDING:
                LOGGER.debug("Continue PENDING candidates=%s",self._candidate_peer_endpoints)
                if len(self._redirect_seed_endpoints) > 0:
                    # ping until get position into topology
                    self._get_peers_of_endpoints(peers,self._redirect_seed_endpoints)
                elif len(self._candidate_peer_endpoints) > 0:
                    self._get_peers_of_endpoints(peers,self._candidate_peer_endpoints)
            elif GetPeersResponse.WAITING:
                if len(self._candidate_peer_endpoints) > 0:
                    # waiting position
                    LOGGER.debug("Continue WAITING temps=%s",self._temp_endpoints)
                    self._get_peers_of_endpoints(peers,self._candidate_peer_endpoints)
        else:
            if self._dstatus not in [GetPeersResponse.NOSPACE,GetPeersResponse.NOT_VALID_CERT]:  
                if not self.is_federations_assembled and not self._gossip._is_recovery_func():
                    LOGGER.debug("JOINED:ready ask head peers=%s redirect=%s.",self._gossip.peers_info,self._redirect_seed_endpoints)
                    self._gossip.dyn_switch_on_federations(self._redirect_seed_endpoints[0] if self._redirect_seed_endpoints != [] else None)
                else:
                    self._gossip.check_unsync_peer()
            else:
                if self._err_msg is None:
                    self._err_msg = "NO SPACE INTO NET" if self._dstatus == GetPeersResponse.NOSPACE else "NOT VALID CERT"
                    LOGGER.debug(f"CAN't JOIN WITH NETWORK - {self._err_msg}\n")
                    
            
                

    def retry_static_peering(self):
        """
        for federation topology try to wait peers connection before send CHAIN HEAD request
        we will wait own cluster peer's 
        """
        with self._lock:
            if not self.is_federations_assembled :
                if self._gossip.is_ready_for_assemble and (self._peer_timeout > self._federations_timeout or self._gossip.is_peers()):
                    # not checked and there is some registered peers and nests were made
                    if self._peer_timeout < self._federations_timeout :
                        self._peer_timeout = self._federations_timeout + 1 # don't check is_peers() 
                    else:
                        # no peers at all - make point of assemble
                        self.check_federations_status()
                            
                    if self._check_time > self._federations_timeout:
                        self.check_federations_status()
                    self._check_time += 1
                self._peer_timeout += 1
            else :
                self._gossip.check_unsync_peer()

            
                
            # Endpoints that have reached their retry count and should be
            # removed
            to_remove = []
            #LOGGER.debug("retry_static_peering: _initial_peer_endpoints %s", len(self._initial_peer_endpoints))
            for endpoint in self._initial_peer_endpoints:
                connection_id = None
                try:
                    connection_id = self._network.get_connection_id_by_endpoint(endpoint)
                except KeyError:
                    #LOGGER.debug("retry_static_peering:KeyError for %s",endpoint)
                    pass

                static_peer_info = self._static_peer_status[endpoint]
                if connection_id is not None:
                    if connection_id in self._connection_statuses:
                        # Endpoint is already a Peer
                        #if endpoint == 'tcp://validator-dgt-c2-7:8207':
                        #    LOGGER.debug("retry_static_peering:Endpoint %s is already a Peer",endpoint)
                        if self._connection_statuses[connection_id] == PeerStatus.PEER:
                            # reset static peering info
                            self._static_peer_status[endpoint] = \
                                StaticPeerInfo(
                                    time=0,
                                    retry_threshold=INITIAL_RETRY_FREQUENCY,
                                    count=0)
                            continue
                #if endpoint == 'tcp://validator-dgt-c2-7:8207':
                #    LOGGER.debug("retry_static_peering:KeyError for %s threshold=%s",str(time.time() - static_peer_info.time),static_peer_info.retry_threshold)
                if (time.time() - static_peer_info.time) > static_peer_info.retry_threshold:
                    #LOGGER.debug("Endpoint has not completed authorization in %s seconds: %s(%s)",static_peer_info.retry_threshold,endpoint,connection_id)
                    if connection_id is not None:
                        # If the connection exists remove it before retrying to
                        # authorize.
                        try:
                            #peer_key = self._network.connection_id_to_public_key(connection_id)
                            #if peer_key is not None:
                            #    self._gossip.remove_peer(peer_key)
                            self._network.remove_connection(connection_id)
                        except KeyError:
                            pass
                    else:
                        # it could be broken connection
                        self._gossip.remove_peer(endpoint)     

                    if static_peer_info.retry_threshold == MAXIMUM_STATIC_RETRY_FREQUENCY:
                        if static_peer_info.count >= MAXIMUM_STATIC_RETRIES:
                            # Unable to peer with endpoint
                            to_remove.append(endpoint)
                            continue
                        else:
                            # At maximum retry threashold, increment count
                            self._static_peer_status[endpoint] = \
                                StaticPeerInfo(
                                    time=time.time(),
                                    retry_threshold=min(
                                        static_peer_info.retry_threshold * 2,
                                        MAXIMUM_STATIC_RETRY_FREQUENCY),
                                    count=static_peer_info.count + 1)
                    else:
                        self._static_peer_status[endpoint] = \
                            StaticPeerInfo(
                                time=time.time(),
                                retry_threshold=min(
                                    static_peer_info.retry_threshold * 2,
                                    MAXIMUM_STATIC_RETRY_FREQUENCY),
                                count=0)

                    LOGGER.debug("retry_static_peering:attempting to peer with %s", endpoint)
                    self._network.add_outbound_connection(endpoint)
                    self._temp_endpoints[endpoint] = EndpointInfo(
                        EndpointStatus.PEERING,
                        time.time(),
                        INITIAL_RETRY_FREQUENCY,self._gossip.network)

            for endpoint in to_remove:
                # Endpoints that have reached their retry count and should be
                # removed
                self._initial_peer_endpoints.remove(endpoint)
                del self._static_peer_status[endpoint]

    def add_candidate_peer_endpoints(self, peer_endpoints,status=None):
        """
        Adds candidate endpoints to the list of endpoints to
        attempt to peer with.

        Args:
            peer_endpoints ([str]): A list of public uri's which the
                validator can attempt to peer with.
        """
        LOGGER.debug("add_candidate_peer_endpoints: status=%s->%s candidate=%s",self._dstatus,status,self._candidate_peer_endpoints)
        with self._lock:
            if status == GetPeersResponse.REDIRECT:
                # go to the redirect peer, which know all peers for us
                self._candidate_peer_endpoints = []
                #self._candidate_net = {}

            if  self._dstatus != GetPeersResponse.JOINED:
                # set current state of 
                self._dstatus = status
            for i in  range(len(peer_endpoints)):
                if i % 2 == 0:
                    endpoint = peer_endpoints[i]
                    if endpoint not in self._candidate_peer_endpoints:
                        self._candidate_peer_endpoints.append(endpoint)
                        self._candidate_net[endpoint] = peer_endpoints[i+1]
            """
            for endpoint in peer_endpoints:
                if endpoint not in self._candidate_peer_endpoints:
                    self._candidate_peer_endpoints.append(endpoint)
            """
        LOGGER.debug("add_candidate_peer_endpoints: candidate=%s",self._candidate_peer_endpoints)

    def set_connection_status(self, connection_id, status):
        self._connection_statuses[connection_id] = status

    def remove_temp_endpoint(self, endpoint):
        with self._lock:
            if endpoint in self._temp_endpoints:
                del self._temp_endpoints[endpoint]

    def _check_temp_endpoints(self):
        with self._lock:
            for endpoint in self._temp_endpoints:
                endpoint_info = self._temp_endpoints[endpoint]
                if (time.time() - endpoint_info.time) > endpoint_info.retry_threshold:
                    LOGGER.debug("Check Endpoint has not completed authorization in %s seconds: %s",endpoint_info.retry_threshold,endpoint)
                    try:
                        # If the connection exists remove it before retrying to
                        # authorize. If the connection does not exist, a
                        # KeyError will be thrown.
                        conn_id = self._network.get_connection_id_by_endpoint(endpoint)
                        self._network.remove_connection(conn_id)

                    except KeyError:
                        pass

                    self._network.add_outbound_connection(endpoint)
                    self._temp_endpoints[endpoint] = EndpointInfo(
                        endpoint_info.status,
                        time.time(),
                        min(endpoint_info.retry_threshold * 2,MAXIMUM_RETRY_FREQUENCY),
                        endpoint_info.network
                        )

    

    def _refresh_peer_list(self, peers):
        for conn_id in peers:
            endpoint = peers[conn_id]
            try:
                self._network.get_connection_id_by_endpoint(endpoint)
            except KeyError:
                LOGGER.debug("removing peer %s because connection went away",endpoint)

                self._gossip.unregister_peer(conn_id)
                if conn_id in self._connection_statuses:
                    status = self._connection_statuses.get(conn_id)
                    del self._connection_statuses[conn_id]
                    LOGGER.debug("removing peer %s conn status=%s nets=%s",endpoint,status,self.networks_info)
                    if status == PeerStatus.TEMP:
                        # for dynamic peer add connection again
                        if endpoint in self._temp_endpoints or endpoint in self._candidate_net:
                            network = self._temp_endpoints[endpoint].network if endpoint in self._temp_endpoints else self._candidate_net[endpoint]
                            self.add_peering_outbound_conn(endpoint,network)
                        else:
                            LOGGER.debug("removing peer %s HAS NO NETWORK INFO nets=%s\n",endpoint,self.networks_info)

    def _refresh_connection_list(self):
        with self._lock:
            closed_connections = []
            for connection_id in self._connection_statuses:
                if not self._network.has_connection(connection_id):
                    closed_connections.append(connection_id)

            for connection_id in closed_connections:
                del self._connection_statuses[connection_id]

    def make_peers_request(self,cluster=None,KYC=None):
        """
        request for position into topology
        """
        if cluster is None:
            cluster = self._gossip.join_cluster
        if KYC is None:
            KYC = self._gossip.KYC

        LOGGER.debug(f"MAKE PEER REQUEST:cluster={cluster}, KYC={KYC} endpoint={self._gossip.endpoint}")
        peers_request = GetPeersRequest(peer_id=bytes.fromhex(self._gossip.validator_id),
                                            endpoint = self._gossip.endpoint , 
                                            cluster = cluster,
                                            KYC = KYC,
                                            network = self._gossip.network,
                                            batch = self._gossip._batch
                                            )
        return peers_request

    def _get_peers_of_peers(self, peers):
        """
        for dynamical topology -
        """
        LOGGER.debug("gossip:_GET_PEERS_OF_PEERS!!!")
        cluster,KYC = self._gossip.get_join_cluster()
        get_peers_request = self.make_peers_request(cluster=cluster,KYC=KYC)
        

        for conn_id in peers:
            try:
                self._network.send(
                    validator_pb2.Message.GOSSIP_GET_PEERS_REQUEST,
                    get_peers_request.SerializeToString(),
                    conn_id)
                LOGGER.debug("gossip:_get_peers_of_peers conn=%d ",conn_id[:8])
            except ValueError:
                LOGGER.debug("Peer disconnected: %s", conn_id)

    def _get_peers_of_endpoints(self, peers, endpoints):
        """
        for dynamical topology - use initial list of endpoints and send connection request to it
        in this case endpoints are list of gateway into federation net 
        """
        LOGGER.debug("gossip:_GET_PEERS_OF_ENDPOINTS!!!")
        cluster,KYC = self._gossip.get_join_cluster()
        get_peers_request = self.make_peers_request(cluster=cluster,KYC=KYC)


        LOGGER.debug("gossip:_get_peers_of_endpoints endpoints=%d ",len(endpoints))
        for endpoint in endpoints:
            conn_id = None
            try:
                conn_id = self._network.get_connection_id_by_endpoint(endpoint)

            except KeyError:
                # If the connection does not exist, send a connection request
                with self._lock:
                    if endpoint in self._temp_endpoints:
                        del self._temp_endpoints[endpoint]
                    LOGGER.debug("Send a TOPOLOGY connection request endpoint=%s\n",endpoint)
                    self._temp_endpoints[endpoint] = EndpointInfo(
                        EndpointStatus.TOPOLOGY,
                        time.time(),
                        INITIAL_RETRY_FREQUENCY, self._gossip.network if not self._gossip._single else (self._gossip.network+'E')) # in single mode change net name

                    self._network.add_outbound_connection(endpoint,self._gossip.endpoint)

            # If the connection does exist, request peers.
            if conn_id is not None:
                if conn_id in peers:
                    # connected and peered - we've already sent peer request
                    continue
                else:
                    # connected but not peered
                    if endpoint in self._temp_endpoints:
                        # Endpoint is not yet authorized, do not request peers
                        continue

                    try:
                        LOGGER.debug("gossip:Endpoint %s send  GOSSIP_GET_PEERS_REQUEST",endpoint)
                        self._network.send(
                            validator_pb2.Message.GOSSIP_GET_PEERS_REQUEST,
                            get_peers_request.SerializeToString(),
                            conn_id)
                    except ValueError:
                        LOGGER.debug("Connection disconnected: %s", conn_id)

    def add_peering_outbound_conn(self,endpoint,network):
        LOGGER.debug("ADD NEW outbound connection with %s(%s) single=%s\n", endpoint,network,self._gossip.is_single)            
        with self._lock:                                                                                            
            self._temp_endpoints[endpoint] = EndpointInfo(                                                          
                EndpointStatus.PEERING,                                                                             
                time.time(),                                                                                        
                INITIAL_RETRY_FREQUENCY,
                network)                                                                            
        # in this case we use SINGLE start peer's marker which say us that endpoint belonge to other network        
        self._network.add_outbound_connection(endpoint,self._gossip.extpoint if network != self._gossip.network else None)   


    def _attempt_to_peer_with_endpoint(self, endpoint,net='net0'):
        LOGGER.debug("Attempting to connect/peer with %s(%s) inet=%s exnet=%s", endpoint,net,self._gossip._endpoint,self._gossip.extpoint)

        # check if the connection exists, if it does - send,
        # otherwise create it
        # send for DASHBOARD own componet port 
        try:
            connection_id = self._network.get_connection_id_by_endpoint(endpoint)

            register_request = PeerRegisterRequest(endpoint=self._gossip._endpoint,mode=PeerRegisterRequest.REGISTER,pid=self._gossip.peer_id,extpoint=self._gossip.extpoint)

            self._network.send(
                validator_pb2.Message.GOSSIP_REGISTER,
                register_request.SerializeToString(),
                connection_id,
                callback=partial(
                    self._peer_callback,
                    endpoint=endpoint,
                    connection_id=connection_id))
        except KeyError:
            # if the connection uri wasn't found in the network's
            # connections, it raises a KeyError and we need to add
            # a new outbound connection
            LOGGER.debug("Attempting to connect/peer with %s(%s)", endpoint,net)
            self.add_peering_outbound_conn(endpoint,net)

    def _reset_candidate_peer_endpoints(self):
        LOGGER.debug("RESET CANDIDATES..")
        with self._lock:
            self._candidate_peer_endpoints = []
            #self._candidate_net = {}

 
    def check_federations_status(self):
        """
        check may be we can send HEAD block request
        """
        LOGGER.debug("CHECK federations_status !\n")
        self._gossip.switch_on_federations()

    def _peer_callback(self, request, result, connection_id, endpoint=None):
        """
        Reply on my own register request
        """
        LOGGER.debug("_peer_callback %s",endpoint)
        with self._lock:
            ack = NetworkAcknowledgement()
            ack.ParseFromString(result.content)

            if ack.status == ack.ERROR:
                LOGGER.debug("Peering request to %s was NOT successful",connection_id)
                self._remove_temporary_connection(connection_id)
            elif ack.status == ack.OK:
                
                if endpoint:
                    try:
                        """
                        in case (ack.sync == TRUE) peer already make point of assemble and we should make sync with them 
                        and inform them after synchronization
                        """
                        LOGGER.debug("Reply on my REGISTER request to %s(%s) was successful. Peer already ack.sync=%s SYNC=%s",connection_id[:8],endpoint,ack.sync,self._gossip.is_sync)
                        self._gossip.register_peer(connection_id,ack.pid, endpoint,sync=None) # ack.sync if self._gossip.is_sync else None) #None)
                        self._connection_statuses[connection_id] = PeerStatus.PEER
                        public_key = self._gossip.peer_to_public_key(connection_id) 
                        LOGGER.debug("Peering register_peer to conn=%s key=%s SYNC=%s", endpoint,public_key[:8] if public_key else public_key,self._gossip.is_sync)
                        """
                        for federation topology try to wait sometime until peers connected
                        and only after this timeout send HEAD block request
                        """
                        #if self._is_federations_assembled and not self._is_send_block_request and self._fbft.genesis_node == public_key and not self._is_recovery_func():
                        # after point of assemble we can have no connected peers - so if this is Genesis ask HEAD
                        #   self._gossip.send_block_request("HEAD", connection_id)
                        


                    except PeeringException as e:
                        # Remove unsuccessful peer
                        LOGGER.warning('Unable to successfully peer with connection_id: %s, due to %s',connection_id[:10], str(e))

                        self._remove_temporary_connection(connection_id)
                else:
                    LOGGER.debug("Cannot register peer with no endpoint for connection_id: %s",connection_id)
                    self._remove_temporary_connection(connection_id)

    def _remove_temporary_connection(self, connection_id):
        status = self._connection_statuses.get(connection_id)
        if status == PeerStatus.TEMP:
            LOGGER.debug("Closing connection to %s PeerStatus.TEMP", connection_id[:8])
            msg = DisconnectMessage()
            try:
                self._network.send(validator_pb2.Message.NETWORK_DISCONNECT,msg.SerializeToString(),connection_id)
            except ValueError:
                pass
            del self._connection_statuses[connection_id]
            self._network.remove_connection(connection_id)
        elif status == PeerStatus.PEER:
            LOGGER.debug("Connection close request for peer ignored: %s",connection_id[:8])
        elif status is None:
            LOGGER.debug("Connection close request for unknown connection ignored: %s",connection_id[:8])

    def connect_success(self, connection_id):
        """
        Check to see if the successful connection is meant to be peered with.
        If not, it should be used to get the peers from the endpoint.
        """
        endpoint = self._network.connection_id_to_endpoint(connection_id)
        endpoint_info = self._temp_endpoints.get(endpoint)

        LOGGER.debug("Endpoint has completed authorization: %s(%s) (id: %s)",endpoint,endpoint_info.network if endpoint_info else None,connection_id[:8])
        if endpoint_info is None:
            LOGGER.debug("Received unknown endpoint: %s", endpoint)

        elif endpoint_info.status == EndpointStatus.PEERING:
            self._connect_success_peering(connection_id, endpoint)

        elif endpoint_info.status == EndpointStatus.TOPOLOGY:
            self._connect_success_topology(connection_id)

        else:
            LOGGER.debug("Endpoint has unknown status: %s(%s)", endpoint,endpoint_info.status)

        with self._lock:
            if endpoint in self._temp_endpoints:
                del self._temp_endpoints[endpoint]

    def _connect_success_peering(self, connection_id, endpoint):
        """
        send my own REGISTER request
        """
        LOGGER.debug("Connection to %s succeeded endpoint=%s component=%s pid=%s", connection_id[:8],endpoint,self._gossip.component,self._gossip.peer_id)

        register_request = PeerRegisterRequest(
            endpoint=self._gossip._endpoint,mode=PeerRegisterRequest.REGISTER,pid=self._gossip.peer_id,component=self._gossip.component,extpoint=self._gossip.extpoint)
        self._connection_statuses[connection_id] = PeerStatus.TEMP
        try:
            """
            inform peer about component port
            """
            self._network.send(
                validator_pb2.Message.GOSSIP_REGISTER,
                register_request.SerializeToString(),
                connection_id,
                callback=partial(
                    self._peer_callback,
                    connection_id=connection_id,
                    endpoint=endpoint))
        except ValueError:
            LOGGER.debug("Connection disconnected: %s", connection_id)

    def _connect_success_topology(self, connection_id):
        """
        for dynamical topology - success request 
        """
        LOGGER.debug("Connection to %s succeeded for TOPOLOGY request",connection_id[:8])

        self._connection_statuses[connection_id] = PeerStatus.TEMP
        cluster,KYC = self._gossip.get_join_cluster()
        get_peers_request = self.make_peers_request(cluster=cluster,KYC=KYC)

        def callback(request, result):
            # request, result are ignored, but required by the callback
            self._remove_temporary_connection(connection_id)
            LOGGER.debug("Connection %s succeeded callback TOPOLOGY ",connection_id[:8])

        try:
            self._network.send(
                validator_pb2.Message.GOSSIP_GET_PEERS_REQUEST,
                get_peers_request.SerializeToString(),
                connection_id,
                callback=callback)
            LOGGER.debug("Send  to %s  TOPOLOGY request:GOSSIP_GET_PEERS_REQUEST",connection_id[:8])
        except ValueError:
            LOGGER.debug("Connection disconnected: %s", connection_id)
