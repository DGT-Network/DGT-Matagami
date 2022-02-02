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
import random
import os
import binascii
import json
from collections.abc import MutableMapping
from enum import Enum

LOGGER = logging.getLogger(__name__)

DGT_TOPOLOGY_SET_NM = 'dgt.consensus.pbft.nodes'
TOPOLOGY_SET_NM = DGT_TOPOLOGY_SET_NM
DGT_TOPOLOGY_MAP_NM = 'dgt.topology.map'
DGT_TOPOLOGY_NEST_NM = 'dgt.topology.nest'
DGT_NESTS_NAME  = 'dgt.dag.nests'
DGT_PING_COUNTER  = 'dgt.ping.counter'
TOPOLOGY_GENESIS_HEX = b'Genesis'.hex()
TOPO_GENESIS =  'Genesis'
TOPO_MAP = "map"
DGT_NET_NEST = '/project/peer/keys/dgt.net.nest'
DGT_SELF_CERT = '/project/peer/keys/certificate.pem'
class PeerSync():
    inactive = 'inactive'
    active   = 'active'
    nosync   = 'nosync'

class PeerRole():
    leader = 'leader'
    plink  = 'plink'

class PeerAtr():
    endpoint   = 'endpoint'
    extpoint   = 'extpoint'
    intpoint   = 'intpoint'
    network    = 'network'
    component  = 'component'
    node_state = 'node_state'
    cluster    = 'cluster'
    children   = 'children'
    name       = 'name'
    role       = 'role'
    delegate   = 'delegate'
    genesis    = 'genesis'
    ptype      = 'type'
    pid        = 'pid' 
    public     = 'public' 
    dynamic    = 'dynamic' 
    KYC        = 'KYC'
    maxpeer    = 'maxpeer'
    segment    = 'segment'


class PeerMaping(MutableMapping):
    """
    A dict like interface wrapper around the peers to guarantee,
    objects are correctly mapped  as they are stored and
    retrieved.
    """

    def __init__(self,nest2key=None,peers={},name='peer'):
        self._nnest2key = nest2key if nest2key else {} # current mapping
        self._peers = peers
        self._name = name
        self._su_iter = None

    def __setitem__(self, key, value):
        # key - nest ,value - key
        #LOGGER.debug(f'SET {self._name}[{key}]') 
        self._nnest2key[key] = value
        self._nnest2key[value] = key
        
 
    def __getitem__(self, key):
        #LOGGER.debug(f'GET {self._name}[{key}]')
        if key in self._nnest2key:
            return self._nnest2key[key]


    def __delitem__(self, key):
        if key in self._nnest2key:
            # drop both key and nest
            val = self._nnest2key[key]
            del self._nnest2key[key]
            del self._nnest2key[val]


    def __contains__(self, key):
        #LOGGER.debug(f'CONTAIN {self._name}[{key}]')
        return key in self._nnest2key

    def __iter__(self):
        self._su_iter = self._nnest2key.__iter__()
        return self

    def __next__(self):
        while True :
            val = next(self._su_iter)
            if len(val) < 8:
                # return only nests
                #LOGGER.debug(f'NEXT {val}') 
                return val

    def __len__(self):
        # Required by abstract base class, but implementing is non-trivial
        return len(self._nnest2key)

    def __str__(self):
        return str(self._nnest2key)

    def __repr__(self):
        return json.dumps(self._nnest2key)

    @property
    def nests(self):
        keys = {}                      
        for nest,val in self.items():  
            keys[nest] = val  
        return keys         

    def to_json(self):
        return json.dumps(self.nests)
    

class FbftTopology(object):
    """
    F-BFT topology 
    """
    def __init__(self,topology_nest_nm=None):
        self._validator_id = None
        self._topo_nest_nm = topology_nest_nm
        self._abstr_topo = self._topo_nest_nm is not None and False
        self._nnest2key = PeerMaping() # nest-> key
        self._own_role = PeerRole.plink
        self._is_arbiter = False
        self._nest_colour = None # own cluster name
        self._genesis_node = None # genesis key
        self._genesis = 'UNDEF'  # genesis cluster
        self._parent = None
        self._leader = None
        self._endpoint = None
        self._arbiters = {} #PeerMaping(self._nnest2key,name="ARBITERS") #{}    # my arbiters 
        self._leaders  = {} #PeerMaping(self._nnest2key,name="LEADERS") #{}    # leadres of other clusters
        self._publics  = []    # public clusters
        self._cluster = None   # own cluster
        self._is_dynamic_cluster = False
        self._topology  = {PeerAtr.children:{}}
        self._nosync = False
        
    @property
    def curr_topology(self):
        self._topology[TOPO_MAP] = self._nnest2key.nests
        return self._topology
    @property
    def nest_colour(self):
        return self._nest_colour
    @property
    def is_dynamic_cluster(self):
        return self._is_dynamic_cluster
    @property
    def own_role(self):
        return self._own_role
    @property
    def is_arbiter(self):
        return self._is_arbiter

    @property
    def is_leader(self):
        return self.own_role == PeerRole.leader

    @property
    def cluster(self):
        return self._cluster if self._cluster else {}

    def is_own_peer(self,key):         
        nest = self.nest2key(key)      
        return nest in self.cluster  
     
    def get_own_peer(self,key,cluster=None):            
        nest = self.nest2key(key)      
        return self.cluster[nest] if cluster is None else cluster[nest]    

    @property
    def own_child_info(self):
        return [peer[PeerAtr.name]+":"+pid[:8] for pid,peer in self.cluster.items()]
    @property
    def arbiters(self):
        return self._arbiters
    def peer_is_arbiter(self,key):  
        return key in self.arbiters 
      
    def get_arbiter(self,key):            
        return self.arbiters[key]     

    @property
    def leaders(self):
        return self._leaders
    @property
    def publics(self):
        return self._publics
    @property
    def genesis(self):
        return self._genesis

    @property
    def genesis_node(self):
        return self._genesis_node if self._genesis_node else ''

    @property
    def topology(self):
        return self._topology

    def cluster_peer_role_by_key(self,key):
        nest = self.nest2key(key)
        return self._cluster[nest][PeerAtr.role] if nest in self._cluster else 'UNDEF'

    def get_topology_iter_from(self,root):
        return self.get_topology_iter(root)
     
    def get_topology_iter(self, root=None,key_mode=True):
        def iter_topology(children):
            for nest,peer in children.items():
                #print("iter_topology key ",key)
                key = self.nest2key(nest) if key_mode else nest 
                yield key,peer
                if isinstance(peer,dict) and PeerAtr.cluster in peer :
                    cluster = peer[PeerAtr.cluster]
                    if PeerAtr.name in cluster and PeerAtr.children in cluster:
                        #LOGGER.debug("iter_topology >>> %s",cluster['name'])
                        yield from iter_topology(cluster[PeerAtr.children])
                        #LOGGER.debug("iter_topology <<< %s",cluster['name'])
                        
        #check children FIXME    
        return iter_topology(self._topology[PeerAtr.children] if root is None else root)


    def get_topology_iter1(self, root=None,key_mode=True):
        # search peer and its cluster
        def iter_topology(children,parent):
            for nest,peer in children.items():
                #print("iter_topology key ",key)
                key = self.nest2key(nest) if key_mode else nest
                yield key,(peer,parent)
                if isinstance(peer,dict) and PeerAtr.cluster in peer :
                    cluster = peer[PeerAtr.cluster]
                    if PeerAtr.name in cluster and PeerAtr.children in cluster:
                        #LOGGER.debug("iter_topology >>> %s",cluster['name'])
                        yield from iter_topology(cluster[PeerAtr.children],cluster)
                        #LOGGER.debug("iter_topology <<< %s",cluster['name'])

        #check children FIXME    
        return iter_topology(self._topology[PeerAtr.children],self._topology) # if root is None else root)

    def __iter__(self):
        return self.get_topology_iter()

    def get_cluster_iter(self, cname,cluster=None):
        def iter_cluster(children):
            for key,peer in children.items():
                print("iter_cluster key ",key)
                yield key,peer
        if cluster is None:
            cluster = self.get_cluster_by_name(cname)
        return iter_cluster(cluster[PeerAtr.children]) if cluster else []

    def get_cluster_leader(self,cluster):
        for nest,peer in cluster[PeerAtr.children].items():
            if peer[PeerAtr.role] == PeerRole.leader :
                return peer,self.nest2key(nest)
        return None,None

    def is_cluster_leader(self,pkey):
        if pkey not in self.cluster:
            return False
        peer = self.cluster[pkey]
        return peer[PeerAtr.role] == PeerRole.leader

    def change_cluster_leader(self,cname,npeer):
        """
        for Validator
        """
        n = 0
        nkey = None
        cluster = self.get_cluster_by_name(cname)
        for nest,peer in self.get_cluster_iter(cname,cluster): 
            key = self.nest2key(nest)
            if n == 2:
                return True,nkey
            if peer[PeerAtr.name] == npeer:                                     
                LOGGER.debug('TOPOLOGY set NEW LEADER %s.%s=%s',cname,npeer,peer)      
                peer[PeerAtr.role] = PeerRole.leader
                if key == self._validator_id:
                    # I am new leader - I should communicate with arbiters 
                    self._own_role = PeerRole.leader
                    LOGGER.debug('I AM NEW LEADER arbiters=%s',len(self._arbiters))
                else:
                    # new leader into other cluster
                    self._leaders[key] = (PeerRole.leader,cname,cluster[PeerAtr.children])
                nkey = key
                n += 1
                """
                if self.own_role == PeerRole.leader:
                    # others cluster leader was changed - update arbiters
                    self._arbiters[key] = (PeerAtr.delegate,cname,cluster[PeerAtr.children])
                    LOGGER.debug('TOPOLOGY ADD ARBITER for=%s',cname)
                    # new leader already connected - inform consensus
                """
            elif peer[PeerAtr.role] == PeerRole.leader :                                 
                LOGGER.debug('TOPOLOGY old LEADER=%s to plink',peer)                              
                peer[PeerAtr.role] = PeerRole.plink
                if key in self._leaders:
                    del self._leaders[key] 
                n += 1 
        return False,nkey
                                                     
    def change_current_leader(self,npid,cname):
        """
        for Engine - new leader key(npid) into cluster(cname)  
        """
        i_am_new_leader = False
        if npid not in self._cluster:
            # other cluster
            cluster = self.get_cluster_by_name(cname)
            if cluster is None or PeerAtr.children not in cluster:
                return False,i_am_new_leader
            cluster = cluster[PeerAtr.children]
        else:
            cluster = self._cluster

        for key,peer in cluster.items():
            if peer[PeerAtr.role] == PeerRole.leader :
                LOGGER.debug('TOPOLOGY old LEADER=%s to plink',peer)                              
                peer[PeerAtr.role] = PeerRole.plink
                if key == self._validator_id:
                    self._own_role = PeerRole.plink
                break
        peer = cluster[npid]
        peer[PeerAtr.role] = PeerRole.leader
        if npid == self._validator_id:
            self._own_role = PeerRole.leader
            i_am_new_leader = True
            LOGGER.debug('I AM NEW LEADER arbiters=%s',len(self._arbiters))
        """
        if self.own_role == PeerRole.leader and npid not in self._arbiters:
            # I am leader
            self._arbiters[npid] = (PeerAtr.delegate,cname,cluster)
            LOGGER.debug('TOPOLOGY ADD ARBITER for=%s',cname)
        """
        LOGGER.debug('TOPOLOGY set NEW LEADER %s',peer)
        return True,i_am_new_leader

    def _switch_off_arbiter(self,peer,key):
        LOGGER.debug('TOPOLOGY old ARBITER=%s',peer)     
        peer[PeerAtr.delegate] = False
        try:
            del self._arbiters[key]
        except KeyError:
            pass
        if key == self._validator_id:                    
            self._is_arbiter = False  

    def _switch_on_arbiter(self,cname,cluster,peer,key):
                                            
        peer[PeerAtr.delegate] = True                                                                         
        if key == self._validator_id:                                                                         
            # I am new arbiter - I should communicate with arbiters and leaders                               
            self._is_arbiter = True                                                                                     
            LOGGER.debug('I AM NEW ARBITER=%s',len(self._arbiters))                                           
        elif self.own_role == PeerRole.leader or (PeerAtr.delegate in peer and peer[PeerAtr.delegate]):  
            if key not in self._arbiters:
                self._arbiters[key] = (PeerAtr.delegate,cname,cluster)                          
            LOGGER.debug('TOPOLOGY ADD ARBITER for=%s total=%s',cname,len(self._arbiters))                                                 
                               
    def change_cluster_arbiter(self,cname,npeer):
        """
        New arbiter into cluster
        """
        n = 0
        nkey = None
        cluster = self.get_cluster_by_name(cname)
        for key,peer in self.get_cluster_iter(cname,cluster): 
            if n == 2:
                return True,nkey
            if peer[PeerAtr.name] == npeer:                                     
                LOGGER.debug('TOPOLOGY set NEW ARBITER %s.%s=%s',cname,npeer,peer)  
                self._switch_on_arbiter(cname,cluster[PeerAtr.children],peer,key)    
                nkey = key
                n += 1
                
            elif PeerAtr.delegate in peer and peer[PeerAtr.delegate] :
                """
                drop old arbiter from arbiter list
                """     
                self._switch_off_arbiter(peer,key)                            
                n += 1 
        return False,nkey

    def change_current_arbiter(self,npid,cname):                                       
        """                                                                           
        new arbiter key(npid) into cluster(cname)                                      
        """                                                                           
        if npid not in self._cluster:                                                 
            # other cluster                                                           
            cluster = self.get_cluster_by_name(cname)                                 
            if cluster is None or PeerAtr.children not in cluster:                    
                return False,False                                          
            cluster = cluster[PeerAtr.children]                                       
        else:                                                                         
            cluster = self._cluster                                                   
                                                                                      
        for key,peer in cluster.items():                                              
            if PeerAtr.delegate in peer and peer[PeerAtr.delegate]: 
                self._switch_off_arbiter(peer,key)
                break
        # set new arbiter                                                                      
        peer = cluster[npid]
        self._switch_on_arbiter(cname,cluster,peer,npid) 
        return True,(npid == self._validator_id)                                                   

    def del_peers(self,cname,pold):
        """
        Del peers from cluster cname
        """
        cluster = self.get_cluster_by_name(cname)
        if cluster is None:
            return False,"Undefined cluster {}".format(cname)

        try:
            peers = json.loads(pold.replace("'",'"'))
        except ValueError as e:
            return False,'Invalid json: '+ str(e)
        n = 0
        children = cluster[PeerAtr.children]
        for key,opeer in peers.items():
            if key in children:
                LOGGER.debug('DEL PEER=%s INTO %s',key[:8],cname)
                del children[key]
                n = n + 1
        if n == 0 :
            return False,"There are no peers for del into cluster {}".format(cname)
        return True,None

    def add_new_peers(self,cname,pnew):
        """
        Add new peer into cluster cname
        {'024642f5a5214ebc6f8a5e3a189f1bc4d2e877b486bb7362d23837afd19e6ac1e0':{'role':'plink','type':'peer','name':'16'}}
        """
        cluster = self.get_cluster_by_name(cname)
        ret = -1
        try:
            peers = json.loads(pnew.replace("'",'"'))
        except ValueError as e:
            return ret,'Invalid json: '+ str(e)

        if cluster is None:
            return ret,"Undefined cluster {}".format(cname)
        children = cluster[PeerAtr.children]
        segment = cluster[PeerAtr.segment]
        child_num = len(children)
        #LOGGER.debug('ADD NEW PEER=%s INTO %s',peers,cname)
        for key,npeer in peers.items():
            peer = self.peer_is_exist(key)
            if peer is None:
                if ((PeerAtr.delegate in npeer and npeer[PeerAtr.delegate]) or (PeerAtr.role in npeer and npeer[PeerAtr.role] == PeerRole.leader)) and len(children) > 0:
                    return False,"New peer with key={} can't be leader or arbiter".format(key[:8])
                else:
                    #  SHOULD BE children[nest]
                    nest = f"{segment}.{segment.lower()}{child_num+1}"
                    children[nest] = npeer
                    self._nnest2key[nest] = key
                    ret = 0
                    if cname == self.nest_colour :
                        ret += 4
                        if (self._cluster is None or self._cluster == {}):
                            self._cluster = children 
                            LOGGER.debug("SET OWN CLUSTER LIST %s",cname)

                    LOGGER.debug('ADD NEW PEER=%s:%s : %s INTO %s(%s) child=%s',nest,key[:8],npeer,cname,self.nest_colour,self.own_child_info)
                    
                    if PeerAtr.role in npeer and npeer[PeerAtr.role] == PeerRole.leader:
                        # add into leaders list
                        if self.nest_colour is not None and cname != self.nest_colour:
                            self._leaders[key] = (PeerRole.leader,cname,children)
                            ret += 2
                        if key == self._validator_id:
                            self._own_role = PeerRole.leader
                        
                    if PeerAtr.delegate in npeer and npeer[PeerAtr.delegate]:
                        if self.nest_colour is not None and cname != self.nest_colour:
                            self._arbiters[key] = (PeerAtr.delegate,cname,children)
                            ret += 1
                        if key == self._validator_id:
                            self._is_arbiter = True
                        
                    


            else:
                return ret,"Peer {} with key={} already exist".format(peer,key[:8])

        return ret,None

    def add_new_cluster(self,cname,pname,clist,ppeer=None):
        """
        add new cluster
        """
        if ppeer is None:
            ppeer,_ = self.get_peer_by_name(cname,pname)
        if ppeer is None:
            return False,"Peer {}.{} does not exist".format(cname,pname)
        if PeerAtr.cluster in ppeer:
            return False,"Peer {}.{} already cluster owner".format(cname,pname)

        try: # {'name': 'Dgt2', 'type': 'cluster'}
            ncluster = json.loads(clist.replace("'",'"'))
        except ValueError as e:
            return False,'Invalid json: '+ str(e)

        if PeerAtr.name in ncluster and PeerAtr.ptype in ncluster :
            cluster = self.get_cluster_by_name(ncluster[PeerAtr.name])
            if cluster is not None:
                return False,"Cluster {} already exist".format(cname)
            ncluster[PeerAtr.children] = {}
            ppeer[PeerAtr.cluster] = ncluster
            if PeerAtr.public in ncluster and ncluster[PeerAtr.public]:
                self._publics.append(ncluster)
        else:
            return False,"Undefined new cluster params"

        return True,None

    def del_cluster(self,cname,pname,ppeer=None):
        # del empty cluster
        if ppeer is None:
            ppeer,_ = self.get_peer_by_name(cname,pname)
        if ppeer is None:
            return False,"Peer {}.{} does not exist".format(cname,pname)
        if PeerAtr.cluster not in ppeer:
            return False,"Peer {}.{} is not cluster owner".format(cname,pname)
        cluster = ppeer[PeerAtr.cluster]
        if len(cluster[PeerAtr.children]) > 0:
            return False,"Cluster {} for {}.{} is not empty".format(cluster[PeerAtr.name],cname,pname)
        del ppeer[PeerAtr.cluster]
        return True,None

    def set_nest_map(self,nlist):
        LOGGER.debug(f'SET MAP : nests={nlist}')
        try:
            nest_list = json.loads(nlist)
        except Exception as ex:
            LOGGER.debug(f'SET MAP err={ex}')
            return False,ex
        changed = False
        for nest,key in nest_list.items():
            self._nnest2key[nest] = key
            self.arbiter_nest2key(nest,key)
            changed = True
        return changed,None

    @property
    def nest_map2str(self):
        return self._nnest2key.to_json()

    def peer_is_exist(self,peer_key):
        for key,peer in self.get_topology_iter():
            if (key == peer_key):
                return peer
        return None

    def key_to_peer(self,peer_key):
        # get peer and it cluster by key 
        for key,peer in self.get_topology_iter1():
            if (key == peer_key):
                return peer # this is (peer,parent)
        return None,None

    def get_position_in_public(self,max_feder_peer=7):
        
        for cluster in self.publics:
            pmax = (cluster[PeerAtr.maxpeer] if PeerAtr.maxpeer in cluster else max_feder_peer)
            LOGGER.debug('check : cluster=%s peers=%s~%s',cluster[PeerAtr.name],len(cluster[PeerAtr.children]),pmax)
            if len(cluster[PeerAtr.children]) < (cluster[PeerAtr.maxpeer] if PeerAtr.maxpeer in cluster else max_feder_peer):
                return cluster[PeerAtr.name],cluster
        return None,None

    def get_public_extent_point(self):
        # get point to add new public cluster
        for cluster in self.publics:
            if PeerAtr.children in cluster:
                for peer in cluster[PeerAtr.children].values():
                    if PeerAtr.cluster not in peer:
                        return cluster[PeerAtr.name],peer[PeerAtr.name]
        return None,None

    def peer_to_cluster_name(self,peer_key):
        if peer_key == TOPOLOGY_GENESIS_HEX:
            return TOPO_GENESIS
        peer = self.peer_is_exist(peer_key)
        if peer and (PeerAtr.cluster in peer) :
            cluster = peer[PeerAtr.cluster]
            return cluster[PeerAtr.name]
        return None



    def peer_is_leader(self,peer_key):
        peer = self.peer_is_exist(peer_key)
        if peer and (PeerAtr.role in peer) and peer[PeerAtr.role] == PeerRole.leader :
            return True
        LOGGER.debug('peer_is_leader: is not leader=%s',peer_key[:8])
        return False
    
    def update_peer_activity(self,peer_key,endpoint,mode,sync=False,force=False,pid=None,extpoint=None):
        
        for key,peer in self.get_topology_iter():
            if (peer_key is not None and key == peer_key) or (PeerAtr.endpoint in peer and peer[PeerAtr.endpoint] == endpoint)  :
                if endpoint is not None:
                    peer[PeerAtr.endpoint] = endpoint
                if pid is not None:
                    peer[PeerAtr.pid] = pid
                if extpoint is not None:
                    peer[PeerAtr.extpoint] = extpoint
                #if sync or (not sync and (peer[PeerAtr.node_state] != PeerSync.active or force)) :
                peer[PeerAtr.node_state] = (PeerSync.active if sync else PeerSync.nosync) if mode else PeerSync.inactive
                """
                if component is not None:
                    peer[PeerAtr.component] = component
                    LOGGER.debug("UPDATE peer_component=%s  peer=%s",component,peer)
                """
                if not sync and not self._nosync:
                    self._nosync = True
                    self._topology['sync'] = not self._nosync 
                LOGGER.debug("UPDATE peer_activity: nosync=%s peer=%s endpoint=%s",self._nosync,peer,endpoint)
                return key
        return None

    def get_peer(self,peer_key):
        if self._cluster is None:
            return None
        nest = self._nnest2key[peer_key]
        if nest in self._cluster:
            peer = self._cluster[nest]
            return peer
        else:
            for key,peer in self.get_topology_iter():
                if key == peer_key:
                    return peer
        return  None

    def get_scope_peer_attr(self,peer_key,attr=PeerAtr.name):  
        # get peer which is in scope of visibility for current peer                                                        
        if peer_key not in self._nnest2key:   
            LOGGER.debug(f"UNDEF PEER={peer_key[0:8]} map={self._nnest2key}")                                                      
            return 'Undef'  
        nest = self._nnest2key[peer_key]                                                                 
        if nest in self.cluster:                                                     
            peer = self.cluster[nest]                                               
        elif peer_key in self._arbiters :
            peer =  self._arbiters[peer_key][2][nest] 
        else:                                                                             
            return 'Undef'                                                       
        return  peer[attr] if attr in peer else 'Undef'                                                                     




    def get_peer_state(self,peer_key,peer=None):
        if peer is None:
            peer = self.get_peer(peer_key)
        if peer is not None and PeerAtr.node_state in peer:
            return peer[PeerAtr.node_state]
        return  PeerSync.inactive

    def get_peer_id(self,peer_key):
        peer = self.get_peer(peer_key)
        if peer is not None and PeerAtr.pid in peer:
            return peer[PeerAtr.pid]
        return  None

    def get_cluster_by_name(self,cname):
        if cname == TOPO_GENESIS:
            return self._topology #[PeerAtr.children]

        for nest,peer in self.get_topology_iter(): #self._topology): # [PeerAtr.children]
            if isinstance(peer,dict) and PeerAtr.cluster in peer :
                #print('PEE',key,type(peer),peer,type(self._topology))
                cluster = peer[PeerAtr.cluster]
                #print('CLA ',cluster[PeerAtr.name])
                if PeerAtr.name in cluster and PeerAtr.children in cluster and cluster[PeerAtr.name] == cname:
                    return cluster
        return None

    def get_cluster_owner(self,cname):
        if cname == TOPO_GENESIS:
            return TOPOLOGY_GENESIS_HEX

        for key,peer in self.get_topology_iter(): #self._topology): # [PeerAtr.children]
            if isinstance(peer,dict) and PeerAtr.cluster in peer :
                #print('PEE',key,type(peer),peer,type(self._topology))
                cluster = peer[PeerAtr.cluster]
                #print('CLA ',cluster[PeerAtr.name])
                if PeerAtr.name in cluster and PeerAtr.children in cluster and cluster[PeerAtr.name] == cname:
                    return key
        return None

    def nest2cluster(self,nest_nm):                                                                                    
                                                                                                                          
        for nest,peer_par in self.get_topology_iter1(key_mode=False): 
            if nest == nest_nm :  
                parent = peer_par[1]                                                      
                
                if PeerAtr.name in parent and PeerAtr.children in parent:            
                    return parent[PeerAtr.name],parent                                                                                            
        return None,None                                                                                                       

    def get_cluster_arbiter(self,cname):
        cluster = self.get_cluster_by_name(cname)

    
    def get_peer_by_name(self,cname,name):
        cluster = self.get_cluster_by_name(cname)
        if cluster is None:
            return None,None
        for key,peer in cluster[PeerAtr.children].items():
            if PeerAtr.name in peer and peer[PeerAtr.name] == name:
                return peer,key
        """
        for key,peer in self.get_topology_iter():
            if PeerAtr.cluster in peer:
                cluster = peer[PeerAtr.cluster]
                if PeerAtr.name in cluster and PeerAtr.children in cluster and cluster[PeerAtr.name] == cname:
                    for skey,speer in cluster[PeerAtr.children].items():
                        #print('SPEER',speer,speer[PeerAtr.name] == cname)
                        if PeerAtr.name in speer and speer[PeerAtr.ptype] == 'peer' and speer[PeerAtr.name] == name:
                            return speer
        """
        return None,None

    def update_peer_component(self,peer_key,component=None,pid=None,extpoint=None,intpoint=None,network="net0"):
        for key,peer in self.get_topology_iter():
            if (peer_key is not None and key == peer_key)  :
                if component is not None:
                    peer[PeerAtr.component] = component
                    LOGGER.debug("UPDATE peer_component=%s  peer=%s",component,peer)
                if pid is not None:
                    peer[PeerAtr.pid] = pid
                if extpoint is not None:
                    peer[PeerAtr.extpoint] = extpoint
                if intpoint is not None:
                    peer[PeerAtr.intpoint] = intpoint
                peer[PeerAtr.network] = network
                break

    def set_peers_control(self,plist):
        self._topology['Control'] = plist

    def arbiter_nest2key(self,nest,key):
        if nest in self._arbiters:                         
            # change nest on key                           
            info = self._arbiters[nest]                    
            self._arbiters[key] = info                     
            del self._arbiters[nest]                       
            LOGGER.debug(f"CHANGE ARBITER KEY={nest}")     

    def load_topo_map(self,topo_map):
        # should be loaded before get_topology
        try:
            if isinstance(topo_map,dict):
                map_dict = topo_map
            else:
                map_dict = json.loads(topo_map)
        except Exception as ex:
            LOGGER.debug(f"CANT LOAD TOPO MAP {topo_map} {ex}")
            return 
        for nest,key in map_dict.items():
            self._nnest2key[nest] = key
            self.arbiter_nest2key(nest,key)
            

        LOGGER.debug(f"NEW MAP={self.nest_map2str} ME={self._validator_id[0:8]}")

    def is_own_topo_nest(self,key):
        return key == self._validator_id #self._topo_nest_nm == nest if self._abstr_topo else nest == self._validator_id
    def nest2key(self,nest):
        return self._nnest2key[nest] if nest in self._nnest2key else nest

    @property
    def arbiters_info(self):
        return [(key[0:8],val[1]) for key,val in self._arbiters.items()]
    def get_topology(self,topology,validator_id,endpoint,peering_mode='static',network='net0',join_cluster=None,KYCKey='0ABD7E'):
        # get topology from string
        def prepare_topology(children):
            for key,peer in children.items():
                if PeerAtr.cluster in peer:                                                              
                    cluster = peer[PeerAtr.cluster]                                                      
                    if PeerAtr.children in cluster:                          
                        cluster[PeerAtr.children] = prepare_topology(cluster[PeerAtr.children]) 
                        
            return  PeerMaping(self._nnest2key,children,name="CHILDS")    


        def get_cluster_info(arbiter_id,parent_name,name,children):
            #LOGGER.debug(f'CLUSTER {name} TRY TO JOIN={join_cluster}')
            if join_cluster is not None and join_cluster == name:
                # dynamic  mode - join this cluster
                if arbiter_id is not None:
                    self._arbiters[arbiter_id] = ('arbiter',parent_name)
                self._nest_colour = name
                self._cluster    = children
                self._parent     = arbiter_id
                self._own_role   = PeerRole.plink
                self._is_arbiter = False
                LOGGER.debug('JOIN OWN NEST=%s',name)
                #return
            for nest,peer in children.items():
                #LOGGER.debug('[%s]:child=%s val=%s',name,key[:8],val)
                key = self.nest2key(nest)
                #LOGGER.debug(f'[{key[:8]}]:child={name} nest={nest}')
                if self.is_own_topo_nest(key):
                    # use instead _validator_id topology_nest_nm
                    if arbiter_id is not None:
                        self._arbiters[arbiter_id] = ('arbiter',parent_name)
                    self._nest_colour = name
                    self._cluster    = children
                    self._parent     = arbiter_id
                    if PeerAtr.role in peer:
                        self._own_role = peer[PeerAtr.role]
                    if PeerAtr.delegate in peer:
                        self._is_arbiter = peer[PeerAtr.delegate]
                    #  yourself 
                    peer[PeerAtr.endpoint] = endpoint
                    peer[PeerAtr.node_state] = PeerSync.active
                    peer[PeerAtr.network] = network
                    LOGGER.debug(f'Found own NEST={name} ARBITER={self._is_arbiter} ROLE={self._own_role} validator_id={nest}.{self._validator_id}')
                    return

                if PeerAtr.cluster in peer:
                    cluster = peer[PeerAtr.cluster]
                    if PeerAtr.name in cluster and PeerAtr.children in cluster:
                        get_cluster_info(key,name,cluster[PeerAtr.name],cluster[PeerAtr.children])
                        if self._nest_colour is not None:
                            self._is_dynamic_cluster = (PeerAtr.dynamic in cluster and cluster[PeerAtr.dynamic])
                            LOGGER.debug(f'STOP CYCLE NEST={self._nest_colour}')
                            return

        def get_arbiters(arbiter_id,name,children):
            # make ring of arbiter - add only arbiter from other cluster
            for nest,peer in children.items():
                # key is nest
                key = self.nest2key(nest)
                if self._nest_colour != name:
                    # check only other cluster and add delegate
                    if PeerAtr.delegate in peer and peer[PeerAtr.delegate]:
                        self._arbiters[key] = (PeerAtr.delegate,name,children)
                        #if arbiter_id == self._parent:
                        #    self._leader = key
                    if PeerAtr.role in peer and peer[PeerAtr.role] == PeerRole.leader:
                        # add into leaders list
                        self._leaders[key] = (PeerRole.leader,name,children)

                if self._genesis_node is None and PeerAtr.genesis in peer:
                    # this is genesis node of all network
                    self._genesis_node = key
                if PeerAtr.cluster in peer:
                    cluster = peer[PeerAtr.cluster]
                    if PeerAtr.name in cluster and PeerAtr.children in cluster:
                        if PeerAtr.public in cluster and cluster[PeerAtr.public]:
                            # add public cluster into list
                            self._publics.append(cluster)
                        get_arbiters(key,cluster[PeerAtr.name],cluster[PeerAtr.children])

        #topology = json.loads(stopology)
        
        
        #if join_cluster and self._nest_colour is None:
            # join_cluster - for dymanic mode
        #    self._nest_colour = join_cluster

        self._validator_id = validator_id
        self._endpoint = endpoint
        self._topology = topology if topology != {} else {PeerAtr.children:{},TOPO_MAP: {}}
        if TOPO_MAP in self._topology:     
            self.load_topo_map(self._topology[TOPO_MAP]) 

        #LOGGER.debug('get_topology=%s',self._topology)
        topology['topology'] = peering_mode
        topology['sync'] = not self._nosync
        if PeerAtr.name in topology and PeerAtr.children in topology:
            self._genesis  = topology['name'] # genesis cluster
            #topology[PeerAtr.children] = prepare_topology(topology[PeerAtr.children])
            get_cluster_info(None,None,topology[PeerAtr.name],topology[PeerAtr.children])
            LOGGER.debug(f'FIND CLUSTER {join_cluster} DONE')
            if join_cluster :
                jcluster = self.get_cluster_by_name(join_cluster)
                if jcluster is None:
                    self._is_dynamic_cluster = True
                else:
                    self._is_dynamic_cluster = (PeerAtr.dynamic in jcluster and jcluster[PeerAtr.dynamic])

        if self._nest_colour is None:
            pass
            #self._nest_colour = TOPO_GENESIS
        else:
            # get arbiters
            get_arbiters(None,topology[PeerAtr.name],topology[PeerAtr.children])
            LOGGER.debug(f'CLUSTER = {self.cluster}')
            for key,peer in self.cluster.items():
                if peer[PeerAtr.role] == PeerRole.leader:
                    self._leader = key
                    break
            # add Identity
            topology['Network'] = 'DGT TEST network'
            topology['Identity'] = {'PubKey'     : self._validator_id,
                                    'IP'         : self._endpoint,
                                    'Network'    : network,
                                    'Cluster'    : self._nest_colour,
                                    TOPO_GENESIS : self._genesis_node,
                                    'Leader'     : self._leader if self._leader else 'UNDEF',
                                    'Parent'     : self._parent if self._parent else 'UNDEF',
                                    'KYCKey'     : KYCKey

            }
            LOGGER.debug('Arbiters RING=%s\n GENESIS=%s PUBLICS=%s child=%s dyn=%s', self.arbiters_info, self.genesis_node[:8], len(self.publics),self.own_child_info,self.is_dynamic_cluster)





