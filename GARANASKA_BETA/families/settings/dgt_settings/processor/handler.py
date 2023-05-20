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
import hashlib
import base64
import json
from functools import lru_cache


from dgt_sdk.processor.handler import TransactionHandler
from dgt_sdk.messaging.future import FutureTimeoutError
from dgt_sdk.processor.exceptions import InvalidTransaction
from dgt_sdk.processor.exceptions import InternalError

from dgt_settings.protobuf.settings_pb2 import SettingsPayload
from dgt_settings.protobuf.settings_pb2 import SettingProposal
from dgt_settings.protobuf.settings_pb2 import SettingVote
from dgt_settings.protobuf.settings_pb2 import SettingCandidate
from dgt_settings.protobuf.settings_pb2 import SettingCandidates
from dgt_settings.protobuf.settings_pb2 import SettingTopology
from dgt_settings.protobuf.setting_pb2 import Setting
from dgt_validator.gossip.fbft_topology import PeerSync,PeerRole,PeerAtr,FbftTopology,DGT_NESTS_NAME,DGT_PING_COUNTER,DGT_TOPOLOGY_SET_NM,DGT_TOPOLOGY_MAP_NM,TOPO_MAP
from dgt_settings.processor.utils import SETTINGS_NAMESPACE,_make_settings_key

LOGGER = logging.getLogger(__name__)
# DGT_PING_COUNTER - could do not all peers
# allow to set DGT_NESTS_NAME without restriction - for doing nests
NO_RESTRICTIONS_PARAMS = [DGT_NESTS_NAME]
# The config namespace is special: it is not derived from a hash.

# Number of seconds to wait for state operations to succeed
STATE_TIMEOUT_SEC = 10
DGT_FAMILY_NAME = 'dgt_settings'

class SettingsTransactionHandler(TransactionHandler):
    def __init__(self):
        self._fbft = None
        LOGGER.debug('SettingsTransactionHandler INIT DONE')

    @property
    def family_name(self):
        return DGT_FAMILY_NAME

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [SETTINGS_NAMESPACE]

    def apply(self, transaction, context):

        txn_header = transaction.header
        public_key = txn_header.signer_public_key
        # check maybe this special params with access without restriction 
        settings_payload = SettingsPayload()
        settings_payload.ParseFromString(transaction.payload)
        setting_proposal = SettingProposal()
        setting_proposal.ParseFromString(settings_payload.data)

        auth_keys = self._get_auth_keys(context)
        LOGGER.debug("AUTH_KEYS=%s batcher_public_key=%s",auth_keys,txn_header.batcher_public_key)
        if auth_keys and public_key not in auth_keys and setting_proposal.setting not in NO_RESTRICTIONS_PARAMS:
            raise InvalidTransaction('{} is not authorized to change settings'.format(public_key))

        #settings_payload = SettingsPayload()
        #settings_payload.ParseFromString(transaction.payload)

        if settings_payload.action == SettingsPayload.PROPOSE:
            return self._apply_proposal(auth_keys, public_key, settings_payload.data, context)
        if settings_payload.action == SettingsPayload.TOPOLOGY:
            return self._apply_topology(auth_keys, public_key, settings_payload.data, context)

        if settings_payload.action == SettingsPayload.VOTE:
            return self._apply_vote(public_key, settings_payload.data,
                                    auth_keys, context)

        raise InvalidTransaction("'action' must be one of {PROPOSE, VOTE} in 'Ballot' mode")

    def _apply_proposal(self, auth_keys, public_key,setting_proposal_data, context):
        setting_proposal = SettingProposal()
        setting_proposal.ParseFromString(setting_proposal_data)

        proposal_id = hashlib.sha256(setting_proposal_data).hexdigest()

        approval_threshold = self._get_approval_threshold(context)

        _validate_setting(auth_keys,
                          setting_proposal.setting,
                          setting_proposal.value)

        if approval_threshold > 1:
            setting_candidates = _get_setting_candidates(context)

            existing_candidate = _first(
                setting_candidates.candidates,
                lambda candidate: candidate.proposal_id == proposal_id)

            if existing_candidate is not None:
                raise InvalidTransaction('Duplicate proposal for {}'.format(setting_proposal.setting))

            record = SettingCandidate.VoteRecord(
                public_key=public_key,
                vote=SettingVote.ACCEPT)
            setting_candidates.candidates.add(
                proposal_id=proposal_id,
                proposal=setting_proposal,
                votes=[record]
            )

            LOGGER.debug('Proposal made to set %s to %s',setting_proposal.setting,setting_proposal.value)
            self._save_setting_candidates(context, setting_candidates)
        else:
            LOGGER.debug('Proposal set %s to %s',setting_proposal.setting,setting_proposal.value)
            self._set_setting_value(context,[(setting_proposal.setting,setting_proposal.value)])


    def _apply_topology(self, auth_keys, public_key,setting_topology_data, context):
        """
        update topology : do update['oper']
        """
        setting_topology = SettingTopology()
        setting_topology.ParseFromString(setting_topology_data)
        #value = _get_setting_value(context, setting_topology.setting, '')
        values = self._get_settings_value(context,[(setting_topology.setting, '')]) #,(DGT_TOPOLOGY_MAP_NM, '')
        LOGGER.debug(f'Topology: settings={values}')
        try:
            topology = json.loads(values[0].replace("'",'"'))
            update = json.loads(setting_topology.value)
            #tmap = json.loads(values[1])
        except ValueError as e:
            raise InvalidTransaction("Can't apply topology operation ({})".format('Invalid json: '+ str(e)))


        extra = []
        values = []
        if 'oper' in update:
            oper = update['oper']
            extra.append(('oper',oper))
            LOGGER.debug(f'FbftTopology: init for OPER={oper}')
            fbft = FbftTopology()
            #fbft.load_topo_map(tmap)                   
            fbft.get_topology(topology,'','','static') 
            #fbft.get_topology(topology,'','','static')
            if oper == 'lead' or oper == 'arbiter' :
                # change current leader or arbiter 
                if ('cluster' in update and 'peer' in update) or 'pid' in update:
                    cname,npeer = update['cluster'],update['peer']
                    extra.append(('cluster',cname))
                    extra.append(('peer',npeer))
                    if oper == 'lead':
                        changed,_ = fbft.change_cluster_leader(cname,npeer)
                    else:
                        changed,_ = fbft.change_cluster_arbiter(cname,npeer)
                    if not changed:
                        raise InvalidTransaction("Can't set new {} into cluster='{}'".format(oper,cname))
                    
                else:
                    raise InvalidTransaction('Undefine cluster or peer for new leader operation')
            elif oper == 'del' or oper == 'add':
                # del/add peer or cluster
                if ('cluster' in update or 'pid' in update) and 'list' in update:
                    # del peer or cluster
                    cname, plist = update['cluster'], update['list']
                    if oper == 'del':
                        LOGGER.debug('TOPOLOGY DEL PEERS %s into %s',plist,cname)
                        changed,err = fbft.del_peers(cname,plist)
                    else: # add new peer into cluster
                        LOGGER.debug('TOPOLOGY ADD PEERS %s into %s',plist,cname)
                        changed,err = fbft.add_new_peers(cname,plist)
                        
                    if changed == -1:
                        raise InvalidTransaction("Can't do '{}' into cluster='{}' ({})".format(oper,cname,err))
                    

                    #values.append((DGT_TOPOLOGY_MAP_NM,fbft.nest_map2str))
                    extra.append(('cluster',cname))
                    extra.append(('list',plist))
                else:
                    raise InvalidTransaction("Undefined all params for operation '{}'".format(oper))
            elif oper == 'cluster':
                # Create new cluster 
                if (('cluster' in update and 'peer' in update) or 'pid' in update) and 'list' in update:
                    cname,npeer,clist = update['cluster'], update['peer'], update['list']
                    changed,err = fbft.add_new_cluster(cname,npeer,clist)
                    if not changed:
                        raise InvalidTransaction("Can't do '{}' operation for='{}.{}' ({})".format(oper,cname,npeer,err))
                    extra.append(('cluster',cname))
                    extra.append(('peer',npeer))
                    extra.append(('list',clist))
                else:
                    raise InvalidTransaction("Undefined params for 'cluster' operation")
            elif oper == 'cdel' :
                if (('cluster' in update and 'peer' in update) or 'pid' in update) :
                    cname,npeer = update['cluster'], update['peer']
                    changed,err = fbft.del_cluster(cname,npeer)
                    if not changed:
                        raise InvalidTransaction("Can't do '{}' operation for='{}.{}' ({})".format(oper,cname,npeer,err))
                    extra.append(('cluster',cname))
                    extra.append(('peer',npeer))
                else:
                    raise InvalidTransaction("Undefined params for 'cluster' operation")
            elif oper == 'map':
                # set mapping for peer into DGT NET 
                # nest ; pub key or certificate key
                if ('list' in update) :
                    nlist = update['list']
                    changed,err = fbft.set_nest_map(nlist)
                    if not changed:
                        raise InvalidTransaction(f"Cant do MAP set ({err})")
                    extra.append(('list',nlist))  
                    
                else:
                    raise InvalidTransaction(f"Undefined params for 'map' operation update={update}")
                """
                values.append((DGT_TOPOLOGY_MAP_NM,fbft.nest_map2str))
                self._set_setting_value(context,values,extra=extra)
                return
                """
            else:
                # add peer into cluster
                raise InvalidTransaction("Undefined operation '{}'".format(oper))

        else:
            raise InvalidTransaction('Undefined SET operation')
        try:
            
            nvalue = json.dumps(fbft.curr_topology)
            values.append((setting_topology.setting,nvalue))
        except Exception as ex:
            raise InvalidTransaction(f'Cant convert result {ex}')

        #LOGGER.debug('TOPOLOGY value=%s set %s to %s',nvalue,setting_topology.setting,update)
        _validate_setting(auth_keys,setting_topology.setting,setting_topology.value)

        LOGGER.debug('TOPOLOGY SET %s TO %s',setting_topology.setting,nvalue)
        self._set_setting_value(context,values,extra=extra) #setting_topology.value)

    def _apply_vote(self, public_key,
                    settings_vote_data, authorized_keys, context):
        settings_vote = SettingVote()
        settings_vote.ParseFromString(settings_vote_data)
        proposal_id = settings_vote.proposal_id

        setting_candidates = self._get_setting_candidates(context)
        candidate = _first(
            setting_candidates.candidates,
            lambda candidate: candidate.proposal_id == proposal_id)

        if candidate is None:
            raise InvalidTransaction(
                "Proposal {} does not exist.".format(proposal_id))

        candidate_index = _index_of(setting_candidates.candidates, candidate)

        approval_threshold = self._get_approval_threshold(context)

        vote_record = _first(candidate.votes,
                             lambda record: record.public_key == public_key)
        if vote_record is not None:
            raise InvalidTransaction('{} has already voted'.format(public_key))

        candidate.votes.add(
            public_key=public_key,
            vote=settings_vote.vote)

        accepted_count = 0
        rejected_count = 0
        for vote_record in candidate.votes:
            if vote_record.vote == SettingVote.ACCEPT:
                accepted_count += 1
            elif vote_record.vote == SettingVote.REJECT:
                rejected_count += 1

        if accepted_count >= approval_threshold:
            self._set_setting_value(context,[(candidate.proposal.setting,candidate.proposal.value)])
            del setting_candidates.candidates[candidate_index]

        elif rejected_count >= approval_threshold or (rejected_count + accepted_count) == len(authorized_keys):
            LOGGER.debug('Proposal for %s was rejected',candidate.proposal.setting)
            del setting_candidates.candidates[candidate_index]

        else:
            LOGGER.debug('Vote recorded for %s',candidate.proposal.setting)

        self._save_setting_candidates(context, setting_candidates)

    def load_topology(self,value):
        try:
            topology = json.loads(value)             
            self._fbft.get_topology(topology,'AA.aa1','','static') 
            LOGGER.debug('LOAD TOPOLOGY DONE ') 

        except Exception as ex:
            LOGGER.debug(f'Cant load topology ({ex})')

    def _set_setting_value(self,context, values,extra=[],data=None):  
        states = {}
        for val in values:
            key,value = val[0],val[1]
            address = _make_settings_key(key)                                                                                                                    
            setting = _get_setting_entry(context, address)                                                                                                       
                                                                                                                                                             
            old_value = None                                                                                                                                     
            old_entry_index = None                                                                                                                               
            for i, entry in enumerate(setting.entries):                                                                                                          
                LOGGER.debug('SET_SETTING_VALUE: [%s]=%s context=%s', i,entry.key,type(context))                                                                 
                if key == entry.key:                                                                                                                             
                    old_value = entry.value                                                                                                                      
                    old_entry_index = i                                                                                                                          
                                                                                                                                                             
                                                                                                                                                             
            inform = True                                                                                                                                        
            if old_entry_index is not None:                                                                                                                      
                curr_value = setting.entries[old_entry_index].value                                                                                              
                if key == DGT_PING_COUNTER:                                                                                                                      
                    # special setting ping for networks                                                                                                          
                    # LOGGER.debug(f'DGT_PING_COUNTER:: {curr_value} + {value} {type(curr_value)}')                                                               
                    value = str(int(value) + int(curr_value))                                                                                                    
                if curr_value == value:                                                                                                                          
                    inform = False                                                                                                                               
                    LOGGER.debug('NEW VALUE THE SAME')                                                                                                           
                setting.entries[old_entry_index].value = value                                                                                                   
            else:                                                                                                                                                
                setting.entries.add(key=key, value=value)                                                                                                        
            
            # add state
            states[address] = setting.SerializeToString()                                                                                                                                               

            
        number = len(states)
        try:                                                                                                                                                 
            addresses = list(context.set_state(states,timeout=STATE_TIMEOUT_SEC))                                            
                                                                                                                                                             
        except FutureTimeoutError:                                                                                                                           
            LOGGER.warning('Timeout occured on context.set_state([%s, <value>])', [addr for addr in states.keys()])                                                                   
            raise InternalError('Unable to set {}'.format([val[0] for val in values]))                                                                                              
                                                                                                                                                             
        if len(addresses) != number:                                                                                                                              
            LOGGER.warning('Failed to save value on address %s', [addr for addr in states.keys()])                                                                                    
            raise InternalError('Unable to save config value {}'.format([val[0] for val in values]))                                                                                
        
        # add events into context                                                                                                                            
        if inform:                                                                                                                                           
            context.add_event(                                                                                                                               
                event_type="settings/update",                                                                                                                
                attributes=[("updated", key)]+extra,                                                                                                         
                data=data                                                                                                                                    
            )                                                                                                                                                
                                                                                                                                                             
    def _save_setting_candidates(self,context, setting_candidates):                                
        self._set_setting_value(context,                                                           
                           [('sawtooth.settings.vote.proposals',base64.b64encode(setting_candidates.SerializeToString()))]           
                           )                                                                  
                                                                                              

    def _get_setting_candidates(self,context):                                                            
        value = self._get_setting_value(context, 'sawtooth.settings.vote.proposals')                      
        if not value:                                                                                
            return SettingCandidates(candidates={})                                                  
                                                                                                     
        setting_candidates = SettingCandidates()                                                     
        setting_candidates.ParseFromString(base64.b64decode(value))                                  
        return setting_candidates                                                                    

    def _get_setting_value(self,context, key, default_value=None):                
        address = _make_settings_key(key)                                    
        setting = _get_setting_entry(context, address)                       
        for entry in setting.entries:                                        
            if key == entry.key:                                             
                return entry.value                                           
                                                                             
        return default_value  
                                                       
    def _get_settings_value(self,context, item_list): 
        def get_setting(settings,key):
            for entry in settings.entries:                                                    
                if key == entry.key:                                                         
                    return entry.value
            return None

        address = []
        for item in item_list:
            address.append(_make_settings_key(item[0]))                                                
        settings = _get_settings_entry(context, address)  
        values = []  
        for item in item_list:
            val = get_setting(settings,item[0]) 
            values.append(val if val is not None else item[1])
                                                                                         
        return values                                                             
        
                                                                                 
    def _get_approval_threshold(self,context):                                
        return int(self._get_setting_value(context, 'sawtooth.settings.vote.approval_threshold', 1))    

    def _get_auth_keys(self,context):                                          
        value = self._get_setting_value(context, 'sawtooth.settings.vote.authorized_keys', '')        
        return _split_ignore_empties(value)                               






def _split_ignore_empties(value):
    return [v.strip() for v in value.split(',') if v]


def _validate_setting(auth_keys, setting, value):
    if not auth_keys and \
            setting != 'sawtooth.settings.vote.authorized_keys':
        raise InvalidTransaction(
            'Cannot set {} until authorized_keys is set.'.format(setting))

    if setting == 'sawtooth.settings.vote.authorized_keys':
        if not _split_ignore_empties(value):
            raise InvalidTransaction('authorized_keys must not be empty.')

    if setting == 'sawtooth.settings.vote.approval_threshold':
        threshold = None
        try:
            threshold = int(value)
        except ValueError:
            raise InvalidTransaction('approval_threshold must be an integer')

        if threshold > len(auth_keys):
            raise InvalidTransaction(
                'approval_threshold must be less than or equal to number of '
                'authorized_keys')

    if setting == 'sawtooth.settings.vote.proposals':
        raise InvalidTransaction(
            'Setting sawtooth.settings.vote.proposals is read-only')




def _get_setting_entry(context, address):
    setting = Setting()

    try:
        entries_list = context.get_state([address], timeout=STATE_TIMEOUT_SEC)
    except FutureTimeoutError:
        LOGGER.warning('Timeout occured on context.get_state([%s])', address)
        raise InternalError('Unable to get {}'.format(address))

    if entries_list:
        setting.ParseFromString(entries_list[0].data)

    return setting

def _get_settings_entry(context, address):                                                      
    settings = Setting()                                                                        
                                                                                               
    try:                                                                                       
        entries_list = context.get_state(address, timeout=STATE_TIMEOUT_SEC)                 
    except FutureTimeoutError:                                                                 
        LOGGER.warning(f'Timeout occured on context.get_state({address})' )                  
        raise InternalError('Unable to get {}'.format(address))                                
     
    for entry in entries_list:
        set = Setting()
        set.ParseFromString(entry.data)
        settings.entries.add(key=set.entries[0].key, value=set.entries[0].value) 
        
                                                                                                   
    return settings                                                                             



def _first(a_list, pred):
    return next((x for x in a_list if pred(x)), None)


def _index_of(iterable, obj):
    return next((i for i, x in enumerate(iterable) if x == obj), -1)




