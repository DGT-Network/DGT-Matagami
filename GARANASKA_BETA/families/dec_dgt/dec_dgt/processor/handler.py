# Copyright 2022 DGT NETWORK INC © Stanislav Parsov 
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
import traceback
from hashlib import sha512 as _sha512
from hashlib import sha256 as _sha256
import base64
import cbor
import json
import time
import math

from dgt_sdk.processor.handler import TransactionHandler
from dgt_sdk.processor.exceptions import InvalidTransaction
from dgt_sdk.processor.exceptions import InternalError
from dec_common.protobuf.dec_dgt_token_pb2 import DecTokenInfo
from dgt_signing import CryptoFactory,create_context,key_to_dgt_addr
from dec_dgt.client_cli.dec_attr import *
from dgt_settings.processor.utils import _make_settings_key,SETTINGS_NAMESPACE
from dgt_settings.protobuf.setting_pb2 import Setting
from dgt_validator.gossip.fbft_topology import DGT_TOPOLOGY_SET_NM,FbftTopology

LOGGER = logging.getLogger(__name__)


FULL_ADDR_TYPES = [DEC_TARGET_OP,DEC_ROLE_OP,DEC_WALLET_OP,DEC_EMISSION_OP,DEC_BURN_OP,DEC_INVOICE_OP,DEC_SEND_OP,DEC_PAY_OP,DEC_ALIAS_OP]
OP_ADDR_TYPES = {
DEC_TARGET_OP   : DEC_TARGET_GRP,
DEC_ROLE_OP     : DEC_ROLE_GRP,
DEC_WALLET_OP   : DEC_WALLET_GRP,
DEC_EMISSION_OP : DEC_EMISSION_GRP,
DEC_BURN_OP     : DEC_EMISSION_GRP,
DEC_INVOICE_OP  : DEC_TARGET_GRP,
DEC_SEND_OP     : DEC_WALLET_GRP,
DEC_PAY_OP      : DEC_WALLET_GRP,
}

DEC_ADDRESS_PREFIX = _sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]

def make_dec_prefix():
    return _sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]

def make_dec_address(name):
    return DEC_ADDRESS_PREFIX + _sha512(name.encode('utf-8')).hexdigest()[-64:]

def full_dec_address(name,gr,owner):                                                        
    tp_prefix = _sha256(gr.encode('utf-8')).hexdigest()[0:2]                                   
    usr_prefix = _sha256(owner.encode('utf-8')).hexdigest()[:22]                               
    dec_address = _sha256(name.encode('utf-8')).hexdigest()[:40]                               
    return ''.join([DEC_ADDRESS_PREFIX,tp_prefix,usr_prefix,dec_address])                      



def make_full_dec_address(name,op,val): 
    if op in FULL_ADDR_TYPES :
        tp = OP_ADDR_TYPES[op]
        if name == DEC_EMISSION_KEY:
            tp = DEC_EMISSION_GRP
    else:
        return make_dec_address(name)
    owner = val[DEC_PAYLOAD][DEC_DID_VAL] if DEC_PAYLOAD in val else val[DEC_DID_VAL]
    return full_dec_address(name,tp,owner)
 
def get_wallet(wval):
    # wallet of source            
    #curr = state[name]            
    token = DecTokenInfo()        
    token.ParseFromString(wval)   
    src = cbor.loads(token.dec)   
    return src,token

def get_dec(val):
    return get_wallet(val)

class DecTransactionHandler(TransactionHandler):
    def __init__(self):
        self._context = create_context('secp256k1') 
        LOGGER.debug('_do_set: context')
        self._private_key = self._context.new_random()
        LOGGER.debug('_do_set: context private_key=%s',self._private_key.as_hex())
        self._public_key = self._context.get_public_key(self._private_key)
        crypto_factory = CryptoFactory(self._context)
        self._signer = crypto_factory.new_signer(self._private_key)
        #self._signer = CryptoFactory(self._context).new_signer(self.private_key)
        LOGGER.debug('_do_set: public_key=%s  ',self._public_key.as_hex())
        LOGGER.info('DecTransactionHandler init DONE PREF=%s',DEC_ADDRESS_PREFIX)

    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return [FAMILY_VERSION]

    @property
    def namespaces(self):
        return [DEC_ADDRESS_PREFIX]

    def apply(self, transaction, context):
        LOGGER.debug('apply:....\n')
        #try:
        self._addr_map = {}
        verb, name, value, to, out = self._unpack_transaction(transaction)
        LOGGER.debug('APPLY: verb=%s name=%s value=%s to=%s',verb, name, value, to)
        state,to = self._get_state_data(name,to, context,verb,value)
        #LOGGER.debug('apply: state = {}'.format(state))
        updated_state = self._do_op_dec(verb, name[0], value, to, state, out)
        
        self._set_state_data( updated_state, context,verb,value)
        #except Exception as ex:
        #    raise InternalError('Apply: verb: {} - {}'.format(verb,ex))

    def _do_op_dec(self,verb, name, value, to, state, out):
        verbs = {
            DEC_EMISSION_OP    : self._do_emission,
            DEC_WALLET_OP      : self._do_wallet,
            DEC_WALLET_OPTS_OP : self._do_wallet_opts,
            DEC_BURN_OP        : self._do_burn,
            DEC_CHANGE_MINT_OP : self._do_change_mint,
            DEC_FAUCET_OP      : self._do_faucet,
            DEC_SEND_OP        : self._do_send,
            DEC_PAY_OP         : self._do_pay,
            DEC_INVOICE_OP     : self._do_invoice,
            DEC_TARGET_OP      : self._do_target,
            DEC_ALIAS_OP       : self._do_alias,
            DEC_ROLE_OP        : self._do_role,
            DEC_MINT_OP        : self._do_mint,
            DEC_HEART_BEAT_OP  : self._do_heartbeat,
            DEC_SET_OP         : self._do_set,
            DEC_INC_OP         : self._do_inc,
            DEC_DEC_OP         : self._do_dec,
            DEC_TRANS_OP       : self._do_trans,
        }
        LOGGER.debug('_do_dec request [%s]....',verb)
        try:
            return verbs[verb](name, value,to, state, out)
        except KeyError:
            # This would be a programming error.
            tb = traceback.format_exc()
            raise InvalidTransaction('Unhandled verb: {} TB={}'.format(verb,tb))
        except InvalidTransaction as ex:   
            raise InvalidTransaction(ex) 

        except Exception as ex:
            tb = traceback.format_exc()                                      
            raise InvalidTransaction('Verb: {} err={} TB={}'.format(verb,ex,tb)) 
        
        
         
    # Emission parts 
    def _do_emission(self,name, val, to, state, out ):                                                                                           
        LOGGER.debug('emission "{}"'.format(name))                                                                                                               
                                                                                                                                        
                                                                                                                                        
        if name in state:                                                                                                               
            raise InvalidTransaction('Verb is "{o}", but emission {n} already was made.'.format(o=DEC_EMISSION_OP,n=name))
        # emitter pubkey
        emitter = val[DEC_EMITTER]            
        if DGT_TOPOLOGY_SET_NM in state:
            tval = json.loads(state[DGT_TOPOLOGY_SET_NM])
            #LOGGER.debug('Topology "{}"'.format(tval))
            fbft = FbftTopology()
            fbft.get_topology(tval,'','','static')
            # 
            is_peer = fbft.peer_is_leader(emitter)
            pname = fbft.get_scope_peer_attr(emitter)
            peer = fbft.get_peer(emitter)
            LOGGER.debug('Topology is peer={} leader "{}"'.format(peer,is_peer))
            if not is_peer:
                raise InvalidTransaction('Verb is "{}", but emitter is not Leader'.format(DEC_EMISSION_OP))


            # check key into topology
        updated = {k: v for k, v in state.items() if k in out}                                                                                      
        #owner_key = self._context.sign('DEC_token'.encode(),self._private_key) 
        payload = val[DEC_PAYLOAD]
        tcurr = payload[DEC_TMSTAMP]
        # emission params
        value = payload[DEC_EMISSION_OP]
        mint_share = value[DEC_MINTING_SHARE][DATTR_VAL] 
        corp_share = value[DEC_СORPORATE_SHARE][DATTR_VAL]
        sale_share = 100.0 - (mint_share + corp_share)
        dec_total = value[DEC_TOTAL_SUM][DATTR_VAL]
        value[DEC_TMSTAMP] =  tcurr 
        value[DEC_MINTING_TOTAL   ] = dec_total/100 * mint_share
        value[DEC_MINTING_REST    ] = value[DEC_MINTING_TOTAL]
        value[DEC_СORPORATE_TOTAL ] = dec_total/100 * corp_share
        value[DEC_СORPORATE_REST  ] = value[DEC_СORPORATE_TOTAL]
        value[DEC_SALE_TOTAL      ] = dec_total/100 *  sale_share
        value[DEC_SALE_REST       ] = value[DEC_SALE_TOTAL]
        value[DEC_SALE_SHARE]  = {DATTR_VAL : sale_share} 

        if DEC_WAIT_TO_DATE not in value:
            value[DEC_WAIT_TO_DATE] = {DATTR_VAL : tcurr + DEC_WAIT_TO_DATE_DEF}
        if DEC_MINT_PARAM not in value :
            value[DEC_MINT_PARAM] = {DATTR_VAL : {DEC_MINT_PERIOD : DEC_MINT_PERIOD_DEF}}
        else:
            mint = value[DEC_MINT_PARAM][DATTR_VAL]
            if DEC_MINT_PERIOD not in mint:
                mint[DEC_MINT_PERIOD] = DEC_MINT_PERIOD_DEF
            
        token_name = value[DEC_NAME][DATTR_VAL]                                               
        token = DecTokenInfo(group_code = token_name,                                                                                  
                             owner_key = self._signer.sign(token_name.encode()),
                             sign = emitter,#self._public_key.as_hex(), 
                             decimals=0,                                                                         
                             dec = cbor.dumps(value)                                                                                      
                )                                                                                                                       
        updated[name] = token.SerializeToString()                                                                                       
        #LOGGER.debug('_do_emission updated=%s',updated)                                                                                      
        return updated  
                                                                                                                    
    def _new_wallet(self,total,tcurr,opts=DEF_WALLET_OPTS,did=DEFAULT_DID,group = DEC_WALLET):
        token = DecTokenInfo(group_code = group,                                                          
                             owner_key = self._signer.sign(DEC_WALLET.encode()), #owner_key,                   
                             sign = self._public_key.as_hex(),                                                 
                             decimals = total,                                                                     
                             dec=cbor.dumps({DEC_TMSTAMP: tcurr,                                               
                                             DEC_TOTAL_SUM : total,                                                
                                             DEC_DID_VAL   : did,                                          
                                             DEC_WALLET_OPTS_OP : opts                                         
                                             }                                                                 
                            )                                                                                  
                )
        return token                                                                                              

    def _do_alias(self,name, value, to, state, out):                         
        LOGGER.debug('Alias "{}" value={}'.format(name,value))               
        #value = {DEC_EMITTER,DEC_PAYLOAD}                                    
        if name in state:                                                                                                 
            raise InvalidTransaction('Verb is "{}", but Alias with name={} already exists.'.format(DEC_ALIAS_OP,name))  

        payload = value[DEC_PAYLOAD]                                                            
        opts = payload[DEC_ALIAS_OP]                                                           
        tcurr = payload[DEC_TMSTAMP]                                                            
        did_val = payload[DEC_DID_VAL] if DEC_DID_VAL in payload else DEFAULT_DID               
        if key_to_dgt_addr(value[DEC_EMITTER]) == opts[DEC_WALLET_ADDR]:                                                          
            LOGGER.debug('owner WALLET alias and signer the same')                                    

        updated = {k: v for k, v in state.items() if k in out}                          
        
        token = self._new_wallet(0,tcurr,opts,did=did_val,group=DEC_WALLET_ALIAS)                              
        updated[name] = token.SerializeToString()                                       
        
        return updated                                                                  

    def _do_wallet(self,name, value, to, state, out):                                                                                     
        LOGGER.debug('Wallet "{}" value={}'.format(name,value))                                                                                                              
        #value = {DEC_EMITTER,DEC_PAYLOAD}
        

        if name in state:                                                                                                              
            raise InvalidTransaction('Verb is "{}", but Wallet with name={} already exists.'.format(DEC_WALLET_OP,name)) 
        #if DEC_EMISSION_KEY not in state:                                                              
        #    raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_WALLET_OP)) 
        if False:
            if DEC_DID_VAL not in value:
                # use default did
                did_val = {DATTR_VAL : DEFAULT_DID,NOTARY_PUBKEY : ""}
            else:
                did_pay = value[DEC_DID_VAL][DEC_DID_VAL]
                did_val = cbor.loads(did_pay)
                psign = value[DEC_DID_VAL][DEC_SIGNATURE]
                # check notary sign
                is_correct = self._check_sign(did_val[NOTARY_PUBKEY],psign,did_pay)                                     
                if not is_correct:                                                                                        
                    raise InvalidTransaction('Verb is "{}", but signature of DID is wrong.'.format(DEC_WALLET_OP))  



        if False:
            # wallet options
            opts_pay = value[DEC_WALLET_OPTS_OP][DEC_WALLET_OPTS_OP]    
            opts = cbor.loads(opts_pay)                             
            psign = value[DEC_WALLET_OPTS_OP][DEC_SIGNATURE]            
            is_correct = self._check_sign(opts[NOTARY_PUBKEY],psign,opts_pay)                                
            if not is_correct:                                                                                 
                raise InvalidTransaction('Verb is "{}", but signature of OPTS is wrong.'.format(DEC_WALLET_OP)) 


            tcurr = value[DEC_TMSTAMP] 
        else:
            # 
            payload = value[DEC_PAYLOAD]
            opts = payload[DEC_WALLET_OP]
            tcurr = payload[DEC_TMSTAMP]
            did_val = payload[DEC_DID_VAL] if DEC_DID_VAL in payload else DEFAULT_DID
            if value[DEC_EMITTER] == name:
                LOGGER.debug('owner WALLET and signer the same')

        updated = {k: v for k, v in state.items() if k in out}                                                                         
        #owner_key = self._context.sign('DEC_token'.encode(),self._private_key) 
        token = self._new_wallet(0,tcurr,opts,did=did_val)                                                       
        updated[name] = token.SerializeToString()                                                                                      
        #LOGGER.debug('_do_set updated=%s',updated)                                                                                    
        return updated                                                                                                                 
  
    def _do_wallet_opts(self,name, value, to, state, out):                                                                                        
        LOGGER.debug('Set wallet opts "{}" to {}'.format(name,value))                                                                                 
                                                                                                                                             
                                                                                                                                             
        if name not in state:                                                                                                                    
            raise InvalidTransaction('Verb is "{}", but wallet not exists: Name: {}'.format(DEC_WALLET_OPTS_OP,name))          
        #if DEC_EMISSION_KEY not in state:                                                                                                   
        #    raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_WALLET_OP))                                    
        if DEC_WALLET_OPTS_OP not in value:                                                                                                         
            # no options    
            raise InvalidTransaction('Verb is "{}", but no options for update wallet: {}.'.format(DEC_WALLET_OPTS_OP,name)) 
                                                                                                                        
        opts_pay = value[DEC_WALLET_OPTS_OP][DEC_WALLET_OPTS_OP]                                                                                        
        opts_new = cbor.loads(opts_pay)                                                                                                    
        psign = value[DEC_WALLET_OPTS_OP][DEC_SIGNATURE]                                                                                        
        # check notary sign                                                                                                              
        is_correct = self._check_sign(opts_new[NOTARY_PUBKEY],psign,opts_pay)
        if not is_correct:
            raise InvalidTransaction('Verb is "{}", but signature of OPTS is wrong.'.format(DEC_WALLET_OPTS_OP))
        LOGGER.debug('Set wallet opts is sign correct {}'.format(is_correct))
        wtoken = DecTokenInfo()                          
        wtoken.ParseFromString(state[name])                
        wallet = cbor.loads(wtoken.dec)                    
        opts = wallet[DEC_WALLET_OPTS_OP] if DEC_WALLET_OPTS_OP in wallet else {}
        if DEC_WALLET_LIMIT in opts_new:
            opts[DEC_WALLET_LIMIT] = opts_new[DEC_WALLET_LIMIT]
        if DEC_SPEND_PERIOD in opts_new:                         
            opts[DEC_SPEND_PERIOD] = opts_new[DEC_SPEND_PERIOD] 
        if DEC_WALLET_STATUS in opts_new:                          
            opts[DEC_WALLET_STATUS] = opts_new[DEC_WALLET_STATUS]
        if DEC_WALLET_ROLE in opts_new:
            role = opts_new[DEC_WALLET_ROLE]
            revoke = role[0:1] == '-'
            if DEC_WALLET_ROLE in opts:
                if revoke:
                    if isinstance(opts[DEC_WALLET_ROLE],list):
                        rval = role[1:]
                        if rval not in opts[DEC_WALLET_ROLE]:
                            raise InvalidTransaction('Verb is "{}", no such role={} in list.'.format(DEC_WALLET_OPTS_OP,rval))
                        opts[DEC_WALLET_ROLE].remove(rval)

                else:
                    # add role
                    if isinstance(opts[DEC_WALLET_ROLE],list):
                        if role in opts[DEC_WALLET_ROLE]:
                            raise InvalidTransaction('Verb is "{}", role={} already in list.'.format(DEC_WALLET_OPTS_OP,role))
                        opts[DEC_WALLET_ROLE].append(role)
                    else:
                        if opts[DEC_WALLET_ROLE] == role:
                            raise InvalidTransaction('Verb is "{}", role={} already in list.'.format(DEC_WALLET_OPTS_OP,role))
                        opts[DEC_WALLET_ROLE] = [opts[DEC_WALLET_ROLE],role]


            elif not revoke:
                opts[DEC_WALLET_ROLE] = [role]
                  
        wallet[DEC_WALLET_OPTS_OP] = opts   
        wtoken.dec = cbor.dumps(wallet)                                                                                                                                         
        updated = {k: v for k, v in state.items() if k in out}    
        updated[name] = wtoken.SerializeToString()                 
                                                              
        return updated                                                                                                                       
    
                                                                                                                                         



    def _do_burn(self,name, value, to, state, out):                                                                        
        LOGGER.debug('Burn "{n}" by {v}'.format(n=name, v=value))                                                                                            
                                                                                                                     
        if name not in state:                                                                                        
            raise InvalidTransaction(                                                                                
                'Verb is "{}" but name "{}" not in state'.format(DEC_BURN_OP,name))                                             
                                                                                                                     
        curr = state[name]                                                                                           
        token = DecTokenInfo()                                                                                       
        token.ParseFromString(curr)  
        dec = cbor.loads(token.dec) 
        nburn = dec[DEC_NBURN][DATTR_VAL]
        total_sum = dec[DEC_TOTAL_SUM][DATTR_VAL] 
        payload = value[DEC_PAYLOAD]
        burn_sum = payload[DEC_BURN_OP][DEC_TOTAL_SUM]
        passkey = dec[DEC_PASSKEY][DATTR_VAL] 
        emitter =  dec[DEC_CORPORATE_PUB_KEY][DATTR_VAL] if DEC_CORPORATE_PUB_KEY in dec else ''                                                                             
        LOGGER.debug('_do_burn token[{}]={}'.format(nburn,value))
        if key_to_dgt_addr(value[DEC_EMITTER]) != emitter:                                                                         
            raise InvalidTransaction('Verb is "{}", but only emmitter have right to burn DEC'.format(DEC_BURN_OP))                                                                                                              
        if nburn <= 0:                                                                                         
            raise InvalidTransaction('Verb is "{}", but limit of burn {}'.format(DEC_BURN_OP,nburn)) 
        if burn_sum > total_sum or burn_sum < 0:
            raise InvalidTransaction('Verb is "{}", but burn sum {} incorrect'.format(DEC_BURN_OP,burn_sum))
        if passkey != payload[DEC_BURN_OP][DEC_PASSKEY]:                                                              
            raise InvalidTransaction('Verb is "{}", but passkey incorrect'.format(DEC_BURN_OP))  

        updated = {k: v for k, v in state.items() if k in out}                                                                   
        dec[DEC_NBURN][DATTR_VAL] = nburn - 1 
        dec[DEC_NBURN][DEC_TMSTAMP] = payload[DEC_TMSTAMP] if DEC_TMSTAMP in payload else time.time()
        dec[DEC_TOTAL_SUM][DATTR_VAL] = total_sum - burn_sum
        token.dec = cbor.dumps(dec)                                                                                       
        updated[name] = token.SerializeToString()                                                                    
                                                                                                                     
        return updated                                                                                               

    def _do_change_mint(self,name, value, to, state, out):                                                                                           
        LOGGER.debug('Сhange_mint "{}" by {}'.format(name, value))                                                                        
                                                                                                                                         
        if name not in state:                                                                                                            
            raise InvalidTransaction(                                                                                                    
                'Verb is "{}" but name "{}" not in state'.format(DEC_CHANGE_MINT_OP,name))                                                      
        
        curr = state[name]                                                                                                               
        token = DecTokenInfo()                                                                                                           
        token.ParseFromString(curr)                                                                                                      
        dec = cbor.loads(token.dec)                                                                                                      
        mint = dec[DEC_MINT_PARAM][DATTR_VAL]                                                                                                
        passkey = dec[DEC_PASSKEY][DATTR_VAL]
        nmint = value[DEC_MINT_PARAM] 
        emitter =  dec[DEC_CORPORATE_PUB_KEY][DATTR_VAL] if DEC_CORPORATE_PUB_KEY in dec else ''                                                                                           
        LOGGER.debug('_do_change_mint param={}  '.format(mint))                                                                        
                                                                                                                                         
        if passkey != value[DEC_PASSKEY]:                                                                                                
            raise InvalidTransaction('Verb is "{}", but passkey incorrect'.format(DEC_CHANGE_MINT_OP))                                          
        if key_to_dgt_addr(value[DEC_EMITTER]) != emitter:
            raise InvalidTransaction('Verb is "{}", and only emmitter have right to change MINT COEFF'.format(DEC_CHANGE_MINT_OP))

        updated = {k: v for k, v in state.items() if k in out}  
        for attr,val in nmint.items():
            if attr in mint and val != mint[attr]:
                mint[attr] = val
                LOGGER.debug('_do_change_mint update[{}]={}'.format(attr,val))
        
        token.dec = cbor.dumps(dec)                                                                                                      
        updated[name] = token.SerializeToString()                                                                                        
                                                                                                                                         
        return updated                                                                                                                   

    def _do_faucet(self,name, value, to, state, out):                                                          
        LOGGER.debug('Faucet "{}" by {}'.format(name,value))                                       
                                                                                                               
       
        if DEC_EMISSION_KEY not in state:                                                          
            raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_FAUCET_OP))                                                                                                       
        curr = state[DEC_EMISSION_KEY]                                                                                     
        token = DecTokenInfo()                                                                                 
        token.ParseFromString(curr)                                                                            
        dec = cbor.loads(token.dec)                                                                            
        total_sum = dec[DEC_TOTAL_SUM][DATTR_VAL]
        passkey = dec[DEC_PASSKEY][DATTR_VAL] 
        sale_share = dec[DEC_SALE_SHARE][DATTR_VAL]
        max_sale = total_sum/100*sale_share
        total_sale = dec[DEC_SALE_TOTAL]
        tval = value[DATTR_VAL]
        tcurr = value[DEC_TMSTAMP]
        # destination token
        if name in state:                                                                       
            # destination token                                                               
            dtoken = DecTokenInfo()                                                           
            dtoken.ParseFromString(state[name])                                                 
                                                                                              
        else:                                                                                 
            LOGGER.debug('Faucet create destination WALLET={}'.format(name))                  
            dtoken = self._new_wallet(0,tcurr)                                                
                                                                 

        
        LOGGER.debug('_do_faucet total={} sale: max={} total={} value={}'.format(total_sum,max_sale,total_sale,value))                                        
                                                                                                               
        if DEC_PASSKEY not in value or passkey != value[DEC_PASSKEY]:                                                                      
            raise InvalidTransaction('Verb is "{}", but passkey incorrect or not set'.format(DEC_FAUCET_OP)) 
                       
        
        if tval > max_sale:
            raise InvalidTransaction('Verb is "{}", but value={} too match < {}'.format(DEC_FAUCET_OP,tval,max_sale))

        updated = {k: v for k, v in state.items() if k in out} 
        dest = cbor.loads(dtoken.dec)                                                            
        dtoken.decimals += tval 
        dest[DEC_TOTAL_SUM] += tval 
        dtoken.dec = cbor.dumps(dest) 



        #dec[DEC_SALE_TOTAL] = total_sale + tval                                                                                                    
        #token.dec = cbor.dumps(dec)                                                                            
        #updated[DEC_EMISSION_KEY] = token.SerializeToString()
        updated[name] = dtoken.SerializeToString()                                                              
                                                                                                               
        return updated                                                                                         

    def _do_send(self,name, value, inputs, state, out):                                                                                                     
        LOGGER.debug('Send "{}" by {}'.format(name,value))                                                                                         
        to = inputs[0]                                                                                                                                             
        if name not in state:                                                                                                                        
            raise InvalidTransaction('Verb is "{}" but name "{}" not in state'.format(DEC_SEND_OP,name))
        #if to not in state:                                                                    
        #    raise InvalidTransaction('Verb is "{}" but "{}" not in state'.format(DEC_SEND_OP,to)) 
                                                                      
        if DEC_EMISSION_KEY not in state:                                                                                                            
            raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_SEND_OP))  
        if DEC_WALLET_ROLE in value and value[DEC_WALLET_ROLE] not in state:
            raise InvalidTransaction('Verb is "{}" but role "{}" not in state'.format(DEC_SEND_OP,value[DEC_WALLET_ROLE]))
                                                                        
        curr = state[name]                                                                                                               
        token = DecTokenInfo()                                                                                                                       
        token.ParseFromString(curr)                                                                                                                  
        #dec = cbor.loads(token.dec)                                                                                                                  
        #total_sum = dec[DEC_TOTAL_SUM][DATTR_VAL]                                                                                                    
        #passkey = dec[DEC_PASSKEY][DATTR_VAL]                                                                                                        
        #sale_share = dec[DEC_SALE_SHARE][DATTR_VAL]                                                                                                  
        #max_sale = total_sum/100*sale_share                                                                                                          
        #total_sale = dec[DEC_SALE_TOTAL]                                                                                                             
        amount = value[DATTR_VAL] 
        tcurr = value[DEC_TMSTAMP]  
        if to in state:
            # destination token                                                                                                                          
            dtoken = DecTokenInfo()                                                                                                                      
            dtoken.ParseFromString(state[to])   
             
        else:
            if value[DEC_CMD_TO_GRP] == DEC_SYNONYMS_GRP:
                raise InvalidTransaction('Verb is "{}" but alias "{}" not in state'.format(DEC_SEND_OP,to))
            LOGGER.debug('_do_send create destination WALLET={}'.format(to))
            dtoken = self._new_wallet(0,tcurr)
        dest = cbor.loads(dtoken.dec)

        LOGGER.debug('_do_send value={}'.format(value))                               
        if name == DEC_EMISSION_KEY:
            # this is case when user ask tokens from сorporate wallet
            # check who is user 
            emiss = cbor.loads(token.dec)
            if key_to_dgt_addr(value[DEC_EMITTER]) != emiss[DEC_CORPORATE_PUB_KEY][DATTR_VAL]:
                raise InvalidTransaction('Verb is "{}", but user who ask transfer tokens to CORPORATE WALLET have not access'.format(DEC_SEND_OP))
            if emiss[DEC_СORPORATE_REST] < amount:
                amount = emiss[DEC_СORPORATE_REST]
            emiss[DEC_СORPORATE_REST] -= amount
            token.dec = cbor.dumps(emiss)
        else:
            eaddr = key_to_dgt_addr(value[DEC_EMITTER])
            src = cbor.loads(token.dec)
            wopts = src[DEC_WALLET_OPTS_OP]
            LOGGER.debug('_do_send CHECK OWNER ={} ~= {}'.format(eaddr,name))
            if (eaddr != name and DEC_WALLET_ADDR not in wopts)  or (DEC_WALLET_ADDR in wopts and eaddr != wopts[DEC_WALLET_ADDR]):
                raise InvalidTransaction('Verb is "{}", but not owner try to send token from user WALLET'.format(DEC_SEND_OP))
            
            total = src[DEC_TOTAL_SUM]
            if total < amount:                                                                                
                raise InvalidTransaction('Verb is "{}", but amount={} token more then token in sender wallet'.format(DEC_SEND_OP,amount)) 
            if DEC_WALLET_ROLE in value:
                role = value[DEC_WALLET_ROLE]
                if DEC_WALLET_ROLE in src[DEC_WALLET_OPTS_OP] and role not in src[DEC_WALLET_OPTS_OP][DEC_WALLET_ROLE]:
                    raise InvalidTransaction('Verb is "{}" but role "{}" not granted'.format(DEC_SEND_OP,role))

              
            # check spend period
            #tcurr = value[DEC_TMSTAMP]
            if DEC_SPEND_TMSTAMP in src :
                last_tm = src[DEC_SPEND_TMSTAMP]
                spend_period = src[DEC_WALLET_OPTS_OP][DEC_SPEND_PERIOD] if DEC_WALLET_OPTS_OP in src and DEC_SPEND_PERIOD in src[DEC_WALLET_OPTS_OP] else DEC_SPEND_PERIOD_DEF
                if tcurr - last_tm < spend_period:
                    raise InvalidTransaction('Verb is "{}", and operation send too fast < {}sec'.format(DEC_SEND_OP,spend_period))

            token.decimals -= amount 
            src[DEC_TOTAL_SUM] -= amount
            src[DEC_SPEND_TMSTAMP] = tcurr
            token.dec = cbor.dumps(src)
        
        # destination wallet
        dest = cbor.loads(dtoken.dec)
        dtoken.decimals += amount  
        dest[DEC_TOTAL_SUM] += amount                                                                                                                      
        dtoken.dec = cbor.dumps(dest)
          
        updated = {k: v for k, v in state.items() if k in out}                                                                                                                
        updated[name] = token.SerializeToString()                                                                                        
        updated[to] = dtoken.SerializeToString()                                                                                                   
                                                                                                                                                     
        return updated                                                                                                                               

    def _do_pay(self,name, value, inputs, state, out):                                                                                                      
        LOGGER.debug('Pay "{}" by {} inputs={} state={}'.format(name,value,inputs,[k for k in state.keys()]))                                                                                                   
        to = inputs[0] 
        target = inputs[1] if len(inputs) > 2 else None
        pinfo = value[DEC_PAYLOAD][DEC_PAY_OP]
        is_invoice = DEC_PROVEMENT_KEY in pinfo                                                                                                                                      
        if name not in state :                                                                                                             
            raise InvalidTransaction('Verb is "{}" but name "{}"  not in state'.format(DEC_PAY_OP,name)) 
        if to not in state and pinfo[DEC_CMD_TO_GRP] == DEC_SYNONYMS_GRP:                                                                  
            raise InvalidTransaction('Verb is "{}" but alias "{}" not in state'.format(DEC_PAY_OP,to))                                         
        if DEC_EMISSION_KEY not in state:                                                                                                                    
            raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_PAY_OP))                                                       
        if target is not None and target not in state:
            raise InvalidTransaction('Verb is "{}" but target "{}" not in state'.format(DEC_PAY_OP,target))
        src,token = get_wallet(state[name])
        wopts = src[DEC_WALLET_OPTS_OP]
        eaddr = key_to_dgt_addr(value[DEC_EMITTER])
        if (eaddr != name and DEC_WALLET_ADDR not in wopts)  or (DEC_WALLET_ADDR in wopts and eaddr != wopts[DEC_WALLET_ADDR]):                                                                                     
            raise InvalidTransaction('Verb is "{}", but not owner try to send token from user WALLET'.format(DEC_PAY_OP)) 

        # wallet of source
        total = src[DEC_TOTAL_SUM]
                                                                                                                                 
        #dec = cbor.loads(token.dec)                                                                                                                         
        #total_sum = dec[DEC_TOTAL_SUM][DATTR_VAL]                                                                                                           
        #passkey = dec[DEC_PASSKEY][DATTR_VAL]                                                                                                               
        #sale_share = dec[DEC_SALE_SHARE][DATTR_VAL]                                                                                                         
        #max_sale = total_sum/100*sale_share                                                                                                                 
        #total_sale = dec[DEC_SALE_TOTAL]                                                                                                                    
        amount = pinfo[DATTR_VAL]
        tcurr = value[DEC_PAYLOAD][DEC_TMSTAMP]                                                                                                                            
        # destination token                                                                                                                                  
        #dest,dtoken = get_wallet(state[to])   
        if to in state:                                                                                                     
            # destination token                                                                                             
            dtoken = DecTokenInfo()                                                                                         
            dtoken.ParseFromString(state[to])                                                                               
                                                                                                                            
        else:                                                                                                               
            LOGGER.debug('_do_pay create destination WALLET={}'.format(to))                                                
            dtoken = self._new_wallet(0,tcurr)                                                                              
        dest = cbor.loads(dtoken.dec)

        LOGGER.debug('_do_send value={}'.format(value))                                                                                                      
        ttoken = DecTokenInfo()                                                                                                                                                     
        if target:
            # check invoice
            # TODO set marker that payment was done  
            # TODO check target object
            ttoken.ParseFromString(state[target])                  
            target_val = cbor.loads(ttoken.dec)  
            t_val =  target_val[DEC_TARGET_OP]                      
            LOGGER.debug('_do_send target={}'.format(t_val))  
            if DEC_INVOICE_OP not in t_val:
                raise InvalidTransaction('Verb is "{}", but target={} with out invoice'.format(DEC_PAY_OP,target))
            invoice = t_val[DEC_INVOICE_OP]
            if is_invoice  and DEC_PROVEMENT_KEY in invoice and pinfo[DEC_PROVEMENT_KEY] != invoice[DEC_PROVEMENT_KEY]:
                raise InvalidTransaction('Verb is "{}", but invoice={} mismatch'.format(DEC_PAY_OP,pinfo[DEC_PROVEMENT_KEY]))
            if DEC_CUSTOMER_KEY not in invoice or (invoice[DEC_CUSTOMER_KEY] is not None and name != invoice[DEC_CUSTOMER_KEY]):
                raise InvalidTransaction('Verb is "{}", but customer mismatch with invoice'.format(DEC_PAY_OP))

            if AVAILABLE_TILL in invoice and invoice[AVAILABLE_TILL] < tcurr:
                # check time TODO
                raise InvalidTransaction('Verb is "{}", but invoice already expired'.format(DEC_PAY_OP))
            # real price 
            if invoice[DEC_TARGET_PRICE] != amount :
                raise InvalidTransaction('Verb is "{}", but price mismatch with invoice ({}~{})'.format(DEC_PAY_OP,invoice[DEC_TARGET_PRICE],amount))
            # change owner and drop invoice
            del t_val[DEC_INVOICE_OP]
            new_owner = key_to_dgt_addr(value[DEC_EMITTER])
            if new_owner == t_val[DEC_OWNER] :                                                                                                  
                raise InvalidTransaction('Verb is "{}", but you are already owner of {}'.format(DEC_PAY_OP, t_val[DEC_TARGET_ID]))
            t_val[DEC_OWNER] = new_owner # from now owner is customer 
            ttoken.dec = cbor.dumps(target_val)


        if DEC_SPEND_TMSTAMP in src :                                                                                                                                             
            last_tm = src[DEC_SPEND_TMSTAMP]                                                                                                                                      
            spend_period = src[DEC_WALLET_OPTS_OP][DEC_SPEND_PERIOD] if DEC_WALLET_OPTS_OP in src and DEC_SPEND_PERIOD in src[DEC_WALLET_OPTS_OP] else DEC_SPEND_PERIOD_DEF       
            if tcurr - last_tm < spend_period:                                                                                                                                    
                raise InvalidTransaction('Verb is "{}", and operation send too fast < {}sec'.format(DEC_PAY_OP,spend_period))                                                    

        if total < amount:                                                                                                             
            raise InvalidTransaction('Verb is "{}", but amount={} token more then token in sender wallet'.format(DEC_PAY_OP,amount))   

        updated = {k: v for k, v in state.items() if k in out} 
                                                                                                      
        dtoken.decimals += amount
        dest[DEC_TOTAL_SUM] += amount
        dtoken.dec = cbor.dumps(dest) 
        # update wallet of customer                                                                                                                         
        token.decimals -= amount
        src[DEC_TOTAL_SUM] -= amount                
        src[DEC_SPEND_TMSTAMP] = tcurr 
        token.dec = cbor.dumps(src)                 

        updated[name] = token.SerializeToString()                                                                                                            
        updated[to] = dtoken.SerializeToString() 
        if target:
            updated[target] = ttoken.SerializeToString()
        LOGGER.debug('PAY "{}"'.format("DONE"))                                                                                                                                                     
        return updated                                                                                                                                       

    def _do_invoice(self,name, value, inputs, state, out):                                                                                                  
        LOGGER.debug('INVOICE "{}" by {}'.format(name,value)) 
        customer = inputs[1] if len(inputs) > 1 else None

        if name not in state:                                                                                                        
            raise InvalidTransaction('Verb is "{}" but target "{}" not exists'.format(DEC_INVOICE_OP,name)) 
                                             
        #if DEC_EMISSION_KEY not in state:                                                                                                               
        #    raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_INVOICE_OP))
        if customer is not None and customer not in state:                                                                 
            raise InvalidTransaction('Verb is "{}" but customer pub key={} not in state'.format(DEC_INVOICE_OP,customer))                                                    
            
        # target                        
        curr = state[name]              
        token = DecTokenInfo()          
        token.ParseFromString(curr)     
        target = cbor.loads(token.dec) 
        t_val = target[DEC_TARGET_OP]
        # 
        owner = t_val[DEC_OWNER] if DEC_OWNER in t_val else 'undef'
        #LOGGER.debug('INVOICE owner "{}" ~ {}'.format(owner,value[DEC_EMITTER])) 
        if owner != key_to_dgt_addr(value[DEC_EMITTER]):
            raise InvalidTransaction('Verb is "{}" and only owner {} can add invoice'.format(DEC_INVOICE_OP,owner)) 

        info = {}
        payload = value[DEC_PAYLOAD]
        invo = payload[DEC_INVOICE_OP]
        if AVAILABLE_TILL in invo:
            info[AVAILABLE_TILL] = invo[AVAILABLE_TILL]

        amount = invo[DATTR_VAL]
        info[DEC_CUSTOMER_KEY] = invo[DEC_CUSTOMER_KEY] #customer
        info[DEC_PROVEMENT_KEY] = invo[DEC_PROVEMENT_KEY]
        info[DEC_TARGET_PRICE] = amount
        t_val[DEC_INVOICE_OP] = info  
                                                                                                                               
        # destination token                                                                                                                             

        LOGGER.debug('_do_invoice value={}'.format(value))                                                                                                 
                                                                                                                                                        
        updated = {k: v for k, v in state.items() if k in out}                                                                                          
        token.dec = cbor.dumps(target)
        updated[name] = token.SerializeToString()                                                                                                       
                                                                                                                                                        
        return updated                                                                                                                                  

    def _do_target(self,name, value, inputs, state, out):
        LOGGER.debug('TARGET "{}" by {}'.format(name,value))                                                                                       

        if name in state:                                                                                                                           
            raise InvalidTransaction('Verb is "{}" target with such name "{}" already in state'.format(DEC_TARGET_OP,name))                                
        LOGGER.debug('TARGET STATE={}'.format([k for k in state.keys()]))
        info = {} 
        payload = value[DEC_PAYLOAD]
        info[DEC_TARGET_OP] = payload[DEC_TARGET_OP] 
        tcurr = payload[DEC_TMSTAMP]  
        tips = payload[DEC_TIPS_OP][DEC_TIPS_OP]  
        agate  = payload[DEC_TIPS_OP][GATE_ADDR_ATTR]                                                                                                                                
        if DEC_DID_VAL  in payload:                      
            # for notary mode                          
            info[DEC_DID_VAL] = payload[DEC_DID_VAL]     
        info[DEC_EMITTER] = key_to_dgt_addr(value[DEC_EMITTER]) # pubkey of owner 
        info[DEC_TMSTAMP] = tcurr 
        # destination token                                                                                                                         
        updated = {k: v for k, v in state.items() if k in out}
        if tips > 0.0:
            # take tips 
            emiss,etoken = get_dec(state[DEC_EMISSION_KEY])
            min_tips = emiss[DEC_TIPS_OP][DATTR_VAL][DEC_TARGET_OP] if DEC_TARGET_OP in emiss[DEC_TIPS_OP][DATTR_VAL] else 0.0
            #LOGGER.debug('TARGET TIPS={}'.format(emiss[DEC_TIPS_OP]))
            if tips < min_tips:
                raise InvalidTransaction('Verb is "{}" but tips < min {} '.format(DEC_TARGET_OP,min_tips))

            oname = info[DEC_EMITTER]
            if oname not in state:
                 raise InvalidTransaction('Verb is "{}" and tips > 0 but owner={} wallet undefined '.format(DEC_TARGET_OP,oname)) 
            owner,otoken = get_wallet(state[oname])
            total = owner[DEC_TOTAL_SUM]
            if tips > total:
                raise InvalidTransaction('Verb is "{}" and not enough DEC on owner={} wallet for paying tips={}'.format(DEC_TARGET_OP,oname,tips))

            if DGT_TOPOLOGY_SET_NM not in state:                   
                raise InvalidTransaction('Verb is "{}" but no topology {} info'.format(DEC_TARGET_OP,DGT_TOPOLOGY_SET_NM))
            tval = json.loads(state[DGT_TOPOLOGY_SET_NM])  
            fbft = FbftTopology()                                                                             
            fbft.get_topology(tval,'','','static')                                                            
            #                                                                                                 
            is_gate = fbft.peer_is_gate(agate)                                                            
            LOGGER.debug('Topology peer={} gate "{}"'.format(agate,is_gate))                              
            if not is_gate:                                                                                   
                raise InvalidTransaction('Verb is "{}", but emitter is not Gate'.format(DEC_EMISSION_OP))   



            otoken.decimals = round(otoken.decimals - tips)           
            owner[DEC_TOTAL_SUM] -= tips       
            owner[DEC_SPEND_TMSTAMP] = tcurr     
            otoken.dec = cbor.dumps(owner)        
            updated[oname] = otoken.SerializeToString()
            if agate in state:                                                               
                # destination token                                                       
                dtoken = DecTokenInfo()                                                   
                dtoken.ParseFromString(state[agate])                                         
                                                                                          
            else:                                                                         
                LOGGER.debug('_do_target create gate WALLET={}'.format(agate))          
                dtoken = self._new_wallet(0,tcurr)                                        
            dest = cbor.loads(dtoken.dec)
            dtoken.decimals = round(dtoken.decimals + tips)                                                      
            dest[DEC_TOTAL_SUM] += tips  
            dtoken.dec = cbor.dumps(dest)
            updated[agate] = dtoken.SerializeToString()  

        token = DecTokenInfo(group_code = DEC_TARGET_GRP,                                                                                          
                             owner_key = self._signer.sign(DEC_TARGET_GRP.encode()),                                                               
                             sign = self._public_key.as_hex(),                                                                                      
                             decimals=int(info[DEC_TARGET_OP][DEC_TARGET_PRICE]),                                                                                                       
                             dec = cbor.dumps(info)                                                                                                 
                )                                                                                                                                   
                                                                                                                                                    
                                                                                                                                 
        LOGGER.debug('_do_target tips={} value={}'.format(tips,info))                                                                                          
                                                                                                                                                    
        updated[name] = token.SerializeToString()                                                                                                   
                                                                                                                                                    
        return updated                                                                                                                              

    def _do_role(self,name, value, inputs, state, out):                                                                                
        LOGGER.debug('NEW ROLE "{}" by {}'.format(name,value))                                                                             
                                                                                                                                         
        if name in state:                                                                                                                
            raise InvalidTransaction('Verb is "{}" role with such name "{}" already exists'.format(DEC_ROLE_OP,name))              
                                                                                                                                         
        info = {} 
        payload = value[DEC_PAYLOAD]                                                                                                                       
        info[DEC_ROLE_OP] = payload[DEC_ROLE_OP]                                                                                   
        info[DEC_EMITTER] = key_to_dgt_addr(value[DEC_EMITTER]) 
        if DEC_DID_VAL  in payload:
            # for notary mode
            info[DEC_DID_VAL] = payload[DEC_DID_VAL]
        
                                                                                                                                         
        token = DecTokenInfo(group_code = DEC_ROLE_GRP,                                                                                
                             owner_key = self._signer.sign(DEC_ROLE_GRP.encode()),                                                     
                             sign = self._public_key.as_hex(),                                                                           
                             decimals=0,                                                                       
                             dec = cbor.dumps(info)                                                                                      
                )                                                                                                                        
                                                                                                                                         
        # destination token                                                                                                              
                                                                                                                                         
        LOGGER.debug('_do_role value={}'.format(value))                                                                                
                                                                                                                                         
        updated = {k: v for k, v in state.items() if k in out}                                                                           
                                                                                                                                         
        updated[name] = token.SerializeToString()                                                                                        
                                                                                                                                         
        return updated                                                                                                                   



    def _do_mint(self,name, value, to, state, out): 
        """
        peer key - node who ask reward + emission + heartbeat
        """                                                             
        LOGGER.debug('Mint "{}" by {} out={}'.format(name, value,out))                                                
                                                                                                                        
        if name not in state:                                                                                           
            raise InvalidTransaction('Verb is "{}" but name "{}" not in state'.format(DEC_MINT_OP,name))   
        if DEC_EMISSION_KEY not in state:                                                                  
            raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_MINT_OP)) 
        if DEC_HEART_BEAT_KEY not in state:
            raise InvalidTransaction('Verb is "{}" but first heartbeat was not done yet'.format(DEC_MINT_OP))
         
        tcurr = value[DEC_TMSTAMP] #time.time()
        ecurr = state[DEC_EMISSION_KEY]
        etoken = DecTokenInfo()                                                           
        etoken.ParseFromString(ecurr)                   
        emiss = cbor.loads(etoken.dec)                  
        wdate = emiss[DEC_WAIT_TO_DATE][DATTR_VAL]  
        mint_period = emiss[DEC_MINT_PARAM][DATTR_VAL][DEC_MINT_PERIOD]    
        if wdate > tcurr:
            raise InvalidTransaction('Verb is "{}" but we should wait until {}'.format(DEC_MINT_OP,wdate))
        
        # wallet                                                                                                                 
        curr = state[name]                                                                                              
        token = DecTokenInfo()                                                                                          
        token.ParseFromString(curr)                                                                                     
        dec = cbor.loads(token.dec)  
        

        # take info from heartbeat
        hcurr = state[DEC_HEART_BEAT_KEY]
        htoken = DecTokenInfo()        
        htoken.ParseFromString(hcurr)  
        heart = cbor.loads(htoken.dec) 
        last_mint = heart[DEC_MINT_TMSTAMP] if DEC_MINT_TMSTAMP in heart else 0
        if DEC_HEART_BEAT_PEERS not in heart or name not in heart[DEC_HEART_BEAT_PEERS]:                       
            raise InvalidTransaction('Verb is "{}" but peer has no heartbeat info'.format(DEC_MINT_OP))  
        
        lucky_peers = heart[DEC_HEART_BEAT_PEERS]
        prev_reward = lucky_peers[name][DEC_MINT_REWARD]
        is_too_fast = tcurr < last_mint + mint_period      
        # last_mint  - keep into emission and calc total reward for all peers and change total dec for mint    
        if is_too_fast and prev_reward <=0 :                                                                    
            raise InvalidTransaction('Verb is "{}" but to fast operation try after={}sec last mint={}'.format(DEC_MINT_OP,(last_mint + mint_period)-tcurr,last_mint))                 


        curr_beat = lucky_peers[name][DEC_HEART_BEAT_CURR]
        if 0 == curr_beat and prev_reward <= 0:
            raise InvalidTransaction('Verb is "{}" but peer has no heartbeat until last call'.format(DEC_MINT_OP))

                                                         
        #  calc total reward and reward for all peers 
        #  
        duration = tcurr - last_mint # time for calc reward
        lucky_nodes = 0
        total_curr_beat = 0
        for key,peer in lucky_peers.items():
            if peer[DEC_HEART_BEAT_CURR] > 0:
                lucky_nodes += 1 
                total_curr_beat += peer[DEC_HEART_BEAT_CURR]

        # calc reward 
        coef = emiss[DEC_MINT_PARAM][DATTR_VAL]
        UMAX = coef[DEC_MINT_COEF_UMAX]
        B2   = coef[DEC_MINT_COEF_B2]
        T1   = coef[DEC_MINT_COEF_T1]
        total_reward = B2*((1-math.exp(-duration/T1))/(duration/T1)-math.exp(-duration/T1))*lucky_nodes*UMAX

        LOGGER.debug('_do_mint token[{}]={} curr_beat={} lucky_nodes={} total_curr_beat={} coef={} total_reward={}'.format(dec,value,curr_beat,lucky_nodes,total_curr_beat,coef,total_reward))


        updated = {k: v for k, v in state.items() if k in out} 

        
        
        #dec[DEC_HEART_BEAT_TOTAL] = total_beat # save for check changing beat counter at the next call
          
        # update DEC_HEART_BEAT_KEY : marker of last mint reward 
        if lucky_nodes > 0 and not is_too_fast:
            if tcurr > last_mint :
                heart[DEC_MINT_TMSTAMP] = tcurr
            # save total reward for all peers
            if DEC_MINT_REWARD in heart:
                if emiss[DEC_MINTING_TOTAL] < heart[DEC_MINT_REWARD] + total_reward:
                    # restrict reward
                    total_reward = emiss[DEC_MINTING_TOTAL] - heart[DEC_MINT_REWARD]
                heart[DEC_MINT_REWARD] += total_reward
            else:
                heart[DEC_MINT_REWARD] = total_reward

            for key,peer in lucky_peers.items():   
                if peer[DEC_HEART_BEAT_CURR] > 0: 
                    beat_curr = peer[DEC_HEART_BEAT_CURR]
                    reward = total_reward*(beat_curr/total_curr_beat)
                    peer[DEC_HEART_BEAT_TOTAL] += beat_curr
                    peer[DEC_HEART_BEAT_CURR] = 0
                    # add current reward
                    peer[DEC_MINT_REWARD] += reward

        # send accumulated reward into wallet 
        dec[DEC_MINT_TMSTAMP] = tcurr
        dec[DEC_TOTAL_SUM] += lucky_peers[name][DEC_MINT_REWARD]
        # clear reward which was sended into wallet
        lucky_peers[name][DEC_MINT_REWARD] = 0.0

        # send result into state
        htoken.dec = cbor.dumps(heart)                                                                      
        updated[DEC_HEART_BEAT_KEY] = htoken.SerializeToString() 
        token.dec = cbor.dumps(dec)               
        updated[name] = token.SerializeToString() 
                                                                                                                        
        return updated                                                                                                  

    def _do_heartbeat(self,name, value, inputs, state, out):                                                                                           
        LOGGER.debug('HEART BEAT "{}" by {}'.format(name,value))                                                                                        

        #if DEC_EMISSION_KEY not in state:                                                                                                            
        #    raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_HEART_BEAT_OP))                                            
                                                                                                                                                     
        tcurr = value[DEC_TMSTAMP]                                                                                                                                   
        if name in state:
            curr = state[name]                                                                     
            token = DecTokenInfo()                                                                 
            token.ParseFromString(curr)  
            dec = cbor.loads(token.dec)                                                          
            LOGGER.debug('_do_heart token[%s]=%s',token.group_code,dec) # token.decimals           
            token.decimals += 1   
            # check heart period   
            if tcurr > dec[DEC_LAST_HEART_TMSTAMP]:
                dec[DEC_LAST_HEART_TMSTAMP] = tcurr
            dec[DEC_HEART_BEAT_TOTAL] += 1 
            # list peer's  pub keys 
            peers = value[DEC_HEART_BEAT_PEERS] if DEC_HEART_BEAT_PEERS in value else []
            for peer_pub in peers:
                peer = key_to_dgt_addr(peer_pub)
                if peer not in dec[DEC_HEART_BEAT_PEERS]:
                    # add peer and check peer using topology info
                    # { total beat,
                    dec[DEC_HEART_BEAT_PEERS][peer] = {DEC_HEART_BEAT_TOTAL: 0,DEC_MINT_REWARD : 0.0,DEC_HEART_BEAT_CURR : 0}
                # heart beat for current period between mint
                dec[DEC_HEART_BEAT_PEERS][peer][DEC_HEART_BEAT_CURR] += 1

            token.dec = cbor.dumps(dec)
        else:
            info = {DEC_HEART_BEAT_TOTAL : 0,
                    DEC_MINT_REWARD      : 0.0,
                    DEC_TMSTAMP            : tcurr, # first heart beat
                    DEC_LAST_HEART_TMSTAMP : tcurr,
                    DEC_MINT_TMSTAMP       : 0,
                    DEC_HEART_BEAT_PERIOD : value[DEC_HEART_BEAT_PERIOD] if DEC_HEART_BEAT_PERIOD in value else DEC_HEART_BEAT_PERIOD_DEF,
                    DEC_HEART_BEAT_PEERS  : {} # info about nodes which signed this transaction
                    }

            token = DecTokenInfo(group_code = DEC_HEART,                                                                                           
                                 owner_key = self._signer.sign(DEC_HEART.encode()),                                                                
                                 sign = self._public_key.as_hex(),                                                                                       
                                 decimals=0,                                                                                                        
                                 dec = cbor.dumps(info)                                                                                                  
                    )                                                                                                                                    
                                                                                                                                                     
        # destination token                                                                                                                          
                                                                                                                                                     
        LOGGER.debug('_do_heartbeat value={}'.format(value))                                                                                           
                                                                                                                                                     
        updated = {k: v for k, v in state.items() if k in out}                                                                                       
                                                                                                                                                     
        updated[name] = token.SerializeToString()                                                                                                    
                                                                                                                                                     
        return updated                                                                                                                               


    def _do_set(self,name, value, to, state, out):
        msg = 'Setting "{n}" to {v}'.format(n=name, v=value)
        LOGGER.debug(msg)
        

        if name in state:
            raise InvalidTransaction('Verb is "set", but already exists: Name: {n}, Value {v}'.format(n=name,v=state[name]))

        updated = {k: v for k, v in state.items() if k in out}
        #owner_key = self._context.sign('DEC_token'.encode(),self._private_key)
        token = DecTokenInfo(group_code = DEC_WALLET,
                             owner_key = self._signer.sign('DEC_token'.encode()), #owner_key,
                             sign = self._public_key.as_hex(),
                             decimals = int(value),
                             dec=cbor.dumps({DEC_MINT_TMSTAMP: 0,DEC_TOTAL_SUM : 0})
                )
        updated[name] = token.SerializeToString()
        #LOGGER.debug('_do_set updated=%s',updated)
        return updated


    def _do_inc(self,name, value, to, state, out):
        msg = 'Incrementing "{n}" by {v}'.format(n=name, v=value)
        LOGGER.debug(msg)

        if name not in state:
            raise InvalidTransaction(
                'Verb is "inc" but name "{}" not in state'.format(name))

        curr = state[name]
        token = DecTokenInfo()
        token.ParseFromString(curr)
        LOGGER.debug('_do_inc token[%s]=%s',token.group_code,value) # token.decimals
        incd = token.decimals + value

        if incd > MAX_VALUE:
            raise InvalidTransaction('Verb is "inc", but result would be greater than {}'.format(MAX_VALUE))

        updated = {k: v for k, v in state.items() if k in out}
        token.decimals = incd
        updated[name] = token.SerializeToString() 

        return updated


    def _do_dec(self,name, value, to, state, out):
        msg = 'Decrementing "{n}" by {v}'.format(n=name, v=value)
        LOGGER.debug(msg)

        if name not in state:
            raise InvalidTransaction(
                'Verb is "dec" but name "{}" not in state'.format(name))

        curr = state[name]
        token = DecTokenInfo()
        token.ParseFromString(curr)
        LOGGER.debug('_do_dec token[%s]=%s',token.group_code,token.decimals,value)
        decd = token.decimals - value

        if decd < MIN_VALUE:
            raise InvalidTransaction(
                'Verb is "dec", but result would be less than {}'.format(
                    MIN_VALUE))

        updated = {k: v for k, v in state.items() if k in out}
        token.decimals = decd
        updated[name] = token.SerializeToString()

        return updated

    def _do_trans(self,vfrom, value, inputs, state, out):
        vto = inputs[0]
        msg = 'transfer "{n}"->"{t}" by {v}'.format(n=vfrom,t=vto, v=value)
        LOGGER.debug(msg)

        if vfrom not in state or vto not in state:
            raise InvalidTransaction(
                'Verb is "trans" but vallet "{}" or vallet "{}" not in state'.format(vfrom,vto))

        curr = state[vfrom]
        token = DecTokenInfo()
        token.ParseFromString(curr)
        to = state[vto]
        token1 = DecTokenInfo()
        token1.ParseFromString(to)
        LOGGER.debug('_do_tans token[%s]=%s',token.group_code,value) 
        decd = token.decimals - value
        if decd < MIN_VALUE:
            raise InvalidTransaction('Verb is "trans", but result would be less than {}'.format(MIN_VALUE))
        incd = token1.decimals + value
        if incd >  MAX_VALUE:
            raise InvalidTransaction('Verb is "inc", but result would be greater than {}'.format(MAX_VALUE))

        updated = {k: v for k, v in state.items() if k in out}
        token.decimals = decd
        updated[vfrom] = token.SerializeToString()
        token1.decimals = incd
        updated[vto] = token1.SerializeToString() 

        return updated
        

    def _unpack_transaction(self,transaction):
        verb, name, value, to, out = self._decode_transaction(transaction)
        LOGGER.debug('_unpack_transaction:{} for {} to={} check'.format(verb, name,to))
        _validate_verb(verb)
        _validate_name(name[0],verb)
        _validate_value(value)
        if to is not None:
            _validate_to(to)
        LOGGER.debug('_unpack_transaction:{} for {}'.format(verb, name))
        return verb, name, value, to, out

    def _check_sign(self,pubkey,signature,payload):
        public_key = self._context.pub_from_hex(pubkey)                             
        ret = self._signer.verify(signature, payload,public_key )        
        return ret


    def _decode_transaction(self,transaction):
        try:
            payload = cbor.loads(transaction.payload)
            # if True:
            # check sign 
            content = cbor.loads(payload[DATTR_VAL])
            
            try:
                public_key = self._context.pub_from_hex(payload[DEC_PUBKEY])
                ret = self._signer.verify(payload[DEC_SIGNATURE], payload[DATTR_VAL],public_key )
                LOGGER.debug('_decode_transaction check sign={} key={}'.format(ret,payload[DEC_PUBKEY]))
            except Exception as ex:
                LOGGER.debug('_decode_transaction check sign error {}'.format(ex))

        except:
            raise InvalidTransaction('Invalid payload serialization')

        LOGGER.debug('_decode_transaction content={}'.format(content))
        try:
            verb = content[DEC_CMD]
        except AttributeError:
            raise InvalidTransaction('Verb is required')

        try:
            name = content[DEC_CMD_ARG]
        except AttributeError:
            raise InvalidTransaction('Name is required')

        try:
            value = content[DEC_CMD_VAL]
            if DEC_HEADER_PAYLOAD in value and DEC_HEADER_SIGN in value:                                          
                """                                                                                                   
                signed with notary transaction                                                                        
                """                                                                                                   
                hpayload = value[DEC_HEADER_PAYLOAD]                                                                
                hsignature = value[DEC_HEADER_SIGN]
                                                                                 
                hdr = cbor.loads(hpayload)   
                # NOTARY KEY                                                                          
                public_key = self._context.pub_from_hex(hdr[DEC_NOTARY_KEY])                                          
                ret = self._signer.verify(hsignature, hpayload,public_key ) 
                if not ret:
                    LOGGER.debug('_decode_transaction Notary sign={} incorrect'.format(ret))
                    raise AttributeError
                LOGGER.debug('_decode_transaction check Notary sign={} HDR={}'.format(ret,hdr)) 
                rsignature = hdr[DEC_NOTARY_REQ_SIGN]                      
                rpayload = value[DEC_PAYLOAD]
                val = cbor.loads(rpayload)
                # OWNER KEY
                public_key = self._context.pub_from_hex(val[DEC_EMITTER])
                ret = self._signer.verify(rsignature, rpayload,public_key ) 
                if not ret:   
                    LOGGER.debug('_decode_transaction User sign={} incorrect'.format(ret))           
                    raise AttributeError 
                LOGGER.debug('_decode_transaction check User sign={} REQ={}'.format(ret,val))
                value = val

        except AttributeError:
            raise InvalidTransaction('Value is required')
        out = [name[0]]
        #LOGGER.debug('_decode_transaction verb=%s',verb)    
        if verb in VALID_VERBS_WITH_TO :
            if DEC_CMD_TO not in content :
                raise InvalidTransaction('To is required')
            to_list = content[DEC_CMD_TO] if isinstance(content[DEC_CMD_TO],list) else [content[DEC_CMD_TO]]
            to = []
            for tv in to_list:
                to.append((FAMILY_NAME,tv[0],tv[1],tv[2])) # add name space
                out.append(tv[0])
            LOGGER.debug('_decode_transaction to={}'.format(to))
        else:
            to = None
        if DATTR_INPUTS in content and content[DATTR_INPUTS] != []:
            # with namespace
            to = content[DATTR_INPUTS] if to is None else to + content[DATTR_INPUTS] 
        LOGGER.debug('_decode_transaction verb={} for {} in={} to={}'.format(verb,name,content[DATTR_INPUTS],to))
        return verb, name, value, to, out

    def _get_state_data(self,name,to, context,verb,val):                                                                                        
        # c2939e262010e2fb3afc48cd4aa029bb11e6af76ea524d2bd14c77a49c7ef9c9e4d489                                                           
                                                                                                                                           
        naddr = full_dec_address(name[0],name[1],name[2])#make_full_dec_address(name,verb,val)                                                                                       
        #LOGGER.debug('ADDR:name={} addr={} to={}'.format(name,naddr,to))                                                                   
        astates = [naddr]                                                                                                                  
        self._addr_map[name[0]] = naddr                                                                                                       
        if to is not None:                                                                                                                 
            r_to = []                                                                                                                      
            for tv in to:                                                                                                                  
                #LOGGER.debug('ADDR: fam={} name={}'.format(fam,addr))                                                                     
                taddr = full_dec_address(tv[1],tv[2],tv[3]) if tv[0] == FAMILY_NAME else _make_settings_key(tv[1])                         
                astates.append(taddr)                                                                                                      
                r_to.append(tv[1])                                                                                                         
                #LOGGER.debug('ADDR: fam={} name={}:{}'.format(tv[0],tv[1],taddr))                                                          
                self._addr_map[tv[1]] = taddr                                                                                              
                                                                                                                                           
        else:                                                                                                                              
            r_to = None  
        LOGGER.debug('_get_state_data key={} add={}'.format(r_to,astates))                                                                                                                  
        state_entries = context.get_state(astates)                                                                                         
        try:                                                                                                                               
            states = {}                                                                                                                    
            #LOGGER.debug('_get_state_data state_entries={} add={}'.format(state_entries,astates))                                         
            for i,entry in enumerate(state_entries):                                                                                       
                if entry.address[0:6] == SETTINGS_NAMESPACE:                                                                               
                    # topology info                                                                                                        
                    #LOGGER.debug('_get_state_data add=%s type=%s',r_to[i],type(entry.data))                                               
                    setting = Setting()                                                                                                    
                    setting.ParseFromString(entry.data)                                                                                    
                    #LOGGER.debug('_get_state_data add={} type={} data={}'.format(r_to[i],type(entry.data),setting))                       
                    #val = json.loads(data)                                                                                                
                    states[setting.entries[0].key] = setting.entries[0].value                                                              
                else:                                                                                                                      
                    state = cbor.loads(entry.data)                                                                                         
                    #LOGGER.debug('_get_state_data entry=({})'.format(entry))                                                              
                    for key, val in state.items():                                                                                         
                        #LOGGER.debug('_get_state_data add=%s', key)                                                                       
                        states[key] = val                                                                                                  
            return states,r_to                                                                                                             
        except IndexError:                                                                                                                 
            LOGGER.debug('_get_state_data: IndexError')                                                                                    
            return {},r_to                                                                                                                 
        except Exception as ex:                                                                                                            
            LOGGER.debug('_get_state_data: Failed to load state data ({})'.format(ex))                                                     
            raise InvalidTransaction('Failed to load state data ({})'.format(ex))                                                          


    def _set_state_data(self, state, context,verb,vl):                                           
        new_states = {}                                                                     
        for key,val in state.items():                                                       
            LOGGER.debug('_set_state_data  [%s]=%s ...', key, val[0:10])                    
            address = self._addr_map[key] #make_full_dec_address(key,verb,vl)               
                                                                                            
            encoded = cbor.dumps({key: val})                                                
            new_states[address] = encoded                                                   
                                                                                            
        addresses = context.set_state(new_states)                                           
        if not addresses:                                                                   
            raise InternalError('State error')                                              



def _validate_verb(verb):
    if verb not in VALID_VERBS:
        raise InvalidTransaction('Verb must be:{}'.format(VALID_VERBS))


def _validate_name(name,verb):
    if verb not in LONG_NAME_OPS and (not isinstance(name, str) or len(name) > MAX_NAME_LENGTH):
        raise InvalidTransaction('Name must be a string of no more than {} characters'.format(MAX_NAME_LENGTH))

def _validate_to(name):                                                                                        
    if not isinstance(name, list):                                                 
        raise InvalidTransaction('To must be a list')  


def _validate_value(value):
    if (isinstance(value, int) and value >= 0 and value < MAX_VALUE) or isinstance(value, dict):
        pass
    else:
        raise InvalidTransaction('Value must be an integer no less than {i} and no greater than {a}'.format(i=MIN_VALUE,a=MAX_VALUE))




