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
import hashlib
import base64
import cbor
import json
import time
import math

from dgt_sdk.processor.handler import TransactionHandler
from dgt_sdk.processor.exceptions import InvalidTransaction
from dgt_sdk.processor.exceptions import InternalError
from dec_common.protobuf.dec_dgt_token_pb2 import DecTokenInfo
from dgt_signing import CryptoFactory,create_context
from dec_dgt.client_cli.dec_attr import *
from dgt_settings.processor.utils import _make_settings_key,SETTINGS_NAMESPACE
from dgt_settings.protobuf.setting_pb2 import Setting
from dgt_validator.gossip.fbft_topology import DGT_TOPOLOGY_SET_NM,FbftTopology

LOGGER = logging.getLogger(__name__)





DEC_ADDRESS_PREFIX = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]

def make_dec_prefix():
    return hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]

def make_dec_address(name):
    return DEC_ADDRESS_PREFIX + hashlib.sha512(name.encode('utf-8')).hexdigest()[-64:]


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
        verb, name, value, to, out = self._unpack_transaction(transaction)
        LOGGER.debug('APPLY: verb=%s name=%s value=%s to=%s',verb, name, value, to)
        state,to = _get_state_data(name,to, context)
        #LOGGER.debug('apply: state = {}'.format(state))
        updated_state = self._do_op_dec(verb, name, value, to, state, out)
        
        _set_state_data( updated_state, context)
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
            raise InternalError('Unhandled verb: {} TB={}'.format(verb,tb))
        #except InvalidTransaction:   
        #    raise InvalidTransaction 

        except Exception as ex:
            tb = traceback.format_exc()                                      
            raise InvalidTransaction('Verb: {} err={} TB={}'.format(verb,ex,tb)) 
        
        
         
    # Emission parts 
    def _do_emission(self,name, value, to, state, out ):                                                                                           
        LOGGER.debug('emission "{}"'.format(name))                                                                                                               
                                                                                                                                        
                                                                                                                                        
        if name in state:                                                                                                               
            raise InvalidTransaction('Verb is "{o}", but already exists: Name: {n}, Value {v}'.format(o=DEC_EMISSION_OP,n=name,v=state[name]))            
        if DGT_TOPOLOGY_SET_NM in state:
            tval = json.loads(state[DGT_TOPOLOGY_SET_NM])
            #LOGGER.debug('Topology "{}"'.format(tval))
            fbft = FbftTopology()
            fbft.get_topology(tval,'','','static')
            is_peer = fbft.peer_is_leader(value[DEC_EMITTER])
            pname = fbft.get_scope_peer_attr(value[DEC_EMITTER])
            peer = fbft.get_peer(value[DEC_EMITTER])
            LOGGER.debug('Topology is peer={} leader"{}"'.format(peer,is_peer))
            if not is_peer:
                raise InvalidTransaction('Verb is "{}", but emitter is not Leader'.format(DEC_EMISSION_OP))


            # check key into topology
        updated = {k: v for k, v in state.items() if k in out}                                                                                      
        #owner_key = self._context.sign('DEC_token'.encode(),self._private_key) 
        mint_share = value[DEC_MINTING_SHARE][DATTR_VAL] 
        corp_share = value[DEC_СORPORATE_SHARE][DATTR_VAL]
        sale_share = 100.0 - (mint_share + corp_share)
        dec_total = value[DEC_TOTAL_SUM][DATTR_VAL]
        tcurr = value[DEC_TMSTAMP] #time.time()
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
            
                                                       
        token = DecTokenInfo(group_code = DEC_NAME_DEF,                                                                                  
                             owner_key = self._signer.sign(DEC_NAME_DEF.encode()),
                             sign = self._public_key.as_hex(), 
                             decimals=0,                                                                         
                             dec = cbor.dumps(value)                                                                                      
                )                                                                                                                       
        updated[name] = token.SerializeToString()                                                                                       
        #LOGGER.debug('_do_emission updated=%s',updated)                                                                                      
        return updated                                                                                                                  

    def _do_wallet(self,name, value, to, state, out):                                                                                     
        LOGGER.debug('Wallet "{}" to {}'.format(name,value))                                                                                                              
                                                                                                                                       
                                                                                                                                       
        if name in state:                                                                                                              
            raise InvalidTransaction('Verb is "{}", but already exists: Name: {}, Value {}'.format(DEC_WALLET_OP,name,state[name])) 
        #if DEC_EMISSION_KEY not in state:                                                              
        #    raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_WALLET_OP)) 
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



            
        # wallet options
        opts_pay = value[DEC_WALLET_OPTS_OP][DEC_WALLET_OPTS_OP]    
        opts = cbor.loads(opts_pay)                             
        psign = value[DEC_WALLET_OPTS_OP][DEC_SIGNATURE]            
        is_correct = self._check_sign(opts[NOTARY_PUBKEY],psign,opts_pay)                                
        if not is_correct:                                                                                 
            raise InvalidTransaction('Verb is "{}", but signature of OPTS is wrong.'.format(DEC_WALLET_OP)) 


        tcurr = value[DEC_TMSTAMP]                                                                                                                              
        updated = {k: v for k, v in state.items() if k in out}                                                                         
        #owner_key = self._context.sign('DEC_token'.encode(),self._private_key)                                                        
        token = DecTokenInfo(group_code = DEC_WALLET,                                                                                  
                             owner_key = self._signer.sign(DEC_WALLET.encode()), #owner_key,                                          
                             sign = self._public_key.as_hex(),                                                                         
                             decimals = 0,                                                                                    
                             dec=cbor.dumps({DEC_TMSTAMP: tcurr,
                                             DEC_TOTAL_SUM : 0,
                                             DEC_DID_VAL   : did_val,
                                             DEC_WALLET_OPTS_OP : opts
                                             }
                            )                                                   
                )                                                                                                                      
        updated[name] = token.SerializeToString()                                                                                      
        #LOGGER.debug('_do_set updated=%s',updated)                                                                                    
        return updated                                                                                                                 
  
    def _do_wallet_opts(self,name, value, to, state, out):                                                                                        
        LOGGER.debug('Set wallet opts "{}" to {}'.format(name,value))                                                                                 
                                                                                                                                             
                                                                                                                                             
        if name not in state:                                                                                                                    
            raise InvalidTransaction('Verb is "{}", but wallet not exists: Name: {}, Value {}'.format(DEC_WALLET_OPTS_OP,name,state[name]))          
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
        burn_sum = value[DEC_TOTAL_SUM]
        passkey = dec[DEC_PASSKEY][DATTR_VAL]                                                                              
        LOGGER.debug('_do_burn token[{}]={}'.format(nburn,value))

                                                                                                                     
        if nburn <= 0:                                                                                         
            raise InvalidTransaction('Verb is "{}", but limit of burn {}'.format(DEC_BURN_OP,nburn)) 
        if burn_sum > total_sum or burn_sum < 0:
            raise InvalidTransaction('Verb is "{}", but burn sum {} incorrect'.format(DEC_BURN_OP,burn_sum))
        if passkey != value[DEC_PASSKEY]:                                                              
            raise InvalidTransaction('Verb is "{}", but passkey incorrect'.format(DEC_BURN_OP))  

        updated = {k: v for k, v in state.items() if k in out}                                                                   
        dec[DEC_NBURN][DATTR_VAL] = nburn - 1 
        dec[DEC_TOTAL_SUM][DATTR_VAL] = total_sum - burn_sum
        token.dec = cbor.dumps(dec)                                                                                       
        updated[name] = token.SerializeToString()                                                                    
                                                                                                                     
        return updated                                                                                               

    def _do_change_mint(self,name, value, to, state, out):                                                                                           
        LOGGER.debug('Сhange_mint "{n}" by {v}'.format(n=name, v=value))                                                                        
                                                                                                                                         
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
        LOGGER.debug('_do_change_mint token[{}]={}'.format(mint,value))                                                                        
                                                                                                                                         
        if passkey != value[DEC_PASSKEY]:                                                                                                
            raise InvalidTransaction('Verb is "{}", but passkey incorrect'.format(DEC_CHANGE_MINT_OP))                                          
        if value[DEC_EMITTER] != dec[DEC_EMITTER]:
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
                                                                                                               
        if name not in state:                                                                                  
            raise InvalidTransaction('Verb is "{}" but pubkey "{}" not in state'.format(DEC_FAUCET_OP,name)) 
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
        # destination token
        dtoken = DecTokenInfo()                                                                
        dtoken.ParseFromString(state[name])
        LOGGER.debug('_do_faucet total={} sale: max={} total={} value={}'.format(total_sum,max_sale,total_sale,value))                                        
                                                                                                               
        if DEC_PASSKEY not in value or passkey != value[DEC_PASSKEY]:                                                                      
            raise InvalidTransaction('Verb is "{}", but passkey incorrect or not set'.format(DEC_FAUCET_OP)) 
                       
        
        if total_sale + tval > max_sale:
            raise InvalidTransaction('Verb is "{}", but value={} too match'.format(DEC_FAUCET_OP,tval))

        updated = {k: v for k, v in state.items() if k in out}                                                             
        dtoken.decimals += tval 
        dec[DEC_SALE_TOTAL] = total_sale + tval                                                                                                    
        token.dec = cbor.dumps(dec)                                                                            
        updated[DEC_EMISSION_KEY] = token.SerializeToString()
        updated[name] = dtoken.SerializeToString()                                                              
                                                                                                               
        return updated                                                                                         

    def _do_send(self,name, value, inputs, state, out):                                                                                                     
        LOGGER.debug('Send "{}" by {}'.format(name,value))                                                                                         
        to = inputs[0]                                                                                                                                             
        if name not in state or to not in state:                                                                                                                        
            raise InvalidTransaction('Verb is "{}" but name "{}" or "{}" not in state'.format(DEC_SEND_OP,name,to))                                                              
        if DEC_EMISSION_KEY not in state:                                                                                                            
            raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_SEND_OP))  
                                                                        
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
        # destination token                                                                                                                          
        dtoken = DecTokenInfo()                                                                                                                      
        dtoken.ParseFromString(state[to])   
        dest = cbor.loads(dtoken.dec)                                                                                                       
        LOGGER.debug('_do_send value={}'.format(value))                               
        if name == DEC_EMISSION_KEY:
            # this is case when user ask tokens from сorporate wallet
            # check who is user 
            emiss = cbor.loads(token.dec)
            if value[DEC_EMITTER] != emiss[DEC_CORPORATE_PUB_KEY][DATTR_VAL]:
                raise InvalidTransaction('Verb is "{}", but user who ask transfer tokens to CORPORATE WALLET have not access'.format(DEC_SEND_OP))
            if emiss[DEC_СORPORATE_REST] < amount:
                amount = emiss[DEC_СORPORATE_REST]
            emiss[DEC_СORPORATE_REST] -= amount
            token.dec = cbor.dumps(emiss)
        else:
            if value[DEC_EMITTER] != name:
                raise InvalidTransaction('Verb is "{}", but not owner try to send token from user WALLET'.format(DEC_SEND_OP))
            src = cbor.loads(token.dec)
            total = src[DEC_TOTAL_SUM]
            if total < amount:                                                                                
                raise InvalidTransaction('Verb is "{}", but amount={} token more then token in sender wallet'.format(DEC_SEND_OP,amount)) 
                                                    
              
            # check spend period
            tcurr = value[DEC_TMSTAMP]
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
        is_invoice = DEC_PROVEMENT_KEY in value                                                                                                                                      
        if name not in state or to not in state:                                                                                                             
            raise InvalidTransaction('Verb is "{}" but name "{}" or "{}" not in state'.format(DEC_PAY_OP,name,to))                                          
        if DEC_EMISSION_KEY not in state:                                                                                                                    
            raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_PAY_OP))                                                       
        if target is not None and target not in state:
            raise InvalidTransaction('Verb is "{}" but target "{}" not in state'.format(DEC_PAY_OP,target))
        if value[DEC_EMITTER] != name:                                                                                     
            raise InvalidTransaction('Verb is "{}", but not owner try to send token from user WALLET'.format(DEC_PAY_OP)) 

        # wallet of source
        curr = state[name]                                                                                                                                   
        token = DecTokenInfo()                                                                                                                               
        token.ParseFromString(curr) 
        src = cbor.loads(token.dec)
        total = src[DEC_TOTAL_SUM]
                                                                                                                                 
        #dec = cbor.loads(token.dec)                                                                                                                         
        #total_sum = dec[DEC_TOTAL_SUM][DATTR_VAL]                                                                                                           
        #passkey = dec[DEC_PASSKEY][DATTR_VAL]                                                                                                               
        #sale_share = dec[DEC_SALE_SHARE][DATTR_VAL]                                                                                                         
        #max_sale = total_sum/100*sale_share                                                                                                                 
        #total_sale = dec[DEC_SALE_TOTAL]                                                                                                                    
        amount = value[DATTR_VAL]
        tcurr = value[DEC_TMSTAMP]                                                                                                                            
        # destination token                                                                                                                                  
        dtoken = DecTokenInfo()                                                                                                                              
        dtoken.ParseFromString(state[to]) 
        dest = cbor.loads(dtoken.dec)   

        LOGGER.debug('_do_send value={}'.format(value))                                                                                                      
        ttoken = DecTokenInfo()                                                                                                                                                     
        if target:
            # check invoice
            # TODO set marker that payment was done  
            # TODO check target object
            ttoken.ParseFromString(state[target])                  
            t_val = cbor.loads(ttoken.dec)                         
            LOGGER.debug('_do_send target={}'.format(t_val))  
            if DEC_INVOICE_OP not in t_val:
                raise InvalidTransaction('Verb is "{}", but target={} with out invoice'.format(DEC_PAY_OP,target))
            invoice = t_val[DEC_INVOICE_OP]
            if is_invoice  and DEC_PROVEMENT_KEY in invoice and value[DEC_PROVEMENT_KEY] != invoice[DEC_PROVEMENT_KEY]:
                raise InvalidTransaction('Verb is "{}", but invoice={} mismatch'.format(DEC_PAY_OP,value[DEC_PROVEMENT_KEY]))
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
            t_val[DEC_EMITTER] = name
            ttoken.dec = cbor.dumps(t_val)


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
        src[DEC_SPEND_TMSTAMP] = value[DEC_TMSTAMP] 
        token.dec = cbor.dumps(src)                 

        updated[name] = token.SerializeToString()                                                                                                            
        updated[to] = dtoken.SerializeToString() 
        if target:
            updated[target] = ttoken.SerializeToString()
                                                                                                                                                             
        return updated                                                                                                                                       

    def _do_invoice(self,name, value, inputs, state, out):                                                                                                  
        LOGGER.debug('INVOICE "{}" by {}'.format(name,value)) 
        customer = inputs[1] if len(inputs) > 1 else None

        if name not in state:                                                                                                        
            raise InvalidTransaction('Verb is "{}" but target "{}" not exists'.format(DEC_INVOICE_OP,name)) 
                                             
        if DEC_EMISSION_KEY not in state:                                                                                                               
            raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_INVOICE_OP))
        if customer is not None and customer not in state:                                                                 
            raise InvalidTransaction('Verb is "{}" but customer pub key={} not in state'.format(DEC_INVOICE_OP,customer))                                                    
            
        # target                        
        curr = state[name]              
        token = DecTokenInfo()          
        token.ParseFromString(curr)     
        target = cbor.loads(token.dec)  
        if target[DEC_EMITTER] != value[DEC_EMITTER]:
            raise InvalidTransaction('Verb is "{}" and only owner can add invoice'.format(DEC_INVOICE_OP,target[DEC_EMITTER])) 

        info = {}
        if AVAILABLE_TILL in value:
            info[AVAILABLE_TILL] = value[AVAILABLE_TILL]

        amount = value[DATTR_VAL]
        info[DEC_CUSTOMER_KEY] = customer
        info[DEC_PROVEMENT_KEY] = value[DEC_PROVEMENT_KEY]
        info[DEC_TARGET_PRICE] = amount
        target[DEC_INVOICE_OP] =info  
                                                                                                                               
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

        info = {}                                                                                                                                   
        info[DEC_TARGET_INFO] = value[DEC_TARGET_INFO]                                                                                            
        info[DEC_TARGET_PRICE] = value[DATTR_VAL] if DATTR_VAL in value else 0                                                             
        info[DEC_EMITTER] = value[DEC_EMITTER] 
        if DEC_INVOICE_OP in value:
            info[DEC_INVOICE_OP] = value[DEC_INVOICE_OP]                                                                                                          
                                                                                                                                                    
        token = DecTokenInfo(group_code = DEC_TARGET_GRP,                                                                                          
                             owner_key = self._signer.sign(DEC_TARGET_GRP.encode()),                                                               
                             sign = self._public_key.as_hex(),                                                                                      
                             decimals=int(info[DEC_TARGET_PRICE]),                                                                                                       
                             dec = cbor.dumps(info)                                                                                                 
                )                                                                                                                                   
                                                                                                                                                    
        # destination token                                                                                                                         
                                                                                                                                                    
        LOGGER.debug('_do_target value={}'.format(value))                                                                                          
                                                                                                                                                    
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
            peers = value[DEC_HEART_BEAT_PEERS] if DEC_HEART_BEAT_PEERS in value else []
            for peer in peers:
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
        _validate_name(name,verb)
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

        #LOGGER.debug('_decode_transaction content=%s',content)
        try:
            verb = content['Verb']
        except AttributeError:
            raise InvalidTransaction('Verb is required')

        try:
            name = content['Name']
        except AttributeError:
            raise InvalidTransaction('Name is required')

        try:
            value = content['Value']
        except AttributeError:
            raise InvalidTransaction('Value is required')
        out = [name]
        #LOGGER.debug('_decode_transaction verb=%s',verb)    
        if verb in VALID_VERBS_WITH_TO :
            if 'To' not in content :
                raise InvalidTransaction('To is required')
            to_list = content['To'] if isinstance(content['To'],list) else [content['To']]
            to = []
            for to_val in to_list:
                to.append((FAMILY_NAME,to_val)) # add name space
                out.append(to_val)
        else:
            to = None
        if DATTR_INPUTS in content and content[DATTR_INPUTS] != []:
            # with namespace
            to = content[DATTR_INPUTS] if to is None else to + content[DATTR_INPUTS] 
        LOGGER.debug('_decode_transaction verb={} for {}'.format(verb,name))
        return verb, name, value, to, out


def _validate_verb(verb):
    if verb not in VALID_VERBS:
        raise InvalidTransaction('Verb must be:{}'.format(VALID_VERBS))


def _validate_name(name,verb):
    if verb not in [DEC_WALLET_OP,DEC_WALLET_OPTS_OP,DEC_MINT_OP,DEC_SEND_OP,DEC_PAY_OP] and (not isinstance(name, str) or len(name) > MAX_NAME_LENGTH):
        raise InvalidTransaction('Name must be a string of no more than {} characters'.format(MAX_NAME_LENGTH))

def _validate_to(name):                                                                                        
    if not isinstance(name, list):                                                 
        raise InvalidTransaction('To must be a list')  


def _validate_value(value):
    if (isinstance(value, int) and value >= 0 and value < MAX_VALUE) or isinstance(value, dict):
        pass
    else:
        raise InvalidTransaction('Value must be an integer no less than {i} and no greater than {a}'.format(i=MIN_VALUE,a=MAX_VALUE))


def _get_state_data(name,to, context):
    astates = [make_dec_address(name)]
    if to is not None:
        r_to = []
        for fam,addr in to:
            if fam == FAMILY_NAME:
                astates.append(make_dec_address(addr))
            else:
                astates.append(_make_settings_key(addr))
            r_to.append(addr)

    else:
        r_to = None
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


def _set_state_data( state, context):
    new_states = {}
    for key,val in state.items():
        LOGGER.debug('_set_state_data  [%s]=%s ...', key, val[0:10])
        address = make_dec_address(key)
        encoded = cbor.dumps({key: val})
        new_states[address] = encoded

    addresses = context.set_state(new_states)
    if not addresses:
        raise InternalError('State error')



