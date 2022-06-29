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
import hashlib
import base64
import cbor
import time

from dgt_sdk.processor.handler import TransactionHandler
from dgt_sdk.processor.exceptions import InvalidTransaction
from dgt_sdk.processor.exceptions import InternalError
from dec_common.protobuf.dec_dgt_token_pb2 import DecTokenInfo
from dgt_signing import CryptoFactory,create_context
from dec_dgt.client_cli.dec_attr import *
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
        verb, name, value, to, out = _unpack_transaction(transaction)
        LOGGER.debug('APPLY: verb=%s name=%s value=%s to=%s',verb, name, value, to)
        state = _get_state_data(name,to, context)
        #LOGGER.debug('apply: state = {}'.format(state))
        updated_state = self._do_op_dec(verb, name, value, to, state, out)
        
        _set_state_data( updated_state, context)
        #except Exception as ex:
        #    raise InternalError('Apply: verb: {} - {}'.format(verb,ex))

    def _do_op_dec(self,verb, name, value, to, state, out):
        verbs = {
            DEC_EMISSION_OP    : self._do_emission,
            DEC_BURN_OP        : self._do_burn,
            DEC_CHANGE_MINT_OP : self._do_change_mint,
            DEC_FAUCET_OP      : self._do_faucet,
            DEC_SEND_OP        : self._do_send,
            DEC_PAY_OP         : self._do_pay,
            DEC_INVOICE_OP     : self._do_invoice,
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
            raise InternalError('Unhandled verb: {}'.format(verb))

    # Emission parts 
    def _do_emission(self,name, value, to, state, out ):                                                                                           
        LOGGER.debug('emission "{}"'.format(name))                                                                                                               
                                                                                                                                        
                                                                                                                                        
        if name in state:                                                                                                               
            raise InvalidTransaction('Verb is "{o}", but already exists: Name: {n}, Value {v}'.format(o=DEC_EMISSION_OP,n=name,v=state[name]))            
                                                                                                                                        
        updated = {k: v for k, v in state.items() if k in out}                                                                                      
        #owner_key = self._context.sign('DEC_token'.encode(),self._private_key)  
        value[DEC_TMSTAMP] = time.time()  
        value[DEC_MINTING_TOTAL   ] = 0
        value[DEC_СORPORATE_TOTAL ] = 0
        value[DEC_SALE_TOTAL      ] = 0
        sale_share = 100.0 - (value[DEC_MINTING_SHARE][DATTR_VAL] + value[DEC_СORPORATE_SHARE][DATTR_VAL])
        value[DEC_SALE_SHARE]  = {DATTR_VAL : sale_share} 
                                                       
        token = DecTokenInfo(group_code = DEC_NAME_DEF,                                                                                  
                             owner_key = self._signer.sign(DEC_NAME_DEF.encode()),
                             sign = self._public_key.as_hex(), 
                             decimals=0,                                                                         
                             dec = cbor.dumps(value)                                                                                      
                )                                                                                                                       
        updated[name] = token.SerializeToString()                                                                                       
        #LOGGER.debug('_do_emission updated=%s',updated)                                                                                      
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
                'Verb is "{}" but name "{}" not in state'.format(DEC_BURN_OP,name))                                                      
                                                                                                                                         
        curr = state[name]                                                                                                               
        token = DecTokenInfo()                                                                                                           
        token.ParseFromString(curr)                                                                                                      
        dec = cbor.loads(token.dec)                                                                                                      
        mint = dec[DEC_MINT_PARAM][DATTR_VAL]                                                                                                
        passkey = dec[DEC_PASSKEY][DATTR_VAL]
        nmint = value[DEC_MINT_PARAM]                                                                                             
        LOGGER.debug('_do_change_mint token[{}]={}'.format(mint,value))                                                                        
                                                                                                                                         
        if passkey != value[DEC_PASSKEY]:                                                                                                
            raise InvalidTransaction('Verb is "{}", but passkey incorrect'.format(DEC_BURN_OP))                                          
                                                                                                                                         
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
        LOGGER.debug('_do_send value={}'.format(value))                               
                                                                                                                                                     
        if token.decimals < amount:                                                                                
            raise InvalidTransaction('Verb is "{}", but amount={} token more then token in sender wallet'.format(DEC_SEND_OP,amount))                                         
                                                                                                                                                     
        updated = {k: v for k, v in state.items() if k in out}                                                                                                   
        dtoken.decimals += amount
        token.decimals -= amount                                                                                                                      
        #token.dec = cbor.dumps(dec)                                                                                                                  
        updated[name] = token.SerializeToString()                                                                                        
        updated[to] = dtoken.SerializeToString()                                                                                                   
                                                                                                                                                     
        return updated                                                                                                                               

    def _do_pay(self,name, value, inputs, state, out):                                                                                                      
        LOGGER.debug('Pay "{}" by {} state={}'.format(name,value,[k for k in state.keys()]))                                                                                                   
        to = inputs[0] 
        is_invoice = DEC_PROVEMENT_KEY in value                                                                                                                                      
        if name not in state or to not in state:                                                                                                             
            raise InvalidTransaction('Verb is "{}" but name "{}" or "{}" not in state'.format(DEC_PAY_OP,name,to))                                          
        if DEC_EMISSION_KEY not in state:                                                                                                                    
            raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_PAY_OP))                                                       
        if is_invoice and value[DEC_PROVEMENT_KEY] not in state:
            raise InvalidTransaction('Verb is "{}" but invoice "{}" not in state'.format(DEC_PAY_OP,value[DEC_PROVEMENT_KEY]))
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
        LOGGER.debug('_do_send value={}'.format(value))                                                                                                      
                                                                                                                                                             
        if token.decimals < amount:                                                                                                                          
            raise InvalidTransaction('Verb is "{}", but amount={} token more then token in sender wallet'.format(DEC_PAY_OP,amount))    
                            
        if is_invoice:
            # check invoice 
            itoken = DecTokenInfo()
            itoken.ParseFromString(state[value[DEC_PROVEMENT_KEY]])
            invoice = cbor.loads(itoken.dec)
            if DEC_TARGET in invoice and (DEC_TARGET not in value or value[DEC_TARGET] != invoice[DEC_TARGET]):
                raise InvalidTransaction('Verb is "{}", but target absent or mismatch '.format(DEC_PAY_OP))
            if AVAILABLE_TILL in invoice:
                # check time 
                pass

        updated = {k: v for k, v in state.items() if k in out}                                                                                               
        dtoken.decimals += amount                                                                                                                            
        token.decimals -= amount                                                                                                                             
        #token.dec = cbor.dumps(dec)                                                                                                                         
        updated[name] = token.SerializeToString()                                                                                                            
        updated[to] = dtoken.SerializeToString()                                                                                                             
                                                                                                                                                             
        return updated                                                                                                                                       

    def _do_invoice(self,name, value, inputs, state, out):                                                                                                  
        LOGGER.debug('INVOICE "{}" by {}'.format(name,value))                                                                                               
        pub_key = inputs[1]                                                                                                                                  
        if name in state:                                                                                                        
            raise InvalidTransaction('Verb is "{}" but prove_key "{}" already in state'.format(DEC_INVOICE_OP,name)) 
                                             
        if DEC_EMISSION_KEY not in state:                                                                                                               
            raise InvalidTransaction('Verb is "{}" but emission was not done yet'.format(DEC_INVOICE_OP))
        if pub_key not in state:                                                                 
            raise InvalidTransaction('Verb is "{}" but pub_key={} not in state'.format(DEC_INVOICE_OP,pub_key))                                                    
                                                                                                                                                        
        info = {}
        if AVAILABLE_TILL in value:
            info[AVAILABLE_TILL] = value[AVAILABLE_TILL]
        if DEC_TARGET in value:
            info[DEC_TARGET] = value[DEC_TARGET]
        amount = value[DATTR_VAL]
        token = DecTokenInfo(group_code = DEC_INVOICE_DEF,                                        
                             owner_key = self._signer.sign(DEC_INVOICE_DEF.encode()),             
                             sign = self._public_key.as_hex(),                                 
                             decimals=amount,                                                       
                             dec = cbor.dumps(info)                                           
                )                                                                              
                                                                                                                               
        # destination token                                                                                                                             

        LOGGER.debug('_do_invoice value={}'.format(value))                                                                                                 
                                                                                                                                                        
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
        token = DecTokenInfo(group_code = 'DEC_token',
                             owner_key = self._signer.sign('DEC_token'.encode()), #owner_key,
                             sign = self._public_key.as_hex(),
                             decimals = int(value),
                             dec=cbor.dumps({})
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
        

def _unpack_transaction(transaction):
    verb, name, value, to, out = _decode_transaction(transaction)
    LOGGER.debug('_unpack_transaction:{} for {} to={} check'.format(verb, name,to))
    _validate_verb(verb)
    _validate_name(name)
    _validate_value(value)
    if to is not None:
        _validate_to(to)
    LOGGER.debug('_unpack_transaction:{} for {}'.format(verb, name))
    return verb, name, value, to, out


def _decode_transaction(transaction):
    try:
        content = cbor.loads(transaction.payload)
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

        to = [content['To']]
        out.append(content['To'])
    else:
        to = None
    if DATTR_INPUTS in content:
        to = content[DATTR_INPUTS] if to is None else to + content[DATTR_INPUTS] 
    LOGGER.debug('_decode_transaction verb={} for {}'.format(verb,name))
    return verb, name, value, to, out


def _validate_verb(verb):
    if verb not in VALID_VERBS:
        raise InvalidTransaction('Verb must be:{}'.format(VALID_VERBS))


def _validate_name(name):
    if not isinstance(name, str) or len(name) > MAX_NAME_LENGTH:
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
        for addr in to:
            astates.append(make_dec_address(addr))
    state_entries = context.get_state(astates)
    try:
        states = {}
        #LOGGER.debug('_get_state_data state_entries={} add={}'.format(state_entries,astates))
        for entry in state_entries:
            state = cbor.loads(entry.data)
            #LOGGER.debug('_get_state_data state=(%s)', state)
            for key, val in state.items():
                #LOGGER.debug('_get_state_data add=%s', key)
                states[key] = val
        return states
    except IndexError:
        LOGGER.debug('_get_state_data: IndexError')
        return {}
    except:
        LOGGER.debug('_get_state_data: Failed to load state data')
        raise InvalidTransaction('Failed to load state data')


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



