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

import logging
import hashlib
import base64
import cbor


from dgt_sdk.processor.handler import TransactionHandler
from dgt_sdk.processor.exceptions import InvalidTransaction
from dgt_sdk.processor.exceptions import InternalError
from deth_common.protobuf.deth_pb2 import (DethTransaction as BgtTokenInfo,
                                           CreateExternalAccountTxn,
                                           EvmPermissions,
                                           CreateContractAccountTxn,
                                           EvmStateAccount,
                                           EvmEntry,EvmStorage
                                           )
from dgt_signing import CryptoFactory,create_context
from deth.client_cli.deth_attr import *
LOGGER = logging.getLogger(__name__)


VALID_VERBS = DETH_CRT_OP, DETH_CALL_OP,DETH_PERM_OP, DETH_SEND_OP,DETH_SMART_OP
VERBS_WITH_TO = DETH_SEND_OP
MIN_VALUE = 0
MAX_VALUE = 4294967295
MAX_NAME_LENGTH = 20

#FAMILY_NAME = 'deth'
#FAMILY_VER = '1.0'
DETH_ADDRESS_PREFIX = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]

def make_deth_prefix():
    return hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]

def make_deth_address(name):
    return DETH_ADDRESS_PREFIX + hashlib.sha512(name.encode('utf-8')).hexdigest()[-64:]


class DethTransactionHandler(TransactionHandler):
    def __init__(self,evm=None):
        self._evm = evm
        self._context = create_context('secp256k1') 
        LOGGER.debug('_do_set: context')
        self._private_key = self._context.new_random()
        LOGGER.debug('_do_set: context private_key=%s',self._private_key.as_hex())
        self._public_key = self._context.get_public_key(self._private_key)
        crypto_factory = CryptoFactory(self._context)
        self._signer = crypto_factory.new_signer(self._private_key)
        #self._signer = CryptoFactory(self._context).new_signer(self.private_key)
        LOGGER.debug('_do_set: public_key=%s  ',self._public_key.as_hex())
        LOGGER.info('DethTransactionHandler init DONE PREF=%s',DETH_ADDRESS_PREFIX)

    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return [FAMILY_VER]

    @property
    def namespaces(self):
        return [DETH_ADDRESS_PREFIX]

    def apply(self, transaction, context):
        LOGGER.debug('apply:....\n')
        verb, name, value, to = _unpack_transaction(transaction)
        LOGGER.debug('apply:verb={} name={} value={} to={}'.format(verb, name, value, to))
        state = _get_state_data(name,to, context)

        updated_state = self._do_deth(verb, name, value, to, state)

        _set_state_data( updated_state, context)

    def _do_deth(self,verb, name, value, to, state):
        verbs = {
            DETH_CRT_OP: self._do_create,
            DETH_CALL_OP: self._do_call,
            DETH_SEND_OP: self._do_send,
            'dec': self._do_dec,
            DETH_SMART_OP: self._do_smart,
        }
        LOGGER.debug('_do_deth request....')
        try:
            return verbs[verb](name, value,to, state)
        except KeyError:
            # This would be a programming error.
            raise InternalError('Unhandled verb: {}'.format(verb))


    def _do_create(self,name, value, to, state):

        LOGGER.debug('Create "{n}" to {v}'.format(n=name, v=value))
        #self._evm.get_balance(name)

        if name in state:
            #self._evm.add(name,100)
            self._evm.get_balance(name) 
            raise InvalidTransaction('Verb is "{}", but already exists: Name: {}'.format(DETH_CRT_OP,name))

        updated = {k: v for k, v in state.items()}
        #owner_key = self._context.sign('BGT_token'.encode(),self._private_key)
        try:
            address,nonce,balance = self._evm.create_account(name)
            LOGGER.debug('account "{}"={} nonce {}'.format(address, balance,nonce))
            storages = []                                                  
            permissions = EvmPermissions(perms=0,set_bit=0)                
            state_account = EvmStateAccount(                               
                     nonce=nonce,                                          
                     address=address,                                      
                     balance=int(balance),                                            
                     permissions=permissions                               
                )                                                          
            token = EvmEntry(                                              
                            account = state_account,                       
                            storage = storages                             
                )                                                          
            #token = BgtTokenInfo(transaction_type = BgtTokenInfo.CREATE_EXTERNAL_ACCOUNT,
            #                     create_external_account = create_external_account
            #
            #        )
        except  Exception as ex :                                                          
            raise InvalidTransaction('Verb is "create", account error - {}'.format(ex)) 
                                                                                           



        updated[name] = token.SerializeToString()
        LOGGER.debug('_do_create updated=%s',updated)
        return updated


    def _do_call(self,name, value, to, state):
        LOGGER.debug('CALL "{n}" by {v}'.format(n=name, v=value))

        if name not in state:
            raise InvalidTransaction(
                'Verb is "call" but name "{}" not in state'.format(name))

        curr = state[name]            
        token = EvmEntry()        
        token.ParseFromString(curr)   

        try:                                                                                   
            self._evm.call_smart_func(value[DETH_CREATER],token.account.address,value[DETH_CALL_FUNC])        
        except  Exception as ex :                                                              
            raise InvalidTransaction('Verb is "call", smart method error - {}'.format(ex))   
                 

        updated = {k: v for k, v in state.items()}
        updated[name] = token.SerializeToString() 

        return updated


    def _do_dec(self,name, value, to, state):
        msg = 'Decrementing "{n}" by {v}'.format(n=name, v=value)
        LOGGER.debug(msg)

        if name not in state:
            raise InvalidTransaction(
                'Verb is "dec" but name "{}" not in state'.format(name))

        curr = state[name]
        token = EvmEntry()
        token.ParseFromString(curr)

        #LOGGER.debug('token=%s',token.account.address)
        decd = token.decimals - value

        if decd < MIN_VALUE:
            raise InvalidTransaction(
                'Verb is "dec", but result would be less than {}'.format(
                    MIN_VALUE))

        updated = {k: v for k, v in state.items()}
        token.decimals = decd
        updated[name] = token.SerializeToString()

        return updated

    def _do_smart(self,name, value, to, state):                                                                                   
        LOGGER.debug('Create smart "{n}" attr {v}'.format(n=name, v=value))                                                                                                          
        creator = value[DETH_CREATER]                                                                                                                           
        if name in state and not value[DETH_UPDATE_MODE]:                                                                                                          
            raise InvalidTransaction('Verb is "smart", but already exists: Name: {n}'.format(n=name))       
                                                                                                                                   
        updated = {k: v for k, v in state.items()}                                                                                 
        smart = value[DETH_SMART_CODE]
        try:
            address,nonce = self._evm.create_smart(creator,smart[DETH_BIN])  
        except  Exception as ex :
            raise InvalidTransaction('Verb is "smart", create error {}'.format(ex)) 

        code = cbor.dumps(smart)
        try:
            if name in state:
                curr = state[name]          
                token = EvmEntry()          
                token.ParseFromString(curr) 
                token.account.address = address
                token.account.nonce = nonce
                token.account.code = code
                LOGGER.debug('Update smart "{}" addr= {}'.format(name, address)) 
            else:


                storages = []
                permissions = EvmPermissions(perms=0,set_bit=0)                                                                            
                state_account = EvmStateAccount(                                                                        
                         nonce=nonce,                                                                                                          
                         address=address, 
                         balance=0,
                         code = code,
                         permissions=permissions                                                                                           
                    ) 
                token = EvmEntry( 
                                account = state_account,
                                storage = storages
                    )                                                                                                                       

        except   Exception as ex:
            raise InvalidTransaction('Verb is "smart", create TOKEN error {}'.format(ex)) 

        updated[name] = token.SerializeToString()                                                                                  
        LOGGER.debug('_do_create updated=%s',updated)                                                                              
        return updated 
                                                                                                                
    def _do_send(self,name, value, to, state):                                                                                            
        LOGGER.debug('Send {} from "{}" to {}'.format(value,name,to))                                                                                                                  
                                                                                                                                           
        if name not in state:                                                                                                                  
            raise InvalidTransaction('Verb is "send", but Name: {} not exists'.format(name))               
                                                                                                                                           
        updated = {k: v for k, v in state.items()}                                                                                         
        ac_from = state[name]            
        ftoken = EvmEntry()        
        ftoken.ParseFromString(ac_from)
        try:
            to_address,nonce,bal1,bal2 = self._evm.send(name,to,int(value))
        except Exception as ex:
            raise InvalidTransaction('Verb is "send", but cmd error {}'.format(ex))

        LOGGER.debug('Send {} nonce={} BAL {}->{}'.format(value,nonce,bal1,bal2))

        if to in state:  
            ac_to = state[to]             
            ttoken = EvmEntry()         
            ttoken.ParseFromString(ac_to)
            #ttoken.account.balance += int(value)
        else:
            # create new 
            permissions = EvmPermissions(perms=0,set_bit=0) 
            storages = [] 
            state_account = EvmStateAccount(                                
                     nonce=0,                                           
                     address=to_address,                                       
                     balance=0,                                  
                     permissions=permissions                                
                )                                                           
            ttoken = EvmEntry(                                               
                            account = state_account,                        
                            storage = storages                              
                )                                                           
        

        ftoken.account.nonce = nonce     
        ftoken.account.balance = int(bal1)    

        ttoken.account.balance = int(bal2)                                                                                                                             
        updated[name] = ftoken.SerializeToString()
        updated[to] = ttoken.SerializeToString()                                                                                          
        LOGGER.debug('_do_send updated=%s ',updated)                                                                                      
        return updated                                                                                                                     
    
    
    
    
       

def _unpack_transaction(transaction):
    verb, name, value, to = _decode_transaction(transaction)

    _validate_verb(verb)
    _validate_name(name)
    _validate_value(value,verb)
    if to is not None:
        _validate_name(to)

    return verb, name, value, to


def _decode_transaction(transaction):
    try:
        content = cbor.loads(transaction.payload)
    except:
        raise InvalidTransaction('Invalid payload serialization')

    LOGGER.debug('_decode_transaction content=%s',content)
    try:
        verb = content[DETH_VERB]
    except AttributeError:
        raise InvalidTransaction('Verb is required')

    try:
        name = content[DETH_NAME]
    except AttributeError:
        raise InvalidTransaction('Name is required')

    try:
        value = content[DETH_VAL]
    except AttributeError:
        raise InvalidTransaction('Value is required')

    LOGGER.debug('_decode_transaction verb=%s',verb)    
    if verb in VERBS_WITH_TO :
        if 'To' not in content :
            raise InvalidTransaction('To is required')
        to = content['To']
    else:
        to = None
    
    return verb, name, value, to


def _validate_verb(verb):
    if verb not in VALID_VERBS:
        raise InvalidTransaction('Verb must be: {}'.format(VALID_VERBS))


def _validate_name(name):
    if not isinstance(name, str):
        raise InvalidTransaction('Name must be a string ')


def _validate_value(value,verb):
    if verb in VERB_NON_INT_VAL:
        return
    if not isinstance(value, int) or value < 0 or value > MAX_VALUE:
        raise InvalidTransaction(
            'Value must be an integer '
            'no less than {i} and no greater than {a}'.format(
                i=MIN_VALUE,
                a=MAX_VALUE))


def _get_state_data(name,to, context):
    states = [make_deth_address(name)]
    if to is not None:
        states.append(make_deth_address(to))
    state_entries = context.get_state(states)
    try:
        states = {}
        for entry in state_entries:
            state = cbor.loads(entry.data)
            LOGGER.debug('_get_state_data state=(%s)', state)
            for key, val in state.items():
                LOGGER.debug('_get_state_data add=%s', key)
                states[key] = val
        return states
    except IndexError:
        return {}
    except:
        LOGGER.debug('_get_state_data: Failed to load state data')
        raise InvalidTransaction('Failed to load state data')


def _set_state_data( state, context):
    new_states = {}
    for key,val in state.items():
        LOGGER.debug('_set_state_data  [%s]=%s', key, val)
        address = make_deth_address(key)
        encoded = cbor.dumps({key: val})
        new_states[address] = encoded

    addresses = context.set_state(new_states)
    if not addresses:
        raise InternalError('State error')



