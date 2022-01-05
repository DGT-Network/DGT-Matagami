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
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo

from dgt_signing import CryptoFactory,create_context

LOGGER = logging.getLogger(__name__)


VALID_VERBS = 'set', 'upd'

MIN_VALUE = 0
MAX_VALUE = 4294967295
MAX_NAME_LENGTH = 20

FAMILY_NAME = 'xcert'
FAMILY_VERSION = '1.0'
XCERT_ADDRESS_PREFIX = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]


def make_xcert_address(name):
    return XCERT_ADDRESS_PREFIX + hashlib.sha512(name.encode('utf-8')).hexdigest()[-64:]


class XcertTransactionHandler(TransactionHandler):
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
        LOGGER.info('XcertTransactionHandler init DONE')

    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return [FAMILY_VERSION]

    @property
    def namespaces(self):
        return [XCERT_ADDRESS_PREFIX]

    def apply(self, transaction, context):
        LOGGER.debug('apply:....\n')
        verb, owner, value  = _unpack_transaction(transaction)
        LOGGER.debug(f'apply:verb={verb} owner={owner} value={value}')
        try:
            state = _get_state_data(owner, context)

            updated_state = self._do_cert(verb, owner, value, state)
        except Exception as ex:
            raise InvalidTransaction(f'Xcert cmd={verb} error {ex}')

        _set_state_data( updated_state, context)

    def _do_cert(self,verb, owner, value, state):
        verbs = {
            'set': self._do_set,
            'upd': self._do_upd,
            
        }
        LOGGER.debug('_do_cert request....')
        try:
            return verbs[verb](owner, value, state)
        except KeyError:
            # This would be a programming error.
            raise InternalError('Unhandled verb: {}'.format(verb))


    def _do_set(self,owner, value, state):
        msg = 'Setting "{n}" to {v}'.format(n=owner, v=value)
        LOGGER.debug(msg)
        

        if owner in state:
            curr = state[owner]
            token = X509CertInfo()
            token.ParseFromString(curr)
            xcert = token.xcert
            raise InvalidTransaction('Xcert already exists: Name: {n}, Value {v} curr={t}'.format(n=owner,v=xcert,t=type(curr)))

        updated = {k: v for k, v in state.items()}
        
        try:
            token = X509CertInfo(
                             owner_key = owner, 
                             xcert = value
                )
            updated[owner] = token.SerializeToString()
            LOGGER.debug('_do_set updated=%s',updated)
        except Exception as ex:
            raise InvalidTransaction('Verb is "set" error:{}'.format(ex))
        return updated


    def _do_upd(self,owner, value, state):
        LOGGER.debug('Update "{n}" by {v}'.format(n=owner, v=value))

        if owner not in state:
            raise InvalidTransaction(
                'Undefined xcert name "{}" not in state'.format(owner))

        updated = {k: v for k, v in state.items()}                           
                                                                             
        try:                                                                 
            token = X509CertInfo(                                            
                             owner_key = owner,                              
                             xcert = value                                   
                )                                                            
            updated[owner] = token.SerializeToString()                       
            LOGGER.debug('_do_upd updated=%s',updated)                       
        except Exception as ex:                                              
            raise InvalidTransaction('Verb is "UPD" error:{}'.format(ex))    

        return updated

 

def _unpack_transaction(transaction):
    verb, owner, value = _decode_transaction(transaction)

    _validate_verb(verb)
    _validate_owner(owner)
    _validate_value(value)
    

    return verb, owner, value


def _decode_transaction(transaction):
    try:
        content = cbor.loads(transaction.payload)
    except:
        raise InvalidTransaction('Invalid payload serialization')

    LOGGER.debug('_decode_transaction content=%s',content)
    try:
        verb = content['Verb']
    except AttributeError:
        raise InvalidTransaction('Verb is required')

    try:
        owner = content['Owner']
    except AttributeError:
        raise InvalidTransaction('Owner is required')

    
    try:
        value = content['Value']
    except AttributeError:
        raise InvalidTransaction('Value is required')

    LOGGER.debug('_decode_transaction verb=%s',verb)    
    
    
    return verb, owner, value


def _validate_verb(verb):
    if verb not in VALID_VERBS:
        raise InvalidTransaction('Verb must be "set","upd"')

def _validate_owner(name):                                                                                        
    if not isinstance(name, str) :                                                 
        raise InvalidTransaction('Name must be a string')  


def _validate_value(value):

    if not isinstance(value, bytes):
        raise InvalidTransaction('Value must be an bytes ')


def _get_state_data(name, context):
    states = [make_xcert_address(name)]
    
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
        address = make_xcert_address(key)
        encoded = cbor.dumps({key: val})
        new_states[address] = encoded

    addresses = context.set_state(new_states)
    if not addresses:
        raise InternalError('State error')



