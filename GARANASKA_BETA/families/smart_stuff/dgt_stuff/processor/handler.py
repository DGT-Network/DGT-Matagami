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
from stuff_common.protobuf.smart_stuff_token_pb2 import StuffTokenInfo

from dgt_signing import CryptoFactory,create_context

LOGGER = logging.getLogger(__name__)


VALID_VERBS = 'set', 'upd'

MIN_VALUE = 0
MAX_VALUE = 4294967295
MAX_NAME_LENGTH = 20

FAMILY_NAME = 'stuff'

STUFF_ADDRESS_PREFIX = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]


def make_stuff_address(name):
    return STUFF_ADDRESS_PREFIX + hashlib.sha512(name.encode('utf-8')).hexdigest()[-64:]


class StuffTransactionHandler(TransactionHandler):
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
        LOGGER.info('StuffTransactionHandler init DONE')

    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [STUFF_ADDRESS_PREFIX]

    def apply(self, transaction, context):
        LOGGER.debug('apply:....\n')
        verb, name, value, user = _unpack_transaction(transaction)
        LOGGER.debug('apply:verb=%s name=%s value=%s user=%s',verb, name, value, user)
        state = _get_state_data(name, context)

        updated_state = self._do_stuff(verb, name, value, user, state)

        _set_state_data( updated_state, context)

    def _do_stuff(self,verb, name, value, user, state):
        verbs = {
            'set': self._do_set,
            'upd': self._do_upd,
            
        }
        LOGGER.debug('_do_stuff request....')
        try:
            return verbs[verb](name, value,user, state)
        except KeyError:
            # This would be a programming error.
            raise InternalError('Unhandled verb: {}'.format(verb))


    def _do_set(self,name, value, user, state):
        msg = 'Setting "{n}" to {v}'.format(n=name, v=value)
        LOGGER.debug(msg)
        

        if name in state:
            curr = state[name]
            token = StuffTokenInfo()
            token.ParseFromString(curr)
            stuff = cbor.loads(token.stuff)
            raise InvalidTransaction('Stuff already exists: Name: {n}, Value {v}'.format(n=name,v=stuff))

        updated = {k: v for k, v in state.items()}
        
        try:
            token = StuffTokenInfo(group_code = 'STUFF_token',
                             owner_key = self._signer.sign('STUFF_token'.encode()), 
                             sign = self._public_key.as_hex(),
                             user = user,
                             stuff = cbor.dumps(value)
                )
            updated[name] = token.SerializeToString()
            LOGGER.debug('_do_set updated=%s',updated)
        except Exception as ex:
            raise InvalidTransaction('Verb is "set" error:{}'.format(ex))
        return updated


    def _do_upd(self,name, value, user, state):
        msg = 'Update "{n}" by {v}'.format(n=name, v=value)
        LOGGER.debug(msg)

        if name not in state:
            raise InvalidTransaction(
                'Undefined stuff name "{}" not in state'.format(name))

        curr = state[name]
        token = StuffTokenInfo()
        token.ParseFromString(curr)
        stuff = cbor.loads(token.stuff)
        LOGGER.debug('_do_upd token[%s]=%s',token.group_code,stuff) # token.decimals
        num = 0
        for attr,val in value.items():
            if attr in stuff:
                stuff[attr] = val # update stuff attribute
                num += 1

        #incd = token.decimals + int(value['value'])
        
        if num == 0:
            raise InvalidTransaction('Verb is "upd", but there are not updated attributes')
        
        updated = {k: v for k, v in state.items()}
        token.user = user
        try:
            token.stuff = cbor.dumps(stuff)
            updated[name] = token.SerializeToString() 
        except Exception as ex:
            raise InvalidTransaction('Verb is "upd" error:{}'.format(ex))

        return updated

 

def _unpack_transaction(transaction):
    verb, name, value, user = _decode_transaction(transaction)

    _validate_verb(verb)
    _validate_name(name)
    _validate_value(value)
    

    return verb, name, value, user


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
        name = content['Name']
    except AttributeError:
        raise InvalidTransaction('Name is required')

    try:
        user = content['User']
    except AttributeError:
        raise InvalidTransaction('User is required')

    try:
        value = content['Value']
    except AttributeError:
        raise InvalidTransaction('Value is required')

    LOGGER.debug('_decode_transaction verb=%s',verb)    
    
    
    return verb, name, value, user


def _validate_verb(verb):
    if verb not in VALID_VERBS:
        raise InvalidTransaction('Verb must be "set","upd"')


def _validate_name(name):
    if not isinstance(name, str) or len(name) > MAX_NAME_LENGTH:
        raise InvalidTransaction('Name must be a string of no more than {} characters'.format(MAX_NAME_LENGTH))


def _validate_value(value):

    if not isinstance(value, dict):
        raise InvalidTransaction('Value must be an dict ')


def _get_state_data(name, context):
    states = [make_stuff_address(name)]
    
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
        address = make_stuff_address(key)
        encoded = cbor.dumps({key: val})
        new_states[address] = encoded

    addresses = context.set_state(new_states)
    if not addresses:
        raise InternalError('State error')



