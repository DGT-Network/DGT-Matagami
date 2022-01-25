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
from bgt_common.protobuf.smart_bgt_token_pb2 import BgtTokenInfo
from dgt_signing import CryptoFactory,create_context

LOGGER = logging.getLogger(__name__)


VALID_VERBS = 'set', 'inc', 'dec','trans'

MIN_VALUE = 0
MAX_VALUE = 4294967295
MAX_NAME_LENGTH = 20

FAMILY_NAME = 'bgt'

BGT_ADDRESS_PREFIX = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]

def make_bgt_prefix():
    return hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]

def make_bgt_address(name):
    return BGT_ADDRESS_PREFIX + hashlib.sha512(name.encode('utf-8')).hexdigest()[-64:]


class BgtTransactionHandler(TransactionHandler):
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
        LOGGER.info('BgtTransactionHandler init DONE PREF=%s',BGT_ADDRESS_PREFIX)

    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [BGT_ADDRESS_PREFIX]

    def apply(self, transaction, context):
        LOGGER.debug('apply:....\n')
        verb, name, value, to = _unpack_transaction(transaction)
        LOGGER.debug('apply:verb=%s name=%s value=%s to=%s',verb, name, value, to)
        state = _get_state_data(name,to, context)

        updated_state = self._do_bgt(verb, name, value, to, state)

        _set_state_data( updated_state, context)

    def _do_bgt(self,verb, name, value, to, state):
        verbs = {
            'set': self._do_set,
            'inc': self._do_inc,
            'dec': self._do_dec,
            'trans': self._do_trans,
        }
        LOGGER.debug('_do_bgt request....')
        try:
            return verbs[verb](name, value,to, state)
        except KeyError:
            # This would be a programming error.
            raise InternalError('Unhandled verb: {}'.format(verb))


    def _do_set(self,name, value, to, state):
        msg = 'Setting "{n}" to {v}'.format(n=name, v=value)
        LOGGER.debug(msg)
        

        if name in state:
            raise InvalidTransaction('Verb is "set", but already exists: Name: {n}, Value {v}'.format(n=name,v=state[name]))

        updated = {k: v for k, v in state.items()}
        #owner_key = self._context.sign('BGT_token'.encode(),self._private_key)
        token = BgtTokenInfo(group_code = 'BGT_token',
                             owner_key = self._signer.sign('BGT_token'.encode()), #owner_key,
                             sign = self._public_key.as_hex(),
                             decimals = int(value)
                )
        updated[name] = token.SerializeToString()
        LOGGER.debug('_do_set updated=%s',updated)
        return updated


    def _do_inc(self,name, value, to, state):
        msg = 'Incrementing "{n}" by {v}'.format(n=name, v=value)
        LOGGER.debug(msg)

        if name not in state:
            raise InvalidTransaction(
                'Verb is "inc" but name "{}" not in state'.format(name))

        curr = state[name]
        token = BgtTokenInfo()
        token.ParseFromString(curr)
        LOGGER.debug('_do_inc token[%s]=%s',token.group_code,value) # token.decimals
        incd = token.decimals + value

        if incd > MAX_VALUE:
            raise InvalidTransaction(
                'Verb is "inc", but result would be greater than {}'.format(MAX_VALUE))

        updated = {k: v for k, v in state.items()}
        token.decimals = incd
        updated[name] = token.SerializeToString() 

        return updated


    def _do_dec(self,name, value, to, state):
        msg = 'Decrementing "{n}" by {v}'.format(n=name, v=value)
        LOGGER.debug(msg)

        if name not in state:
            raise InvalidTransaction(
                'Verb is "dec" but name "{}" not in state'.format(name))

        curr = state[name]
        token = BgtTokenInfo()
        token.ParseFromString(curr)
        LOGGER.debug('_do_dec token[%s]=%s',token.group_code,token.decimals,value)
        decd = token.decimals - value

        if decd < MIN_VALUE:
            raise InvalidTransaction(
                'Verb is "dec", but result would be less than {}'.format(
                    MIN_VALUE))

        updated = {k: v for k, v in state.items()}
        token.decimals = decd
        updated[name] = token.SerializeToString()

        return updated

    def _do_trans(self,vfrom, value, vto, state):
        msg = 'transfer "{n}"->"{t}" by {v}'.format(n=vfrom,t=vto, v=value)
        LOGGER.debug(msg)

        if vfrom not in state or vto not in state:
            raise InvalidTransaction(
                'Verb is "trans" but vallet "{}" or vallet "{}" not in state'.format(vfrom,vto))

        curr = state[vfrom]
        token = BgtTokenInfo()
        token.ParseFromString(curr)
        to = state[vto]
        token1 = BgtTokenInfo()
        token1.ParseFromString(to)
        LOGGER.debug('_do_tans token[%s]=%s',token.group_code,value) 
        decd = token.decimals - value
        if decd < MIN_VALUE:
            raise InvalidTransaction('Verb is "trans", but result would be less than {}'.format(MIN_VALUE))
        incd = token1.decimals + value
        if incd >  MAX_VALUE:
            raise InvalidTransaction('Verb is "inc", but result would be greater than {}'.format(MAX_VALUE))

        updated = {k: v for k, v in state.items()}
        token.decimals = decd
        updated[vfrom] = token.SerializeToString()
        token1.decimals = incd
        updated[vto] = token1.SerializeToString() 

        return updated
        

def _unpack_transaction(transaction):
    verb, name, value, to = _decode_transaction(transaction)

    _validate_verb(verb)
    _validate_name(name)
    _validate_value(value)
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

    LOGGER.debug('_decode_transaction verb=%s',verb)    
    if verb == 'trans' :
        if 'To' not in content :
            raise InvalidTransaction('To is required')
        to = content['To']
    else:
        to = None
    
    return verb, name, value, to


def _validate_verb(verb):
    if verb not in VALID_VERBS:
        raise InvalidTransaction('Verb must be "set","trans", "inc", or "dec"')


def _validate_name(name):
    if not isinstance(name, str) or len(name) > MAX_NAME_LENGTH:
        raise InvalidTransaction('Name must be a string of no more than {} characters'.format(MAX_NAME_LENGTH))


def _validate_value(value):
    if not isinstance(value, int) or value < 0 or value > MAX_VALUE:
        raise InvalidTransaction(
            'Value must be an integer '
            'no less than {i} and no greater than {a}'.format(
                i=MIN_VALUE,
                a=MAX_VALUE))


def _get_state_data(name,to, context):
    states = [make_bgt_address(name)]
    if to is not None:
        states.append(make_bgt_address(to))
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
        address = make_bgt_address(key)
        encoded = cbor.dumps({key: val})
        new_states[address] = encoded

    addresses = context.set_state(new_states)
    if not addresses:
        raise InternalError('State error')



