# Copyright 2018 NTRLab
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
import cbor
import json


from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from smart_bgt.processor.utils  import FAMILY_NAME,FAMILY_VER,make_smart_bgt_address,SMART_BGT_ADDRESS_PREFIX
from smart_bgt.processor.services import BGXlistener
from smart_bgt.processor.services import BGXwallet
from smart_bgt.processor.crypto import BGXCrypto
from smart_bgt.processor.token import Token
from smart_bgt.processor.token import MetaToken
from smart_bgt.processor.emission import EmissionMechanism


LOGGER = logging.getLogger(__name__)
BGX_EPSILON = 0.000000000001


class SmartBgtTransactionHandler(TransactionHandler):
    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return [FAMILY_VER]

    @property
    def namespaces(self):
        return [SMART_BGT_ADDRESS_PREFIX]

    def apply(self, transaction, context):
        verb, args = _unpack_transaction(transaction)
        LOGGER.info('SmartBgtTransactionHandler verb=%s args %s', verb, args)
        try:
            if verb == 'generate_key':
                state = ''
            elif verb == 'balance_of':
                state = _get_state_data([args['addr']], context)
            elif verb == 'total_supply':
                state = _get_state_data([args['token_name']], context)
            elif verb == 'init':
                private_key = args['private_key']
                digital_signature = BGXCrypto.DigitalSignature(private_key)
                open_key = digital_signature.getVerifyingKey()
                state = _get_state_data([args['Name'], open_key], context)
            elif verb == 'transfer':
                state = _get_state_data([args['Name'], args['to_addr']], context)
            else:
                state = _get_state_data([args['Name']], context)

            try:
                updated_state = _do_smart_bgt(verb, args, state)
            except InvalidTransaction as exc:
                if not (verb == 'generate_key' or verb == 'balance_of' or verb == 'total_supply'):
                    _set_state_data(state, context)
                raise exc

            if not (verb == 'generate_key' or verb == 'balance_of' or verb == 'total_supply'):
                _set_state_data(updated_state, context)
        except AttributeError:
            raise InvalidTransaction('Args are required')


def _unpack_transaction(transaction):
    return  _decode_transaction(transaction)


def _decode_transaction(transaction):
    try:
        content = cbor.loads(transaction.payload)
    except:
        raise InvalidTransaction('Invalid payload serialization')
    try:
        verb = content['Verb']
    except AttributeError:
        raise InvalidTransaction('Verb is required')

    return verb, content


def _get_state_data(names, context):
    LOGGER.debug("SMART_BGT>processor>handler>_get_state_data"
                 "\nnames=%s\ncontext=%s",
                 names, context)

    alist = []
    for name in names:
        address = make_smart_bgt_address(name)
        alist.append(address)
    state_entries = context.get_state(alist)

    LOGGER.debug('_get_state_data state_entries=%s', state_entries)
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


def _set_state_data(state, context):
    LOGGER.debug("SMART_BGT>processor>handler>_set_state_data"
                 "\nstate=%s\ncontext=%s",
                 state, context)

    new_states = {}
    for key,val in state.items():
        LOGGER.debug('_set_state_data  [%s]=%s', key, val)
        address = make_smart_bgt_address(key)
        encoded = cbor.dumps({key: val})
        new_states[address] = encoded

    addresses = context.set_state(new_states)

    if not addresses:
        LOGGER.debug('_set_state_data  State error')
        raise InternalError('State error')
    LOGGER.debug('_set_state_data  DONE address=%s', address)


def _do_smart_bgt(verb, args, state):
    LOGGER.debug('_do_smart_bgt request verb=%s', verb)

    try:
        if verb == 'init':
            return _do_init(args, state)
        elif verb == 'generate_key':
            return _do_generate_key(state)
        elif verb == 'transfer':
            return _do_transfer(args, state)
        elif verb == 'allowance':
            return _do_allowance(args, state)
        elif verb == 'balance_of':
            return _get_balance_of(args, state)
        elif verb == 'total_supply':
            return _get_total_supply(args, state)
    except KeyError:
        # This would be a programming error.
        raise InternalError('Unhandled verb: {}'.format(verb))


def _do_generate_key(state):
    digital_signature = BGXCrypto.DigitalSignature()
    private_key = digital_signature.getSigningKey()
    LOGGER.debug("New private key generated: " + str(private_key))
    updated = {k: v for k, v in state.items()}
    return updated


def _do_init(args, state):
    LOGGER.debug("_do_init ...")
    try:
        full_name  = args['Name']
        private_key = args['private_key']
        ethereum_address = args['ethereum_address']
        num_bgt = int(args['num_bgt'])
        bgt_price = int(args['bgt_price'])
        dec_price = int(args['dec_price'])
    except KeyError:
        msg = "_do_init not all args"
        LOGGER.debug(msg)
        return updated
    except ValueError as err:
        LOGGER.debug("args err=%s",err)
        return updated

    updated = {k: v for k, v in state.items()}
    digital_signature = BGXCrypto.DigitalSignature(private_key)
    emission_mechanism = EmissionMechanism()
    open_key = digital_signature.getVerifyingKey()

    wallet = BGXwallet()
    if open_key in state:
        wallet_str = state[open_key]
        wallet.fromJSON(wallet_str)

    if full_name in state:
        LOGGER.debug("This type of tokens already exists. Updating..")
        meta_str = state[full_name]
        meta = MetaToken()
        meta.fromJSON(meta_str)
        old_price = meta.get_internal_token_price()
        owner = meta.get_owner_key()
        group_code = meta.get_group_code()

        if abs(old_price - bgt_price) > BGX_EPSILON or owner != open_key:
            LOGGER.debug("Old price and new one are different OR wrong public key")
            return updated

        token = None

        if open_key in state:
            token = wallet.strictly_get_token(group_code)

        token, meta = emission_mechanism.releaseExtraTokens(token, meta, digital_signature, \
                                                            ethereum_address, num_bgt, bgt_price, dec_price)
    else:
        LOGGER.debug("Creating new type of tokens..")
        symbol = 'BGT'
        company_id = 'company_id'
        description = 'BGT token'
        token, meta = emission_mechanism.releaseTokens(full_name, symbol, company_id, digital_signature, \
                                                       ethereum_address, num_bgt, description, bgt_price, dec_price)

    if token is None or meta is None:
        LOGGER.debug("Emission failed: not enough money")
        return updated

    wallet.append(token)
    updated[full_name] = str(meta.toJSON())
    updated[open_key] = str(wallet.toJSON())
    LOGGER.debug("Init - ready! updated=%s", updated)
    return updated


def _do_transfer(args, state):
    LOGGER.debug("_do_transfer ...")
    updated = {k: v for k, v in state.items()}

    try:
        from_addr = args['Name']
        to_addr = args['to_addr']
        num_bgt = float(args['num_bgt'])
        group_id = args['group_id']
    except KeyError:
        msg = "_do_transfer not all args"
        LOGGER.debug(msg)
        return updated
    except ValueError as err:
        LOGGER.debug("args err=%s",err)
        return updated

    LOGGER.debug("SMART_BGT>processor>handler>_do_transfer"
                 "\nfrom_addr=%s\nto_addr=%s\nnum_bgt=%s\ngroup_id=%s",
                 from_addr, to_addr, num_bgt, group_id)

    if from_addr not in state:
        LOGGER.debug("Sending tokens - address %s not registered", from_addr)
        raise InvalidTransaction('Verb is "transfer" but name "{}" not in state'.format(from_addr))

    from_wallet_str = state[from_addr]
    LOGGER.debug("SMART_BGT>processor>handler>_do_transfer"
                 "\nfrom_wallet_str=%s",
                 from_wallet_str)
    from_wallet = BGXwallet()
    from_wallet.fromJSON(from_wallet_str)
    from_token = from_wallet.get_token(group_id)

    to_token = Token()
    to_wallet = BGXwallet()
    if to_addr in state:
        LOGGER.debug("SMART_BGT>processor>handler>_do_transfer"
                     "\nto_addr is in state")
        to_wallet_str = state[to_addr]
        to_wallet.fromJSON(to_wallet_str)
        to_token = to_wallet.get_token(group_id)

    to_token.copy(from_token)
    res = from_token.send(to_token, num_bgt)
    LOGGER.debug("Sending tokens - result = %s", str(res))

    if not res:
        LOGGER.debug("Sending tokens - not enough money")
        raise InvalidTransaction('Unhandled action (not enough money)')
    else:
        from_wallet.append(from_token)
        to_wallet.append(to_token)
        updated[from_addr] = str(from_wallet.toJSON())
        updated[to_addr] = str(to_wallet.toJSON())

    LOGGER.debug("Transfer - ready! updated=%s", updated)
    return updated


def _do_allowance(args, state):
    LOGGER.debug("_do_allowance ...")
    try:
        from_addr = args['Name']
        num_bgt = float(args['num_bgt'])
        group_id = args['group_id']
    except KeyError:
        msg = "_do_allowance not all arg"
        LOGGER.debug(msg)
        raise InvalidTransaction(msg)
    except ValueError as err:
        LOGGER.debug("args err=%s",err)
        raise InvalidTransaction("_do_allowance arg value error")

    if from_addr not in state:
        LOGGER.debug("allowance - address %s not registered", from_addr)
        return state

    from_wallet_str = state[from_addr]
    from_wallet = BGXwallet()
    from_wallet.fromJSON(from_wallet_str)
    from_token = from_wallet.get_token(group_id)

    res = from_token.send_allowance(num_bgt)
    LOGGER.debug("allowance - result = %s", str(res))
    return state


def _get_balance_of(args, state):
    LOGGER.debug("_get_balance_of ...")
    try:
        addr = args['addr']
    except KeyError:
        msg = "_get_balance_of not all arg"
        LOGGER.debug(msg)
        raise InvalidTransaction(msg)
    except ValueError as err:
        LOGGER.debug("args err=%s",err)
        raise InvalidTransaction("_do_allowance arg value error")

    if addr not in state:
        LOGGER.debug("_get_balance_of - address %s not registered", addr)
        return state

    wallet_str = state[addr]
    wallet = BGXwallet()
    wallet.fromJSON(wallet_str)
    balance = wallet.get_balance()
    LOGGER.debug("_get_balance_of - address %s balance = %s", addr, str(balance))
    return state


def _get_total_supply(args, state):
    LOGGER.debug("_get_total_supply ...")
    try:
        addr = args['token_name']
    except KeyError:
        msg = "_get_total_supply not all arg"
        LOGGER.debug(msg)
        raise InternalError(msg)
    except ValueError as err:
        LOGGER.debug("args err=%s",err)
        raise InvalidTransaction("_do_allowance arg value error")

    if addr not in state:
        LOGGER.debug("_get_total_supply - metatoken %s not registered", addr)
        return state

    meta_token_str = state[addr]
    meta_token = MetaToken()
    meta_token.fromJSON(meta_token_str)
    balance = meta_token.get_total_supply()
    LOGGER.debug("_get_total_supply - total supply of %s = %s", addr, str(balance))
    return state
