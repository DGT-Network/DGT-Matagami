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
from dgt_sdk.protobuf.transaction_pb2 import TransactionHeader
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo

from dgt_signing import CryptoFactory,create_context
from dgt_signing.core import X509_COMMON_NAME
from x509_cert.client_cli.xcert_attr import *
from x509_cert.xcert_addr_util import make_xcert_address,XCERT_ADDRESS_PREFIX

LOGGER = logging.getLogger(__name__)


VALID_VERBS = XCERT_SET_OP, XCERT_UPD_OP, XCERT_CRT_OP

MIN_VALUE = 0
MAX_VALUE = 4294967295
MAX_NAME_LENGTH = 20
CERT_MARKER = '-----BEGIN CERTIFICATE-----\n'

class XcertTransactionHandler(TransactionHandler):
    def __init__(self):
        self._context = create_context('secp256k1') 
        LOGGER.debug('_do_set: context')
        self._private_key = self._context.new_random()
        LOGGER.debug('_do_set: context private_key=%s',self._private_key.as_hex())
        self._public_key = self._context.get_public_key(self._private_key)
        crypto_factory = CryptoFactory(self._context)
        self._signer = crypto_factory.new_signer(self._private_key)
        self._trans_signer_key = None
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

    def _get_trans_signer(self,transaction): 
        self._trans_signer_key = transaction.header.signer_public_key                                                                               
        LOGGER.debug('_transaction signer={}'.format(self._trans_signer_key))             

    def _get_xcert_value(self,value):
        try:                                                                  
            sval = cbor.loads(value)                                          
            LOGGER.debug('extract data - "{}"'.format(sval))                  
            xvalue = bytes.fromhex(sval[XCERT_PAYLOAD][XCERT_ATTR])           
        except Exception as ex:                                               
            LOGGER.debug('set cant extract data - "{}"'.format(ex))           
            xvalue = value 
        return xvalue                                                   

    def apply(self, transaction, context):
        """
        transaction = message TpProcessRequest {
            TransactionHeader header = 1;  // The transaction header
            bytes payload = 2;  // The transaction payload
            string signature = 3;  // The transaction header_signature
            string context_id = 4; // The context_id for state requests.
        }
        """
        LOGGER.debug('apply: trans={}...\n'.format(type(transaction)))
        self._get_trans_signer(transaction)
        verb, owner, value  = _unpack_transaction(transaction)
        LOGGER.debug('apply:verb={} owner={} value={}'.format(verb,owner,value))
        
        try:
            state = _get_state_data(owner, context)
            if owner != NOTARY_LIST_ID:
                slist = _get_state_data(NOTARY_LIST_ID, context)
                is_notary = self.check_notary_key(NOTARY_LIST_ID,slist)
                if not is_notary:
                    raise InvalidTransaction('Xcert cmd={verb} error - NOT AUTHORIZED NOTARY!!!'.format(verb))
                #LOGGER.debug('apply: NOTARY {}\n'.format(is_notary))

            updated_state = self._do_cert(verb, owner, value, state)
        except Exception as ex:
            raise InvalidTransaction('Xcert cmd={} error {}'.format(verb,ex))

        _set_state_data( updated_state, context)

    def get_xcert_pem(self,key,state):
        if key in state:             
            curr = state[key]                    
            token = X509CertInfo()                 
            token.ParseFromString(curr)            
            xcert = token.xcert  
            return xcert    
                      
    def get_xcert(self,key,state):
        xcert_pem = self.get_xcert_pem(key,state)
        xcert = self._signer.context.load_x509_certificate(xcert_pem)
        return xcert

    def get_meta_xcert(self,xcert):                                                 
        #xcert = self.get_xcert(key,state)                                  
        val = self.get_xcert_attributes(xcert,X509_COMMON_NAME)          
        return cbor.loads(bytes.fromhex(val)) if val is not None else {}
         
    def get_xcert_attributes(self,xcert,attr):                       
        return self._signer.context.get_xcert_attributes(xcert,attr) 

    def check_notary_key(self,key,state):
        xcert = self.get_xcert(key,state)
        mcert = self.get_meta_xcert(xcert)
        nkey = self._signer.context.get_pub_key(xcert)
        if NOTARY_KEYS in mcert:
            nlist = mcert[NOTARY_KEYS]
            LOGGER.debug('apply: KEY={} NOTARY_LIST={}\n'.format(nkey,nlist))
            return nkey in nlist
        return False

    def _do_cert(self,verb, owner, value, state):
        verbs = {
            XCERT_SET_OP: self._do_set,
            XCERT_UPD_OP: self._do_upd,
            XCERT_CRT_OP: self._do_crt,
            
        }
        LOGGER.debug('_do_cert request....')
        try:
            return verbs[verb](owner, value, state)
        except KeyError:
            # This would be a programming error.
            raise InternalError('Unhandled verb: {}'.format(verb))

    def _do_crt(self,owner, value, state):
        return self._do_set(owner,value,state,crt=True)


    def _do_set(self,owner, value, state,crt=False):

        LOGGER.debug('Setting "{}" to {}'.format(owner,value))
        """
        check owner key - in notary mode it shoud be from static list of notary
        TODO
        """

        if owner in state and not crt:
            curr = state[owner]
            token = X509CertInfo()
            token.ParseFromString(curr)
            xcert = token.xcert
            # public_key should be key one of the notary
            #public_key = xcert.public_key()
            raise InvalidTransaction('Xcert already exists: Name: {n}, Value {v} curr={t}'.format(n=owner,v=xcert,t=type(curr)))

        updated = {k: v for k, v in state.items()}

        xvalue = self._get_xcert_value(value)
        try:
            token = X509CertInfo(
                             owner_key = owner, 
                             xcert = xvalue
                )
            updated[owner] = token.SerializeToString()
            LOGGER.debug('_do_set updated=%s',updated)
        except Exception as ex:
            raise InvalidTransaction('Verb is "set" error:{}'.format(ex))
        return updated


    def _do_upd(self,owner, value, state):
        LOGGER.debug('Update "{n}" by {v}'.format(n=owner, v=value))

        if owner not in state:
            raise InvalidTransaction('Undefined xcert name "{}" not in state'.format(owner))

        updated = {k: v for k, v in state.items()}                           
        xvalue = self._get_xcert_value(value)                                                                     
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
            #LOGGER.debug('_get_state_data state=(%s)', state)
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



