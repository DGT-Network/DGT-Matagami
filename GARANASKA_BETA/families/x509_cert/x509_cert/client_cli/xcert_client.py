# Copyright 2017 DGT NETWORK INC © Stanislav Parsov
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

import hashlib
import base64
import time
import random
import requests
import yaml
import cbor
import json
import logging
from dgt_signing import create_context
from dgt_signing import CryptoFactory
from dgt_signing import ParseError
from dgt_signing.core import (X509_COMMON_NAME, X509_USER_ID,X509_BUSINESS_CATEGORY,X509_SERIAL_NUMBER)

from dgt_sdk.protobuf.transaction_pb2 import TransactionHeader
from dgt_sdk.protobuf.transaction_pb2 import Transaction
from dgt_sdk.protobuf.batch_pb2 import BatchList
from dgt_sdk.protobuf.batch_pb2 import BatchHeader
from dgt_sdk.protobuf.batch_pb2 import Batch
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo

from x509_cert.client_cli.exceptions import XcertClientException,XcertClientKeyfileException
from x509_cert.client_cli.xcert_attr import *
LOGGER = logging.getLogger(__name__)

NOTARY_TYPES = [KEYKEEPER_ID,NOTARY_LEADER_ID,NOTARY_FOLOWER_ID,NOTARY_LIST_ID]


def _sha256(data):
    return hashlib.sha256(data).hexdigest()

def _sha512(data):                          
    return hashlib.sha512(data).hexdigest() 

def _get_prefix():                                             
    return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]                     
                                                                   
def _get_address(name):                                      
    prefix = _get_prefix()                                    
    game_address = _sha512(name.encode('utf-8'))[64:]              
    return prefix + game_address  
                                 
def _token_info(val):
    token = X509CertInfo()
    token.ParseFromString(val)
    return token

def write_conf(conf,fconf=NOTARY_CONF_NM):                     
    with open(fconf,"w") as vfile:                             
        try:                                                   
            vfile.write(json.dumps(conf,indent=2))             
            LOGGER.info(f"SAVE VCONF = {conf}")                
        except Exception as ex:                                
            LOGGER.info(f"CANT SAVE VCONF={fconf} err={ex}")   

def read_conf(fconf=NOTARY_CONF_NM):                                 
    try:                                                             
        with open(fconf,"r") as vfile:                               
            info =  json.load(vfile)                                 
                                                                     
    except Exception as ex:                                          
        LOGGER.info(f"CANT READ VCONF = {ex}")                       
        info = {}                                                    
    LOGGER.info(f"VCONF = {info}")                                   
    return info                                                      
                                                                     
def _make_xcert_transaction(signer, verb, name, value,to=None):                                                                                                                                
    val = {                                                                                                                                                                                  
        'Verb': verb,                                                                                                                                                                        
        'Owner': name,                                                                                                                                                                       
        'Value': value,                                                                                                                                                                      
    }                                                                                                                                                                                        
    if to is not None:                                                                                                                                                                       
        val['To'] = to                                                                                                                                                                       
    payload = cbor.dumps(val)                                                                                                                                                                
                                                                                                                                                                                             
    # Construct the address                                                                                                                                                                  
    address = _get_address(name)                                                                                                                                                        
    inputs = [address]                                                                                                                                                                       
    outputs = [address]                                                                                                                                                                      
    if to is not None:                                                                                                                                                                       
        address_to = _get_address(to)                                                                                                                                                   
        inputs.append(address_to)                                                                                                                                                            
        outputs.append(address_to)                                                                                                                                                           
                                                                                                                                                                                             
    header = TransactionHeader(                                                                                                                                                              
        signer_public_key=signer.get_public_key().as_hex(),                                                                                                                            
        family_name=FAMILY_NAME,                                                                                                                                                             
        family_version=FAMILY_VERSION,                                                                                                                                                       
        inputs=inputs,                                                                                                                                                                       
        outputs=outputs,                                                                                                                                                                     
        dependencies=[],                                                                                                                                                                     
        payload_sha512=_sha512(payload),                                                                                                                                                     
        batcher_public_key=signer.get_public_key().as_hex(),                                                                                                                           
        nonce=hex(random.randint(0, 2**64))                                                                                                                                                  
    ).SerializeToString()                                                                                                                                                                    
                                                                                                                                                                                             
    signature = signer.sign(header)                                                                                                                                                    
                                                                                                                                                                                             
    transaction = Transaction(                                                                                                                                                               
        header=header,                                                                                                                                                                       
        payload=payload,                                                                                                                                                                     
        header_signature=signature                                                                                                                                                           
    )                                                                                                                                                                                        
    return transaction                                                                                                                                                                       
                                                                     

                                                                     
def create_meta_xcert_txn(signer, key, value): 
    payload = cbor.dumps(value).hex()    
    info = {X509_COMMON_NAME:payload}
    xcert = signer.context.create_x509_certificate(info, signer.private_key, after=XCERT_AFTER_TM, before=XCERT_BEFORE_TM)

    transaction = _make_xcert_transaction(signer, XCERT_CRT_OP, key, xcert)
    return transaction                                                                                                  
                                                                     
                                                                     
                                                                     

class XcertClient:
    def __init__(self, url, keyfile=None,backend=None):
        self.url = url
        self._backend = backend
        #print(f"XcertClient: BACKEND={backend} ")
        self._context = create_context('secp256k1',backend=self._backend)
        if keyfile is not None:
            self._signer = self.get_signer(keyfile)
        else:
            self._private_key = None
            self._public_key = None
        

    def get_signer(self,keyfile):
        try:                                                                                          
            with open(keyfile) as fd:                                                                 
                private_key_str = fd.read().strip()                                                   
                fd.close()                                                                            
        except OSError as err:                                                                        
            raise XcertClientKeyfileException('Failed to read private key: {}'.format(str(err)))                                    
                                                                                                      
        try:                                                                                          
            self._private_key = self._context.from_hex(private_key_str) 
            self._public_key = self._context.get_public_key(self._private_key)                                          
        except ParseError as e:                                                                       
            raise XcertClientException('Unable to load private key: {}'.format(str(e)))               
                                                                                                      
        return CryptoFactory(self._context).new_signer(self._private_key)                                 


    def load_xcert(self,xcert_pem):
        xcert = self._signer.context.load_x509_certificate(xcert_pem)
        return xcert

    def get_xcert_attributes(self,xcert,attr):
        return self._signer.context.get_xcert_attributes(xcert,attr)

    def get_xcert_notary_attr(self,xcert):
        val = self.get_xcert_attributes(xcert,X509_COMMON_NAME)
        return cbor.loads(bytes.fromhex(val)) if val is not None else {}

    def xcert_to_dict(self,xcert,exclude=[X509_COMMON_NAME]):                                
        val = self._signer.context.xcert_to_dict(xcert,exclude)           
        return val  

    def get_pub_key(self,xcert):
        #
        return self._signer.context.get_pub_key(xcert)

    def is_notary_info(self,key):
        return key in NOTARY_TYPES

    def get_notary_info(self,key):
        value = self.show(key)    
        token = X509CertInfo()       
        token.ParseFromString(value) 
        xcert = self.load_xcert(token.xcert)
        val = self.get_xcert_notary_attr(xcert) 
        return val


    def set_or_upd(self,value,user,before,after):
        if isinstance(value,dict):
            info = value
        else:
            with open(value,"r") as cert_file:                                               
                try:                                                                         
                    info =  json.load(cert_file)                                             
                                                                                             
                except Exception as ex:                                                      
                    info = {}  
        
        try:
            signer = self.get_signer(user)
            pubkey = signer.get_public_key().as_hex() 
        except XcertClientKeyfileException:
            #use default key 
            signer = self._signer
            pubkey = user 
        if self.is_notary_info(pubkey):
            payload = cbor.dumps(info).hex()
            info = {X509_COMMON_NAME:payload}

        cert = signer.context.create_x509_certificate(info, signer.private_key, after=after, before=before)
        return pubkey,cert

    def _do_meta_xcert_transaction(self, oper,value,user,before=XCERT_BEFORE_TM,after=XCERT_AFTER_TM):
        pubkey,cert = self.set_or_upd(value,user,before,after)
        transaction = self._make_xcert_transaction(oper,pubkey, cert)
        return transaction

    def _do_oper(self,oper,value,user,before,after,wait=None):                                    
        pubkey,cert = self.set_or_upd(value,user,before,after)                          
        print(f'{oper} cert={cert} pub={pubkey} valid={before}/{after}')                   
        return self._send_transaction(oper,pubkey, cert, to=None, wait=wait,user=user) 

    def set(self,value,user,before,after,wait=None):
        return self._do_oper(XCERT_SET_OP,value,user,before,after, wait=wait)

    def upd(self,value,user,before,after, wait=None):
        return self._do_oper(XCERT_UPD_OP,value,user,before,after, wait=wait)      

    def crt(self,value,user,before,after, wait=None):  
        return self._do_oper(XCERT_CRT_OP,value,user,before,after, wait=wait)                                   
        

    def list(self):
        result = self._send_request("state?address={}".format(self._get_prefix()))

        try:
            encoded_entries = yaml.safe_load(result)["data"]

            return [
                cbor.loads(base64.b64decode(entry["data"]))
                for entry in encoded_entries
            ]

        except BaseException:
            return None

    def show(self, name):
        address = self._get_address(name)
        
        try:
            result = self._send_request("state/{}".format(address), name=name,)
        except XcertClientException:
            return None

        try:
            return cbor.loads(base64.b64decode(yaml.safe_load(result)["data"]))[name]

        except BaseException:
            return None

    def _get_status(self, batch_id, wait):
        try:
            result = self._send_request('batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise XcertClientException(err)

    def _get_prefix(self):
        return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]

    def _get_address(self, name):
        prefix = self._get_prefix()
        game_address = _sha512(name.encode('utf-8'))[64:]
        return prefix + game_address

    def _send_request(self, suffix, data=None, content_type=None, name=None,rest_url=None):
        rest_url = rest_url if rest_url else self.url
        if rest_url.startswith("http://"):
            url = "{}/{}".format(rest_url, suffix)
        else:
            url = "http://{}/{}".format(rest_url, suffix)

        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type
        #print('_send_request',url)
        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)
                

            if result.status_code == 404:
                raise XcertClientException("No such key: {}".format(name))

            elif not result.ok:
                raise XcertClientException("Error {}: {}".format(result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise XcertClientException('Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise XcertClientException(err)

        return result.text

    def _make_xcert_transaction(self, verb, name, value,to=None):
        val = {                                                                                                  
            'Verb': verb,                                                                                        
            'Owner': name,                                                                                       
            'Value': value,                                                                                      
        }    
        if to is not None:         
            val['To'] = to                                                                                                             
        payload = cbor.dumps(val)                                                                                
                                                                                                                 
        # Construct the address                                                                                  
        address = self._get_address(name)                                                                        
        inputs = [address]                                                                                       
        outputs = [address]  
        # add key notary list
        inputs.append(self._get_address(NOTARY_LIST_ID))                                                                                    
        if to is not None:                                                                                       
            address_to = self._get_address(to)                                                                   
            inputs.append(address_to)                                                                            
            outputs.append(address_to)                                                                           
                                                                                                                 
        header = TransactionHeader(                                                                              
            signer_public_key=self._signer.get_public_key().as_hex(),                                            
            family_name=FAMILY_NAME,                                                                             
            family_version=FAMILY_VERSION,                                                                       
            inputs=inputs,                                                                                       
            outputs=outputs,                                                                                     
            dependencies=[],                                                                                     
            payload_sha512=_sha512(payload),                                                                     
            batcher_public_key=self._signer.get_public_key().as_hex(),                                           
            nonce=hex(random.randint(0, 2**64))                                                                  
        ).SerializeToString()                                                                                    
                                                                                                                 
        signature = self._signer.sign(header)                                                                    
                                                                                                                 
        transaction = Transaction(                                                                               
            header=header,                                                                                       
            payload=payload,                                                                                     
            header_signature=signature                                                                           
        )                                                                                                        
        return transaction


    def _send_transaction(self, verb, name, value, to=None, wait=None,user='anybody'):
        # 'set',pubkey, cert, to=None, wait=wait,user=user)
        transaction = self._make_xcert_transaction(verb,name,value)
        batch_list = self._create_batch_list([transaction])
        batch_id = batch_list.batches[0].header_signature

        if wait and wait > 0:
            wait_time = 0
            start_time = time.time()
            response = self._send_request(
                "batches", batch_list.SerializeToString(),
                'application/octet-stream',
            )
            while wait_time < wait:
                status = self._get_status(
                    batch_id,
                    wait - int(wait_time),
                )
                wait_time = time.time() - start_time

                if status != 'PENDING':
                    return (status,batch_id) # response

            return (status,batch_id) #return response

        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
        )

    def _create_batch_list(self, transactions):
        transaction_signatures = [t.header_signature for t in transactions]

        header = BatchHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            transaction_ids=transaction_signatures
        ).SerializeToString()

        signature = self._signer.sign(header)

        batch = Batch(
            header=header,
            transactions=transactions,
            header_signature=signature,
            timestamp=int(time.time()))
        return BatchList(batches=[batch])
