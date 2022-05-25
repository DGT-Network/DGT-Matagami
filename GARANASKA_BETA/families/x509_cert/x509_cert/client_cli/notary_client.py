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
from x509_cert.client_cli.xcert_client import XcertClient,_sha512

try:                                                            
    from x509_cert.client_cli.vault import Vault  
except Exception as ex:   
    print(f'Cant load Vault - {ex}')                                      
    Vault = None                                          

LOGGER = logging.getLogger(__name__)

NOTARY_TYPES = [KEYKEEPER_ID,NOTARY_LEADER_ID,NOTARY_FOLOWER_ID,NOTARY_LIST_ID]


                                                                     

class NotaryClient(XcertClient):
    def __init__(self, url, keyfile=None,backend=None,vault_url=None,notary=None,lead_addr=None):
        """
        url - dgt rest-api
        keyfile -key file for sign sertificate
        backend 
        """
        super().__init__(url,keyfile=keyfile,backend=backend)
        self._vault = None
        if Vault:
            if vault_url is None:
                # client mode 
                ninfo = self.get_notary_info(NOTARY_LEADER_ID)
                print(f'notary info={ninfo}')
                if NOTARY_TOKEN in ninfo and NOTARY_URL in ninfo:
                    self._vault = Vault(ninfo[NOTARY_URL],token=ninfo[NOTARY_TOKEN])
                else:
                    print('Cant get notary info')
                    
                    
            else:
                # init mode                                                      
                self._vault = Vault(vault_url,notary=notary,lead_addr=lead_addr) 
        
        

    def get_xcert_notary_attr(self,xcert):
        val = self.get_xcert_attributes(xcert,X509_COMMON_NAME)
        return cbor.loads(bytes.fromhex(val)) if val is not None else {}

    def is_notary_info(self,key):
        return key in NOTARY_TYPES

    def get_notary_info(self,key):
        value = self.show(key)    
        token = X509CertInfo()       
        token.ParseFromString(value) 
        xcert = self.load_xcert(token.xcert)
        val = self.get_xcert_notary_attr(xcert) 
        return val

    def init(self,name,wait=None):
        # Notary init
        
        if self._vault:
            print(f'INIT NOTARY={name}')
            
            _meta_xcert = self._vault.init()
            key = _meta_xcert[0]
            if key:
                info = _meta_xcert[1]
                if _meta_xcert[2]:                                                               
                    response = self.set(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM) 
                else:                                                                  
                    response = self.crt(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM)
                print(f'INIT NOTARY={name} key={key} info={info} response={response}') 




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
        return pubkey,cert,info

    def _do_oper(self,oper,value,user,before,after,wait=None):
        pubkey,cert,info = self.set_or_upd(value,user,before,after)
        if self._vault and not self.is_notary_info(pubkey):
            if oper == XCERT_SET_OP :
                try:
                    val = self._vault.get_xcert(pubkey)
                    print(f'Certificate for {pubkey} already exist')
                    return
                except Exception as ex:
                    pass
            secret = info.copy()
            secret['did'] = self.get_user_did(pubkey)
            secret['xcert'] = cert.hex() 
            if not self._vault.create_or_update_secret(pubkey,secret=secret):
                print(f'Cant write secret={pubkey}')
                return
                                   
        print(f'notary:{oper} cert={cert} pub={pubkey} valid={before}/{after}')                 
        return self._send_transaction(oper,pubkey, cert, to=None, wait=wait,user=user)   


    def _do_meta_xcert_transaction(self, oper,value,user,before=XCERT_BEFORE_TM,after=XCERT_AFTER_TM):
        pubkey,cert,_ = self.set_or_upd(value,user,before,after)
        transaction = self._make_xcert_transaction(oper,pubkey, cert)
        return transaction


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


    def get_xcert(self,uid):
        if self._vault :
            return self._vault.get_xcert(uid)

    def create_xcert(self,proto,uid='456125525'):
        resp = self.crt(proto,str(uid),XCERT_BEFORE_TM,XCERT_AFTER_TM)
        return self.get_user_did(uid) if resp else None

    def get_user_did(self,uid):                                    
        did = f"did:notary:{self._public_key.as_hex()[:8]}:{uid}"      
        return did    
                                                         
    """
    def upd_meta_xcert(self,info,key,init=False):                                                                                             
        # meta cert for keykeeper and raft node                                                                                               
        info[NOTARY_NAME] = self._notary                                                                                                      
        info[NOTARY_STIME] = int(time.time())                                                                                                 
        if init:                                                                                                                              
            response = self.set(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM)                                                                
        else:                                                                                                                                 
            response = self.crt(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM)                                                                
        LOGGER.info(f"RESPONSE ={response}")                                                                                                  
                                                                                                                                              
    def upd_user_xcert(self,info,key):                                                                                                        
        # user cert                                                                                                                           
        response = self.crt(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM)                                                                    
        LOGGER.info(f"USER XCERT RESPONSE ={response}") 
    """                                                                                      
