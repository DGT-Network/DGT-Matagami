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

# DEC 
from dec_dgt.client_cli.dec_client import DecClient
from dec_dgt.client_cli.dec_attr import DEC_WALLET_OP,DEC_WALLET_OPTS_OP,DEC_WALLET_LIMIT,DEC_SPEND_PERIOD,DEC_WALLET_STATUS,DEC_DID_VAL

LOGGER = logging.getLogger(__name__)

NOTARY_TYPES = [KEYKEEPER_ID,NOTARY_LEADER_ID,NOTARY_FOLOWER_ID,NOTARY_LIST_ID]
DID_WALLETS = "wallets"
DID_ROLES   = "roles"
DID_GOODS   = "goods"

                                                                     

class NotaryClient(XcertClient):
    def __init__(self, url, keyfile=None,backend=None,vault_url=None,notary=None,lead_addr=None):
        """
        url - dgt rest-api
        keyfile -key file for sign sertificate
        backend 
        """
        super().__init__(url,keyfile=keyfile,backend=backend)
        self._vault = None
        self._url = url
        self._backend = backend
        if Vault:
            if vault_url is None:
                # client mode 
                ninfo = self.get_notary_info(NOTARY_LEADER_ID)
                #print(f'notary info={ninfo}')
                if NOTARY_TOKEN in ninfo and NOTARY_URL in ninfo:
                    self._vault = Vault(ninfo[NOTARY_URL],token=ninfo[NOTARY_TOKEN])
                else:
                    print('Cant get notary info')
                    
                    
            else:
                # init mode                                                      
                self._vault = Vault(vault_url,notary=notary,lead_addr=lead_addr) 

        self._cdec = None
        
    def init_dec(self,keyfile):
        # for  wallet mode 
        # keyfile - this is private key wallet owner 
        self._cdec = DecClient(self._url,keyfile=keyfile,backend=self._backend)

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

    def crt_secret_wallet(self,key,opts,did):
        opts[DEC_DID_VAL] = did                                                  
        if not self._vault.create_or_update_secret(key,secret=opts):                
            print('Cant update secret={}'.format(key))                               
            return False
        return True                                                                    


    def wallet(self,args,wait=None):
        # use notary key for sign did arguments
        #   
        try:
            uid = self.did2uid(args.did)
            data = self._vault.get_xcert(uid)
            if data is None:
                print(f'Certificate for {args.did} UNDEF')
                return
            owner = self._cdec.signer_as_hex
            secret = data['data']
            print('Certificate for {} VAL={} owner={}'.format(args.did,secret,owner))
            # add new wallet into xcert list 
            if args.cmd == DEC_WALLET_OP:
                # create wallet and add them into DID wallets list
                if DID_WALLETS in secret and isinstance(secret[DID_WALLETS],dict) :
                    wlist = secret[DID_WALLETS]
                    if owner in wlist:
                        print('Wallet already in wallets relating to DID={}'.format(args.did)) 
                        # check secret for wallet - DROP OUT LATER 
                        wallet = self._vault.get_secret(owner)
                        if wallet is None:
                            self.crt_secret_wallet(owner,wlist[owner],args.did)

                        return                                     
                else:
                    wlist = {}
                wopts = self._cdec.get_only_wallet_opts(args)
                wlist[owner] = wopts
                secret[DID_WALLETS] = wlist
                #
                # create secret with wallet options 
                if self.crt_secret_wallet(owner,wopts,args.did):
                    return
                #print('Certificate with wallet={}'.format(secret))
                dec_wallet = self._cdec.wallet
            elif args.cmd == DEC_WALLET_OPTS_OP:
                if DID_WALLETS not in secret or not isinstance(secret[DID_WALLETS],dict) or owner not in secret[DID_WALLETS]:   
                    print('No such wallet relating to DID={}'.format(args.did))
                    return
                opts = secret[DID_WALLETS][owner]
                print('current OPTS for wallet={} args={}'.format(opts,args))
                if not self._cdec.upd_wallet_opts(opts,args):
                    print('No new options set(limit,sped period,role and etc) {} '.format(opts))
                    return
                    
                dec_wallet = self._cdec.wallet_opts
            else:
                print('Undef CMD for wallet operation with wallet={}'.format(secret))
                return

            if not self._vault.create_or_update_secret(uid,secret=secret):    
                print('Cant update secret={}'.format(uid))                             
                return                                                           

            return dec_wallet(args,wait,nsign=self._signer)
        except Exception as ex:
            return

    def wallets(self,args,wait=None):           
        # list wallets for DID                  
        return self.get_wallets(args.did)

    def get_wallets(self,did,wait=None):  
        # list wallets for DID
        try:                                                                                         
            uid = self.did2uid(did)                                                             
            data = self._vault.get_xcert(uid)                                                        
            if data is None:                                                                         
                print(f'Certificate for {did} UNDEF')                                           
                return                                                                               
            secret = data['data']                                                                    
            # add new wallet into xcert list 
            #print('secret',secret)                                                        
            if DID_WALLETS in secret and isinstance(secret[DID_WALLETS],dict) :                      
                wlist = secret[DID_WALLETS]                                                          
                return wlist                                                                          
            else:                                                                                    
                print('No wallets relating to DID={}'.format(did))

        except Exception as ex:                                                                      
            return   
                                                                                        
    def role(self,args,wait=None):
        # create role 
        try:                                                                                  
            uid = self.did2uid(args.did)                                                           
            data = self._vault.get_xcert(uid)                                                 
            if data is None:                                                                  
                print('Certificate for {} UNDEF'.format(args.did))                                         
                return                                                                        
            secret = data['data']                                                             
            # add new role into DID role list                                                  
            if DID_ROLES in secret and isinstance(secret[DID_ROLES],dict) :               
                rlist = secret[DID_ROLES]  
                if args.role_id in rlist:
                    print('Role {} already in list for {}.'.format(args.role_id,args.did))
                    #return  
                # add new role                                                                  
            else:                                                                             
                # new role list
                rlist = {}                            
            # add new role
            role = self._cdec.get_role_opts(args)
            rlist[args.role_id] = role 
            secret[DID_ROLES] = rlist
            if not self._vault.create_or_update_secret(uid,secret=secret):      
                print('Cant update secret={}'.format(uid))                      
                return                                                          
            return self._cdec.role(args) 
                                                                                        
        except Exception as ex: 
            print('Create role ={} for {} err {}'.format(args.role_id,args.did,ex))                                                              
            return                                                                            

    def get_roles(self,did,wait=None):                                                                    
        # list wallets for DID                                                                              
        try:                                                                                                
            uid = self.did2uid(did)                                                                         
            data = self._vault.get_xcert(uid)                                                               
            if data is None:                                                                                
                print(f'Certificate for {did} UNDEF')                                                       
                return                                                                                      
            secret = data['data']                                                                           
            # add new wallet into xcert list                                                                
            #print('secret',secret)                                                                         
            if DID_ROLES in secret and isinstance(secret[DID_ROLES],dict) :                             
                rlist = secret[DID_ROLES]                                                                 
                return rlist                                                                                
            else:                                                                                           
                print('No roles relating to DID={}'.format(did))                                          
                                                                                                            
        except Exception as ex: 
            print('Cant get roles for {} err {}'.format(did,ex))                                                                             
            return                                                                                          


    def roles(self,args,wait=None):
        return self.get_roles(args.did,wait=wait)

    def get_goods(self,did,wait=None):                                                     
        # list goods for DID                                                             
        try:                                                                               
            uid = self.did2uid(did)                                                        
            data = self._vault.get_xcert(uid)                                              
            if data is None:                                                               
                print(f'Certificate for {did} UNDEF')                                      
                return                                                                     
            secret = data['data']                                                          
            # add new wallet into xcert list                                               
            #print('secret',secret)                                                        
            if DID_GOODS in secret and isinstance(secret[DID_GOODS],dict) :                
                glist = secret[DID_GOODS]                                                  
                return glist                                                               
            else:                                                                          
                print('No goods relating to DID={}'.format(did))                           
                                                                                           
        except Exception as ex:                                                            
            print('Cant get goods for {} err {}'.format(did,ex))                           
            return                                                                         
                                                                                           
    def goods(self,args,wait=None):               
        return self.get_goods(args.did,wait=wait) 

    def get_did_info(self,did):
        uid = self.did2uid(did)                                     
        data = self._vault.get_xcert(uid)                                
        if data is None:                                                 
            print('Certificate for {} UNDEF'.format(did))           
            return                                                       
        secret = data['data'] 
        return secret,uid                                           




    def target(self,args,wait=None):
        # create target                                                                                   
        try:                                                                                            
            secret,uid = self.get_did_info(args.did)
            if secret is None:
                return                                                    

            # add new role into DID role list                                                           
            if DID_GOODS in secret and isinstance(secret[DID_GOODS],dict) :                             
                glist = secret[DID_GOODS]                                                               
                if args.target_id in glist:                                                               
                    print('Target {} already in list for {}.'.format(args.target_id,args.did))              
                    #return                                                                             
                # add new target                                                                          
            else:                                                                                       
                # new goods list                                                                         
                glist = {}                                                                              
            # add new role                                                                              
            target = self._cdec.get_target_opts(args)                                                       
            glist[args.target_id] = target                                                                 
            secret[DID_GOODS] = glist                                                                   
            if not self._vault.create_or_update_secret(uid,secret=secret):                              
                print('Cant update secret={}'.format(args.did))                                              
                return                                                                                  
            return self._cdec.target(args)                                                                
                                                                                                        
        except Exception as ex:                                                                         
            print('Create target ={} for {} err {}'.format(args.target_id,args.did,ex))                     
            return  
          
    def get_did_via_wallet(self,key):
        # take did from wallet                                                       
        try:                                                                         
            wallet = self._vault.get_secret(key)                                
            if wallet is None:                                                        
                print('Wallet for {} UNDEF'.format(key))                       
                return                                                               
            did = wallet[DEC_DID_VAL]                                                
            #print("wallet: {}".format(wfrom)) 
            return did                                      
        except Exception as ex:                                                      
            print('Cant get walllet {} err {}'.format(key,ex))                 
            return                                                                   


    def pay(self,args,wait=None):
        if args.did is None:
            # take did from wallet
            fdid = self.get_did_via_wallet(args.name)
            if fdid is None:
                return None
        else:
            fdid = args.did
        print("from wallet: did={}".format(fdid))
        tdid = self.get_did_via_wallet(args.to)   
        print("to wallet: did={}".format(tdid))  
        if tdid is None: 
            return None   
        if args.target:
            # check target 
            fsecret,fuid = self.get_did_info(fdid)
            if fsecret is None :
                return
            elif DID_GOODS not in fsecret or args.target not in fsecret[DID_GOODS]:
                print("No target={} in goods".format(args.target))
                return
            tsecret,tuid = self.get_did_info(tdid)          
            if tsecret is None:                        
                return                                 

            print("from: {} to {}".format(fsecret[DID_GOODS],tsecret))
            # do transaction pay and update goods list in case of success
            resp = self._cdec.pay(args,control=True)
            #print("resp = {}".format(resp))
            if resp in ['PENDING','INVALID']  :
                print("PAY status = {}".format(resp))
                return

            # in case success 
            if fdid != tdid:
                target = fsecret[DID_GOODS].pop(args.target)
                tsecret[DID_GOODS][args.target] = target
                if not self._vault.create_or_update_secret(fuid,secret=fsecret):      
                    print('Cant update FROM secret={}'.format(fdid))                 
                    return 
                if not self._vault.create_or_update_secret(tuid,secret=tsecret):                                                            
                    print('Cant update TO secret={}'.format(tdid))  
                    fsecret[DID_GOODS][args.target] = target
                    if not self._vault.create_or_update_secret(fuid,secret=fsecret):      
                        print('Cant restore FROM secret={}'.format(fdid))                 
                    return 
            else:
                print("Target owner and buyer the same for {} done".format(args.target))

            print("pay for {} done".format(args.target)) 
        else:
            # only dec transfer
            pass

    def get_balance_of(self,pkey):
        return self._cdec.get_balance_of(pkey)

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
    def did2uid(self,did):                                       
        uid = did.split(':')
        return uid[3]  if len(uid) > 3 else did                                                  

    def make_xcert_prof(self,info,proto_xcert=None):                              
        proto = XCERT_PROTO.copy() if proto_xcert is None else proto_xcert.copy()                                          
        if EMAIL_ATTR in info and info[EMAIL_ATTR]:                                               
            proto["EMAIL_ADDRESS"] = info[EMAIL_ATTR]                        
        if DID_ATTR in info and info[DID_ATTR]:                                                 
            proto["USER_ID"] = str(info[DID_ATTR])                           
                                                                             
        if ADDRESS_ATTR  in info and info[ADDRESS_ATTR]:                                            
            proto["LOCALITY_NAME"] = info[ADDRESS_ATTR]                      
        if COUNTRY_ATTR in info and info[COUNTRY_ATTR]:                                             
            proto["COUNTRY_NAME"] = info[COUNTRY_ATTR]                       
        return proto                                                         
    
                                                         
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
