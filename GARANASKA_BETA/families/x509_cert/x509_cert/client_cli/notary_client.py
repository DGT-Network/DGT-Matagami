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
import traceback

from dgt_signing import create_context,key_to_dgt_addr,check_dgt_addr,checksum_encode
from dgt_signing import CryptoFactory
from dgt_signing import ParseError
from dgt_signing.core import (X509_COMMON_NAME, X509_USER_ID,X509_BUSINESS_CATEGORY,X509_SERIAL_NUMBER)

from dgt_sdk.protobuf.transaction_pb2 import TransactionHeader
from dgt_sdk.protobuf.transaction_pb2 import Transaction
from dgt_sdk.protobuf.batch_pb2 import BatchList
from dgt_sdk.protobuf.batch_pb2 import BatchHeader
from dgt_sdk.protobuf.batch_pb2 import Batch
"""
from dgt_sdk.protobuf.notary_pb2 import NotaryRequest
"""
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo

from x509_cert.client_cli.exceptions import XcertClientException,XcertClientKeyfileException
from x509_cert.client_cli.xcert_attr import *
from x509_cert.client_cli.xcert_client import XcertClient,_sha512,_sha256
# 
try:
    from sha3 import keccak_256
except Exception as ex:
    pass
KECCAK_MODE = "keccak"

try:                                                            
    from x509_cert.client_cli.vault import Vault  
except Exception as ex:   
    print(f'Cant load Vault - {ex}')                                      
    Vault = None                                          

# DEC 
from dec_dgt.client_cli.dec_client import DecClient
from dec_dgt.client_cli.dec_attr import (DEC_WALLET_OP,DEC_WALLET_OPTS_OP,DEC_WALLET_LIMIT,DEC_SPEND_PERIOD,
                                         DEC_WALLET_STATUS,DEC_DID_VAL,DEC_APPROVALS,DEC_APPROVAL,DEC_NOTARY_REQ,DEC_NOTARY_KEY,DEC_NOTARY_REQ_SIGN,
                                         DEC_HEADER_PAYLOAD,DEC_PAYLOAD,DEC_HEADER_SIGN,DEC_CMD_OPTS,DEC_TRANS_OPTS,DEC_EMITTER,
                                         DEC_CMD,DEC_CMD_ARG,  DEC_CMD_TO ,DEC_TARGET_INFO, DEC_PAY_OP,DEC_TARGET_OP
                                         )

LOGGER = logging.getLogger(__name__)

NOTARY_TYPES = [KEYKEEPER_ID,NOTARY_LEADER_ID,NOTARY_FOLOWER_ID,NOTARY_LIST_ID]
DID_WALLETS = "wallets"
DID_ROLES   = "roles"
DID_GOODS   = "goods"
WAIT_DEF = 10
# <group>/<did>/<object>
TARGET_PATH = "targets/{}/{}"     
ROLES_PATH = "roles/{}/{}"       
WALLETS_PATH = "wallets/{}/{}"   

TARGET_PATH_ = "{}/target/{}"
ROLES_PATH_ = "{}/roles/{}"
WALLETS_PATH_ = "{}/wallets/{}"                                                                     




class NotaryClient(XcertClient):
    def __init__(self, url, keyfile=None,backend=None,vault_url=None,notary=None,lead_addr=None):
        """
        url - dgt rest-api
        keyfile -key file for sign certificate
        backend 
        """
        super().__init__(url,keyfile=keyfile,backend=backend)
        self._vault = None
        self._url = url
        self._backend = backend
        self._vault_url = vault_url
        self._notary = notary
        self._lead_addr = lead_addr
        self._cdec = None
        self._user_signer = None

    def init_vault(self):
        if Vault is None: 
            print('No vault')                   
            LOGGER.debug("No vault instance")   
            return False                        
            
                                                                                                              
        if self._vault_url is None:                                                                                   
            # client mode                                                                                       
            # wait until info about leader will be commit into DGT                                              
            ninfo = None                                                                                        
            attempt = 100                                                                                       
            while ninfo is None and attempt > 0:                                                                
                attempt -= 1                                                                                    
                ninfo = self.get_notary_info(NOTARY_LEADER_ID)                                                  
                if ninfo is None:                                                                               
                    LOGGER.debug("NOTARY CLIENT try to get LEADER info: {}".format(attempt))                    
                    time.sleep(1)                                                                               
                    #print(f'notary info={ninfo}')                                                              
            if ninfo is not None and NOTARY_TOKEN in ninfo and NOTARY_URL in ninfo:                             
                self._vault = Vault(ninfo[NOTARY_URL],token=ninfo[NOTARY_TOKEN]) 
                return True                               
            else:                                                                                               
                print('Cant get notary info')                                                                   
                LOGGER.debug("Cant get notary info from DGT")
                return False                                                   
                                                                                                                
        else:                                                                                                   
            # init mode                                                                                         
            self._vault = Vault(self._vault_url,notary=self._notary,lead_addr=self._lead_addr)                                    
            return True

    def get_user_key(self,user_key_file):
        try:                                                  
            # use user key                                    
            self._user_signer = self.get_signer(user_key_file)                    
        except XcertClientKeyfileException:                   
            #use as default notary key                        
            self._user_signer = self._signer                             

        self._user_pubkey = self._user_signer.get_public_key().as_hex()

    def pubkey2addr(self,pubkey,lng=20,pref="0x"):
        # self._user_signer.pubkey2addr(pubkey,lng)
        a =  keccak_256(pubkey.encode()).digest()[-lng:]
        a1 =  keccak_256(pubkey.encode()).digest()[-lng:].hex()
        print('a',a1.encode(),a.hex().encode())
        #crc1 = _sha256(_sha256(a).encode())
        h = hashlib.sha256()
        h.update(a1.encode())
        h.update(h.digest())
        crc = h.hexdigest()
        crc1 = _sha256(_sha256(a1.encode()).encode())
        print(a,a1,'H',h.hexdigest(),'C',crc1)
        addr = "{}{}{}".format(pref,a1,crc[0:4])
        print('A',a.hex(),'C',crc[0:4],crc,'AD',addr)
        self.check_addr(addr)
        return addr
    def check_addr(self,addr):
        a = addr[2:42]
        h = hashlib.sha256()
        h.update(a.encode())
        h.update(h.digest())
        crc = h.hexdigest() #_sha256(_sha256(a.encode()).encode()) #h.hexdigest()
        crc0 = addr[-4:]
        print('a',a,'cr',addr[-4:],crc[0:4] == crc0)

    def init_dec(self,keyfile):
        # for  wallet mode 
        # keyfile - this is private key wallet owner 
        self._cdec = DecClient(self._url,keyfile=keyfile,backend=self._backend)

    def get_xcert_notary_attr(self,xcert):
        val = self.get_xcert_attributes(xcert,X509_COMMON_NAME)
        return cbor.loads(bytes.fromhex(val)) if val is not None else {}

    def is_notary_info(self,key):
        # check maybe this is special key for some kind of notary
        return key in NOTARY_TYPES

    def get_notary_info(self,key):
        value = self.show(key) 
        if value is None:
            return

        token = X509CertInfo()       
        token.ParseFromString(value) 
        xcert = self.load_xcert(token.xcert)
        val = self.get_xcert_notary_attr(xcert) 
        return val

    def init(self,name,wait=None):
        # Notary init
        
        if self._vault:
            logging.info('INIT NOTARY={} SYNC WITH DGT'.format(name))
            
            _meta_xcert = self._vault.init()
            key = _meta_xcert[0]
            if key:
                info = _meta_xcert[1]
                if _meta_xcert[2]:                                                               
                    response = self.set(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM) 
                else:                                                                  
                    response = self.crt(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM)
                ilog = 'INIT NOTARY={} key={} info={} response={}'.format(name,key,info,response)
                #print(ilog)
                LOGGER.info(ilog) 

    def crt_obj_secret(self,key,opts,did):
        opts[DEC_DID_VAL] = did                                                  
        if not self._vault.create_or_update_secret(key,secret=opts):                
            print('Cant update secret={}'.format(key))                               
            return False
        return True  
     
    def show_secret(self, uid):
        # show secret by uid 
        #self._vault.list_secrets()
        secret = self._vault.get_secret(uid)
        if secret:
            pkey = secret[DID_UKEY_ATTR] if DID_UKEY_ATTR in secret else None
            print('User[{}] PUBKEY={}'.format(uid,pkey))
            # take from DGT 
            return self.show(pkey)
        else:
            if self.is_notary_info(uid):
                print('THIS IS NOTARY ID={}'.format(uid))
                return self.show(uid)
            else:
                print('NO xcert for user with ID={}'.format(uid))

    def show_raft_info(self,opts):
        try:
            rconf = self._vault.get_raft_config()['data']['config']
        except Exception as ex:
            return "Notary not ready - {}".format(ex)
        return rconf

    def show_seal_status(self):                                              
        try:                                                                    
            stat = self._vault.get_seal_status()             
        except Exception as ex:                                                 
            return "Notary not ready - {}".format(ex)                           
        return stat

    def get_info_list(self,opts):
        is_meta = opts.meta > 0
        is_recursive = opts.recursive > 0
        def do_yaml(t_dir,c_yaml):
            #print("t_dir=>{} c_yaml={}".format(t_dir,type(c_yaml)))
            c_dir = self._vault.get_sys_info(info="ls",path=t_dir)
            #print("cdir={} {}".format(c_dir,type(c_dir)))
            for fnm in c_dir:
                fpath = t_dir + '' + fnm
                mdata = self._vault.get_secret(fpath) if opts.meta > 0 else None
                if mdata:
                    for dk in [XCERT_ATTR]:
                        if dk in mdata:
                            del mdata[dk]
                if fnm[-1] == '/': 
                    if opts.recursive > 0:
                        try:

                            c_yaml[fnm] = do_yaml(fpath,{} if fnm not in ["roles/","target/","wallets/"] or  is_meta else {})
                        except Exception as ex:
                            print("bad arg path={} fnm={} - ({})".format(fpath,fnm,ex))
                            c_yaml[fnm] = {}
                    else:
                        c_yaml[fnm] = "-Dir"
                else:  
                    f_val = "-Cert" if mdata is None else mdata
                    if isinstance(c_yaml,dict):
                        c_yaml[fnm] = f_val
                    else:
                        c_yaml.append(fnm)
            return c_yaml   
                                           
        to_yaml = do_yaml(opts.list,{})
        #print(yaml.dump([1.1, [2.1, 2.2], [[3.1, 3.2, 3.3]]],indent=4,default_flow_style=False))
        return yaml.dump(to_yaml,explicit_start=True,indent=4,default_flow_style=False)


    def get_user_sign_req(self,info):                                         
        # this is header of request with owner sign                                      
        req_header = {                                                                   
                DEC_EMITTER     : self._user_signer.get_public_key().as_hex(),                
                DEC_PAYLOAD     : info[DEC_CMD_OPTS],                                                  
                                                                                         
        }                                                                                
        payload = cbor.dumps(req_header)                                                 
        psignature = self._user_signer.sign(payload)                                          


        req = {                                                             
                DEC_EMITTER          : req_header[DEC_EMITTER],             
                DEC_NOTARY_REQ_SIGN  : psignature,                          
                DEC_PAYLOAD          : payload                              
            }                                                               
        
        
                                         
        return {DEC_CMD_OPTS : req, DEC_TRANS_OPTS: info[DEC_TRANS_OPTS]}             
    
    def _send_sign_xcert_transaction(self, topts, info,wait=None): 
        #to      = topts[DEC_CMD_TO] if DEC_CMD_TO in topts else None           
        #din     = topts[DEC_CMD_DIN] if DEC_CMD_DIN in topts else None         
        #din_ext = topts[DEC_CMD_DIN_EXT] if DEC_CMD_DIN_EXT in topts else None 
        return self._send_transaction(topts[DEC_CMD],topts[DEC_CMD_ARG], info[DEC_PAYLOAD], to=None, wait=wait if wait is not None else WAIT_DEF)
        
                
    def xcert_notary_approve(self,req,wait=None):  
        LOGGER.debug("xcert_notary_approve: REQ={}".format(req)) 
        #return ("ERROR","") 
        return self._send_sign_xcert_transaction(req[DEC_TRANS_OPTS],req[DEC_CMD_OPTS],wait=wait)

     
    def crt_req(self,args,uid=None):
        info =self.crt_info(args,uid=uid)
        #print('REQ',info)
        req = self.get_user_sign_req(info)
        #print('REQ',req)
        return req

    def crt_info(self,args,uid=None):
        user_id = uid if uid is not None else args.user_id
        pubkey,cert,info = self.set_or_upd(args.proto,args.user,args.before,args.after,user_id=user_id)
        tcurr = time.time() 
        #info[DEC_TMSTAMP] = tcurr   
        print("XCERT={} ".format(info))                                                   
        info[XCERT_ATTR] = cert.hex()                          
        opts = {                                                                  
                 DEC_CMD_OPTS   : info,                                           
                 DEC_TRANS_OPTS : { DEC_CMD    : XCERT_CRT_OP,                   
                                    DEC_CMD_ARG: user_id     # special key for notary or addr which was generated from pubkey               
                                  }                                               
                }
        return opts                                                                 

    def crt_vault_done(self,opts,topts):
        # finish xcert operation
        info = cbor.loads(opts[DEC_PAYLOAD])
        uid = info[DEC_PAYLOAD][X509_USER_ID]
        LOGGER.debug('crt_vault_done UID={} info={} {}'.format(uid,info,topts))
        oper = ''
        #if self._vault and not self.is_notary_info(user_id):                                
        # usual user certificate                                                        
        if oper == XCERT_SET_OP :                                                       
            try:                                                                        
                val = self._vault.get_xcert(uid)                                    
                print(f'Certificate for {pubkey} already exist')                        
                return                                                                  
            except Exception as ex:                                                     
                pass 
        self.crt_fix_secret(info,uid)


    def crt_fix_secret(self,info,uid):
        pubkey = info[DEC_EMITTER]                                                           
        secret = info.copy()                                                                 
        secret[DID_ATTR]      = self.get_user_did(uid)                                       
        secret[DID_UKEY_ATTR] = pubkey     # keep user pub key                               
        if not self._vault.create_or_update_secret(uid,secret=secret):                       
            LOGGER.debug('Cant write secret={}'.format(uid))                                 
            return                                                                           
        LOGGER.debug('write secret for did={} key={}'.format(secret[DID_ATTR],pubkey))       



    def crt(self,args,wait=WAIT_DEF):
        # create user xcert using notary approve 
        # value, wait, user_id = args.value, args.wait, args.user_id
        uid = args.user_id
        if uid == KECCAK_MODE:
            # keccak_256(public_key).digest()[-20:]
            self.get_user_key(args.user)
            addr = key_to_dgt_addr(self._user_pubkey)
            #addr1 = checksum_encode(self._user_pubkey)
            #print("XCERT ADDR",addr,addr1,check_dgt_addr(addr))
            #return
            uid = addr
            #return 
        secret = self._vault.get_secret(uid)
        if secret:
            print('User cert with ID={} already created'.format(uid))
            return
        else:
            print('Create user cert with ID={}'.format(uid))

        if args.notary > 0:                                      
            # send notary request                                
            if args.notary_url is None:                          
                print("Set notary rest api url")                 
                return None                                      
            # send request batch_list.SerializeToString()        
            nreq = self.crt_req(args,uid=uid)                   
            return self.send_notary_req(nreq,args)               



        value, wait = args.proto, args.wait
        ret =  self._do_oper(XCERT_CRT_OP,value,args.user,args.before,args.after, wait=wait,user_id=uid)
        if ret[0] == "COMMITTED":
            # fix secret
            info =self.crt_info(args,uid=uid)[DEC_CMD_OPTS]
            self.crt_fix_secret(info,uid)

    def wallet_vault_done(self,opts,topts=None):
        payload = cbor.loads(opts[DEC_PAYLOAD])
        did = payload[DEC_PAYLOAD][DEC_DID_VAL]
        uid = self.did2uid(did)
        """
        secret = self._vault.get_secret(uid)
        wlist = secret[DID_WALLETS] if DID_WALLETS in secret else {} 
        """
        owner = payload[DEC_EMITTER]  
        wopts = payload[DEC_PAYLOAD][DEC_WALLET_OP]
        wallet_path = WALLETS_PATH.format(uid,owner)
        """
        wlist[owner] = wopts                                                          
        secret[DID_WALLETS] = wlist  
        """                                                 
        #                                                                             
        # create secret with wallet options
        #                                            
        if not self.crt_obj_secret(wallet_path,wopts,did):                                 
            print('Cant create Wallet={} for DID={}'.format(wallet_path,did))                   
            return 
        """
        if not self._vault.create_or_update_secret(uid,secret=secret):    
            print('Cant update secret={}'.format(uid))                    
            return                                                        
        """
                                                                           

    def wallet(self,args,wait=None):
        # use notary key for sign did arguments
        #   
        try:
            secret,uid = self.get_did_info(args.did)                          
            if secret is None:                                                
                print('Certificate for {} not exist'.format(uid))             
                return                                                        
            owner = self._cdec.signer_as_hex
            wallet_path = WALLETS_PATH.format(uid,owner)
            #print('Certificate for {} VAL={} owner={}'.format(args.did,secret,owner))
            # add new wallet into xcert list 
            if args.cmd == DEC_WALLET_OP:
                # create wallet and add them into DID wallets list
                data = self._vault.get_xcert(wallet_path)                         
                if data is not None:                                            
                    print('Wallet {} already exist'.format(wallet_path))            
                    return                                                      

                """
                if DID_WALLETS in secret and isinstance(secret[DID_WALLETS],dict) :
                    wlist = secret[DID_WALLETS]
                    if owner in wlist:
                        print('Wallet already in wallets relating to DID={}'.format(args.did)) 
                        # check secret for wallet - DROP OUT LATER 
                        wallet = self._vault.get_secret(owner)
                        if wallet is None:
                            self.crt_obj_secret(owner,wlist[owner],args.did)

                        return                                     
                else:
                    wlist = {}
                """
                nreq = self._cdec.wallet_req(args)
                if args.notary > 0:                                             
                    # send notary request                                       
                    if args.notary_url is None:                                 
                        print("Set notary rest api url")                        
                        return None                                             
                    #nreq = self._cdec.wallet_req(args)                          
                    return self.send_notary_req(nreq,args)                      

                #print('Create wallet {}'.format(wallet_path))
                sreq = self._cdec.notary_req_sign(nreq[DEC_CMD_OPTS], self._signer)        
                #print("S",sreq)                                                           
                nreq[DEC_CMD_OPTS] = sreq                                                  
                resp,_ =  self._cdec.notary_approve(nreq,wait=WAIT_DEF)                    
                #resp,_ = self._cdec.wallet(args,wait=WAIT_DEF)
                if resp in ['PENDING','INVALID']  :               
                    print("WALLET status = {} cancel operation".format(resp))        
                    return                                        
                self.wallet_vault_done(nreq[DEC_CMD_OPTS],nreq[DEC_TRANS_OPTS])
                """
                wopts = self._cdec.get_only_wallet_opts(args)
                #wlist[owner] = wopts
                #secret[DID_WALLETS] = wlist
                #
                # create secret with wallet options 
                if not self.crt_obj_secret(wallet_path,wopts,args.did):
                    print('Cant create/update Wallet={} info into VAULT for DID={}'.format(wallet_path,args.did))
                    return
                """
                #print('New wallet={} was created'.format(wallet_path))
                
            elif args.cmd == DEC_WALLET_OPTS_OP:
                if DID_WALLETS not in secret or not isinstance(secret[DID_WALLETS],dict) or owner not in secret[DID_WALLETS]:   
                    print('No such wallet relating to DID={}'.format(args.did))
                    return
                opts = secret[DID_WALLETS][owner]
                print('current OPTS for wallet={} args={}'.format(opts,args))
                if not self._cdec.upd_wallet_opts(opts,args):
                    print('No new options set(limit,sped period,role and etc) {} '.format(opts))
                    return
                resp = self._cdec.wallet_opts(args,wait=WAIT_DEF,nsign=self._signer)             
                if resp in ['PENDING','INVALID']  :                                         
                    print("WALLET OPTS status = {}".format(resp))                                
                    return                                                                  
                    

            else:
                print('Undef CMD for wallet operation with wallet={}'.format(secret))
                return
            """
            if not self._vault.create_or_update_secret(uid,secret=secret):    
                print('Cant update secret={}'.format(uid))                             
                return                                                           
            """
            return resp

        except Exception as ex:
            print('wallet operation({}) fault={}'.format(args.cmd,ex))
            return

    def wallets(self,args,wait=None):           
        # list wallets for DID                  
        val = self.get_wallets(args.did)
        if args.yaml > 0:                                                                       
            val = yaml.dump(val,explicit_start=True,indent=4,default_flow_style=False)          
        return val                                                                              


    def get_wallets(self,did,wait=None):  
        # list wallets for DID
        try:                                                                                         
            uid = self.did2uid(did)  
            return self._vault.get_sys_info(info="ls",path=WALLETS_PATH.format(uid,"/")) 
            """                                                          
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
            """
        except Exception as ex:                                                                      
            return   
                                                                                        
    def role(self,args,wait=None):
        # create role 
        try:                                                                                  
            secret,uid = self.get_did_info(args.did)        
            if secret is None:
                print('Certificate for {} not exist'.format(uid))                              
                return                                      

            role_path = ROLES_PATH.format(uid,args.role_id)                                                          
            data = self._vault.get_xcert(role_path)                                                 
            if data is not None:                                                                  
                print('Role {} already exist'.format(role_path))                                         
                return 
            # add new role
            resp,_ = self._cdec.role(args,wait=WAIT_DEF)
            if resp in ['PENDING','INVALID']  :             
                print("ROLE transaction status = {} - cancel".format(resp))       
                return                                      
            role = self._cdec.get_role_opts(args)
            #rlist[args.role_id] = role 
            #secret[DID_ROLES] = rlist
            if not self._vault.create_or_update_secret(role_path,secret=role):      
                print('Cant update role={}'.format(role_path))                      
                return                                                          
            return resp 
                                                                                        
        except Exception as ex: 
            print('Create role ={} for {} err {}'.format(args.role_id,args.did,ex))                                                              
            return                                                                            

    def get_roles(self,did,wait=None):                                                                    
        # list wallets for DID                                                                              
        try:                                                                                                
            uid = self.did2uid(did)  
            return self._vault.get_sys_info(info="ls",path=ROLES_PATH.format(uid,"/")) 
            """                                                                      
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
            """                                         
                                                                                                            
        except Exception as ex: 
            print('Cant get roles for {} err {}'.format(did,ex))                                                                             
            return                                                                                          


    def roles(self,args,wait=None):
        val = self.get_roles(args.did,wait=wait)
        if args.yaml > 0:                                                              
            val = yaml.dump(val,explicit_start=True,indent=4,default_flow_style=False) 
        return val



    def get_goods(self,did,wait=None):                                                     
        # list goods for DID                                                             
        try:                                                                               
            uid = self.did2uid(did)  
            return self._vault.get_sys_info(info="ls",path=TARGET_PATH.format(uid,"/"))  
            """                                                    
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
            """                          
                                                                                           
        except Exception as ex:                                                            
            print('Cant get goods for {} err {}'.format(did,ex))                           
            return                                                                         
                                                                                           
    def goods(self,args,wait=None):               
        val = self.get_goods(args.did,wait=wait) 
        if args.yaml > 0:
            val = yaml.dump(val,explicit_start=True,indent=4,default_flow_style=False)
        return val

    def get_did_info(self,did):
        uid = self.did2uid(did)                                     
        data = self._vault.get_xcert(uid)                                
        if data is None:                                                 
            print('Certificate for {} UNDEF'.format(did))           
            return                                                       
        secret = data['data'] 
        return secret,uid                                           

    def target_vault_done(self,opts,topts):  
        payload = cbor.loads(opts[DEC_PAYLOAD]) 
        #print('P',payload)                                  
        did = payload[DEC_PAYLOAD][DEC_DID_VAL] #if DEC_DID_VAL in payload else "_DID_"                             
        uid = self.did2uid(did)                                           
        #secret = self._vault.get_secret(uid) 
        target_id = topts[DEC_CMD_ARG] 
        target = payload[DEC_PAYLOAD][DEC_TARGET_OP] 
        owner = payload[DEC_EMITTER]
        targ_path =  TARGET_PATH.format(uid,target_id)                           
        """
        glist = secret[DID_GOODS] if DID_GOODS in secret else {}      
        """                                        
        #                                                                 
        # create secret with target options                               
        #                                                                 
        if not self.crt_obj_secret(targ_path,target,did):             
            print('Cant create target={}'.format(target_id))               
            return                                                              
        # add new target into secret target list   
        """                                                                     
        glist[target_id] = target                                          
        secret[DID_GOODS] = glist                                               
        if not self._vault.create_or_update_secret(uid,secret=secret):          
            print('Cant update secret={}'.format(did))                                                                           
            return                                                              
        """


    def target(self,args,wait=None):
        # create target                                                                                   
        try:                                                                                            
            secret,uid = self.get_did_info(args.did)
            if secret is None:
                return  
            targ_path =  TARGET_PATH.format(uid,args.target_id)                                                 
            val = self._vault.get_secret(targ_path)
            if val is not None:
                print('Target {} already exist.'.format(args.target_id)) 
                return
            # add new role into DID role list 
            """                                                          
            if DID_GOODS in secret and isinstance(secret[DID_GOODS],dict) :                             
                glist = secret[DID_GOODS]                                                               
                if args.target_id in glist:                                                               
                    print('Target {} already in list for {}.'.format(args.target_id,args.did))              
                    #return                                                                             
                # add new target                                                                          
            else:                                                                                       
                # new goods list                                                                         
                glist = {}  
            """                                                                            
            # add new role  
            nreq = self._cdec.target_req(args)
            if args.notary > 0:
                # send notary request 
                if args.notary_url is None:
                    print("Set notary rest api url")
                    return None
                # send request batch_list.SerializeToString()
                #nreq = self._cdec.target_req(args)
                return self.send_notary_req(nreq,args)
            #print("N",nreq)
            sreq = self._cdec.notary_req_sign(nreq[DEC_CMD_OPTS], self._signer)
            #print("S",sreq)
            nreq[DEC_CMD_OPTS] = sreq
            resp,_ =  self._cdec.notary_approve(nreq,wait=WAIT_DEF)
            #print("R",resp)
            #return
            #resp,_ = self._cdec.target(args,wait=WAIT_DEF)  
            if resp in ['PENDING','INVALID']  :                         
                print("TARGET status error = {}".format(resp))                  
                return                                                 
            self.target_vault_done(nreq[DEC_CMD_OPTS],nreq[DEC_TRANS_OPTS])
            return resp                                                               
                                                                                                        
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

    def pay_vault_done(self,opts,topts):
        # get buyer uid
        fdid = opts[DEC_DID_VAL] if DEC_DID_VAL in opts else self.get_did_via_wallet(topts[DEC_CMD_ARG])
        fuid = self.did2uid(fdid)
        tdid = self.get_did_via_wallet(topts[DEC_CMD_TO][0])
        pinfo = cbor.loads(opts[DEC_PAYLOAD])
        is_diff = fdid != tdid
        print('pay_vault_done DIFF={} DID={}->{} {}'.format(is_diff,fdid,tdid,pinfo)) 
        if DEC_TARGET_INFO in pinfo[DEC_PAYLOAD][DEC_PAY_OP]:
            tname = pinfo[DEC_PAYLOAD][DEC_PAY_OP][DEC_TARGET_INFO]
            fsecret,fuid = self.get_did_info(fdid)
            tsecret,tuid = self.get_did_info(tdid)
            
            #return
            target = tsecret[DID_GOODS].pop(tname)    # take from old owner                                        
            fsecret[DID_GOODS][tname] = target   
            print('pay_vault_done TARGET={} list={}'.format(tname,fsecret[DID_GOODS]))  
            # return                                           
            if not self._vault.create_or_update_secret(fuid,secret=tsecret):                       
                print('Cant update Owner secret={}'.format(tdid))                                  
                return                                                                             
            if not self._vault.create_or_update_secret(tuid,secret=fsecret):                       
                print('Cant update Customer secret={}'.format(fdid))                               
                tsecret[DID_GOODS][tname] = target                                           
                if not self._vault.create_or_update_secret(fuid,secret=tsecret):                   
                    print('Cant restore Owner secret={}'.format(tdid))                             
                return    
            # save target and update its DID  -                                                                        
            if not self.crt_obj_secret(tname,target,fdid):                                
                print('Cant update target={} did={}'.format(tname,fdid))                  
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
            tsecret,tuid = self.get_did_info(tdid)
            if fsecret is None or tsecret is None:
                return
            elif DID_GOODS not in tsecret or args.target not in tsecret[DID_GOODS]:
                print("No target={} in target list".format(args.target))
                return

            print("from: {} to {}".format(tsecret[DID_GOODS],fsecret[DID_GOODS]))
            if args.notary > 0:                                  
                # send notary request                            
                if args.notary_url is None:                      
                    print("Set notary rest api url")             
                    return None                                  

                nreq = self._cdec.pay_req(args)
                print("NOTARY REQ = {}".format(nreq))
                self.pay_vault_done(nreq[DEC_CMD_OPTS],nreq[DEC_TRANS_OPTS])                                    
                return                                                              
                return self.send_notary_req(nreq,args)           

            # do transaction pay and update goods list in case of success
            resp,_ = self._cdec.pay(args,control=True)
            #print("PAY resp = {}".format(resp))
            if resp in ['PENDING','INVALID']  :
                print("PAY status = {} ".format(resp))
                return

            # in case success 
            if fdid != tdid:
                target = tsecret[DID_GOODS].pop(args.target)
                fsecret[DID_GOODS][args.target] = target
                if not self._vault.create_or_update_secret(fuid,secret=tsecret):      
                    print('Cant update Owner secret={}'.format(tdid))                 
                    return 
                if not self._vault.create_or_update_secret(tuid,secret=fsecret):                                                            
                    print('Cant update Customer secret={}'.format(fdid))  
                    tsecret[DID_GOODS][args.target] = target
                    if not self._vault.create_or_update_secret(fuid,secret=tsecret):      
                        print('Cant restore Owner secret={}'.format(tdid))                 
                    return 
                if not self.crt_obj_secret(args.target,target,fdid): 
                    print('Cant update target={} did={}'.format(args.target,fdid)) 
                    return


            else:
                print("Target owner and buyer the same for {} done".format(args.target))

            print("pay for {} done".format(args.target)) 
        else:
            # only dec transfer
            resp = self._cdec.pay(args,wait=WAIT_DEF)                   
            if resp in ['PENDING','INVALID']  :                        
                print("PAY status = {}".format(resp))                  
                return                                                 
            print("PAY status = {} OK".format(resp))

    def get_balance_of(self,pkey):
        return self._cdec.get_balance_of(pkey)

    def set_or_upd(self,value,user,before,after,user_id=None):
        if isinstance(value,dict):
            info = value
        else:
            with open(value,"r") as cert_file:                                               
                try:                                                                         
                    info =  json.load(cert_file)                                             
                                                                                             
                except Exception as ex:                                                      
                    info = {}  
        
        try:
            # use user key 
            signer = self.get_signer(user)
            pubkey = signer.get_public_key().as_hex() 
        except XcertClientKeyfileException:
            #use as default notary key 
            signer = self._signer
            pubkey = user 

        if self.is_notary_info(pubkey):
            # special notary certificate
            payload = cbor.dumps(info).hex()
            info = {X509_COMMON_NAME : payload}

        if user_id is not None:
            info[X509_USER_ID] = user_id
        # user who ask certificate
        self._user_signer = signer

        cert = signer.context.create_x509_certificate(info, signer.private_key, after=after, before=before)
        return pubkey,cert,info

    def _do_oper(self,oper,value,user_key,before,after,wait=None,user_id=None):
        pubkey,cert,info = self.set_or_upd(value,user_key,before,after,user_id=user_id)
        if user_id is None :
            user_id = pubkey
        if self._vault and not self.is_notary_info(user_id):
            # usual user certificate
            if oper == XCERT_SET_OP :
                try:
                    val = self._vault.get_xcert(user_id)
                    print(f'Certificate for {pubkey} already exist')
                    return
                except Exception as ex:
                    pass
            secret = info.copy()
            secret[DID_ATTR]      = self.get_user_did(user_id)
            secret[XCERT_ATTR]    = cert.hex() # keep certificate payload
            secret[DID_UKEY_ATTR] = pubkey     # keep user pub key 
            if not self._vault.create_or_update_secret(user_id,secret=secret):
                print(f'Cant write secret={user_id}')
                return
            print('write secret for did={} key={}'.format(secret['did'],pubkey))
                                   
        print(f'notary:{oper} cert={cert} pub={pubkey} valid={before}/{after}')                 
        return self._send_transaction(oper,pubkey, cert, to=None, wait=wait,user=user_key)   


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
        did = f"did:notary:{self._public_key.as_hex()[-8:]}:{uid}"      
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
    def notary_sign(self,req):                                                                    
        notary_hdr = {                                                                                
                    DEC_NOTARY_KEY : self._signer.get_public_key().as_hex(),                               
                    DEC_NOTARY_REQ_SIGN : req.signature 
                 }                                                                                    
        hpayload = cbor.dumps(notary_hdr)                                                             
        hsignature = self._signer.sign(hpayload)                                                      
        sreq = NotaryRequest(                                                                         
                signer_public_key = notary_hdr[DEC_NOTARY_KEY],                                       
                signature = hsignature,                                                               
                payload = cbor.dumps({DEC_HEADER_PAYLOAD: hpayload,
                                      DEC_PAYLOAD: req.payload
                                      })                   
            )                                                                                         
        return sreq                                                                                   

    """
    def approvals(self,args): 

        result = self._send_request(DEC_APPROVALS,rest_url=args.notary_url)                   
        print("approvals",result)                                                                                            
        try:                                                                                         
            encoded_entries = yaml.safe_load(result)["data"]                                         
                                                                                                     
            return [                                                                                 
                entry #cbor.loads(base64.b64decode(entry["data"]))                                          
                for entry in encoded_entries                                                         
            ]                                                                                        
                                                                                                     
        except BaseException:                                                                        
            return None                                                                              
    
    def approval(self,args):                                                                                
          
        #if args.approve == 0 :
        # just show off request
        # content_type = None if args.approve == 0 else 'application/octet-stream'
        result = self._send_request("{}?akey={}&approve={}&status={}&delete={}".format(DEC_APPROVAL,args.name,args.approve,args.status,args.delete), rest_url=args.notary_url)                                      
        #print("approvals",result)                                                                                
        try:                                                                                                     
            entry = yaml.safe_load(result)["data"]                                                     
            if args.approve == 0 or args.status > 0:
                # just show off request
                return entry
            # approve request with name  
            #                            
            val = bytes.fromhex(entry)
            data_val = cbor.loads(val) 
            opts = data_val[DEC_CMD_OPTS] 
            if DEC_HEADER_SIGN in opts:
                print('Request "{}" already approved'.format(args.name))
                return
            ret = self._signer.verify(opts[DEC_NOTARY_REQ_SIGN], opts[DEC_PAYLOAD],self._context.pub_from_hex(opts[DEC_EMITTER])) 
            #print('approval check sign={} data={}'.format(ret,data_val))
            
            if ret:
                sreq = self._cdec.notary_req_sign(opts, self._signer) #self.notary_sign(nreq)
                data_val = {DEC_CMD_OPTS : sreq,DEC_TRANS_OPTS : data_val[DEC_TRANS_OPTS]}
                res = self.send_notary_approve(args.name,data_val, args)

                #print('approval check sign={} data={}'.format(ret,data_val))
                return res
                                                                                                                 
        except BaseException as ex :
                                                                                                
            print('approve {} - error {} TB={}'.format(args.name,ex, traceback.format_exc()))
            return None
        
        # approve request with name 
        #  
        
    def send_notary_req(self,data,args):                                                                                              
        print("send_notary_req to",args.notary_url)                                                                                                             
        result = self._send_request("{}".format(DEC_NOTARY_REQ),data=cbor.dumps(data),content_type='application/octet-stream',rest_url=args.notary_url)             
        #print("send_notary_req",result)
        return result                                                                                    
    
    def send_notary_approve(self,key,data,args):                                                                                                                                  
                                                                                                                                                                              
        result = self._send_request("{}?akey={}".format("notary_approve",key),data=cbor.dumps(data),content_type='application/octet-stream',rest_url=args.notary_url) 
        return result       
          
                                                                                                                                                 
    def notary_approve(self,req):
        # approve operation and fix result into notary VAULT DB
        LOGGER.debug("NOTARY_APPROVE: REQ={}".format(req))
        if DEC_TRANS_OPTS not in req:
            return ('ERROR',"")
        topts = req[DEC_TRANS_OPTS]
        verb = topts[DEC_CMD]
        if verb == XCERT_CRT_OP:
            return self.xcert_notary_approve(req,wait=3)
        else:
            return self._cdec.notary_approve(req,wait=3)
    
    def notary_approve_vault(self,req):
        LOGGER.debug("NOTARY_APPROVE_VAULT: REQ={}".format(req))
        if DEC_CMD_OPTS in req and DEC_TRANS_OPTS in req:
            # continue with approve
            topts = req[DEC_TRANS_OPTS] 
            opts = req[DEC_CMD_OPTS]
            LOGGER.debug("NOTARY_APPROVE_VAULT: CMD={} OPTS={}".format(topts,opts))
            verb = topts[DEC_CMD]
            if verb == DEC_WALLET_OP:
                # fix new wallet
                self.wallet_vault_done(opts)
            elif verb == DEC_TARGET_OP:
                self.target_vault_done(opts,topts)
            elif verb == DEC_PAY_OP:
                self.pay_vault_done(opts,topts)
            elif verb == XCERT_CRT_OP:
                self.crt_vault_done(opts,topts)
            else:
                pass

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
