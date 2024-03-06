# Copyright 2022 DGT NETWORK INC © Stanislav Parsov
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
import os

from dgt_signing import create_context
from dgt_signing import CryptoFactory,key_to_dgt_addr,DGT_ADDR_PREF
from dgt_signing import ParseError
from dgt_signing import test_eth_list
from dgt_sdk.oauth.requests import OAuth2Session
from dgt_sdk.protobuf.transaction_pb2 import TransactionHeader
from dgt_sdk.protobuf.transaction_pb2 import Transaction
from dgt_sdk.protobuf.batch_pb2 import BatchList
from dgt_sdk.protobuf.batch_pb2 import BatchHeader
from dgt_sdk.protobuf.batch_pb2 import Batch
"""
from dgt_sdk.protobuf.notary_pb2 import NotaryRequest
"""
from dec_common.protobuf.dec_dgt_token_pb2 import DecTokenInfo

from dec_dgt.client_cli.exceptions import DecClientException
from dec_dgt.client_cli.dec_attr import *
from dgt_validator.gossip.fbft_topology import DGT_TOPOLOGY_SET_NM

TRANS_TOUT = 4
HTTPS_SRV_KEY = '/project/peer/keys/http_srv.key'  
HTTPS_SRV_CERT = '/project/peer/keys/http_srv.crt'


"""
{ 'emitter': '3056301006072a8648ce3d020106052b8104000a034200045976931dfc659f1eafbda1698c78fa55ff4502bc71fbfa663468d49e894a1a468d0608873b08de6ff64b11fb0398223ec09674e7e83a20ba6d37580370e56fc4',
  'payload': {
               'target': {'target_price': 1002.0, 'target_info': 'empty target', 'invoice': {'customer': None, 'target_price': 1002.0}},
               'timestamp': 1670580692.5705304,
               'did': 'did:notary:30563010:000000000'
             }
}
"""


# settings family
from dgt_settings.processor.utils import _make_settings_key,SETTINGS_NAMESPACE

def _sha512(data):
    return hashlib.sha512(data).hexdigest()
def _sha256(data):                         
    return hashlib.sha256(data).hexdigest()

def _get_prefix():                                             
    return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]                     
                                                                   
def _get_address(name,space=None):                                      
    prefix = _get_prefix()                                    
    dec_address = _sha512(name.encode('utf-8'))[64:]              
    return prefix + dec_address  
                                 
def _token_info(val):
    token = DecTokenInfo()
    token.ParseFromString(val)
    return token

def set_param(info,attr,val,def_val):
    rval = val if val else def_val
    #rval = uval if attr not in EMISSION_UNVISIBLE_ATTR else key_to_dgt_addr(uval)
    if attr in info:
        if val:
            info[attr][DATTR_VAL] = rval 
    else:
        info[attr] = {DATTR_VAL : rval }

def set_param_field(info,attr,field,val,def_val=''):                                               
    rval = val if val else def_val                                                  
    #rval = uval if attr not in EMISSION_UNVISIBLE_ATTR else key_to_dgt_addr(uval)  
    if attr in info:                                                                
        if val:                                                                     
            info[attr][DATTR_VAL][field] = rval                                            
    else:                                                                           
        info[attr] = {DATTR_VAL : {field : rval} }                                            



def is_alias(name):
    return "@" in name or name.startswith('+') and not os.path.isfile(name) #or (not name.startswith(DGT_ADDR_PREF) and not os.path.isfile(name))



class DecClient:
    def __init__(self, url=None, keyfile=None,signer=None,backend=None,token=None):
        self.url = url

        if keyfile is not None:
            #print("use keyfile {}".format(keyfile))
            try:
                with open(keyfile) as fd:
                    private_key_str = fd.read().strip()
                    fd.close()
            except OSError as err:
                raise DecClientException(
                    'Failed to read private key: {}'.format(str(err)))
            context = create_context('secp256k1',backend=backend)
            try:
                private_key = context.from_hex(private_key_str)
            except ParseError as e:
                raise DecClientException(
                    'Unable to load private key: {}'.format(str(e)))

            self._signer = CryptoFactory(context).new_signer(private_key)
            self._context = context
        elif signer:
            self._signer = signer
            self._context = signer.context
        else:
            self._context = create_context('secp256k1',backend=backend)
        # request oauth client
        
        self._requests = OAuth2Session(token = {'access_token': token} if token is not None else None)                                                              




    def get_pub_key(self,vkey):
        # try first open file with private key
        try:                                                        
            with open(vkey) as fd:                               
                private_key_str = fd.read().strip()                 
                fd.close() 
            if vkey.endswith('.pub') or vkey.endswith('.PUB'):
                #print('PUB',private_key_str)
                return private_key_str
        except OSError as err:
            # use value as pub key  
            #print('PUB',vkey)                                    
            return vkey 
        try:                                                      
            private_key = self._context.from_hex(private_key_str) 
            signer = CryptoFactory(self._context).new_signer(private_key) 
            pubkey = signer.get_public_key().as_hex() 
            #print('pub',pubkey)
            return pubkey   
        except ParseError as e:                                   
            print('Unable to load private key: {} use param is key'.format(str(e)))
            return vkey  

    def key_to_addr(self,vkey,did=DEFAULT_DID):
        if DEC_EMISSION_KEY == vkey:
            return (DEC_EMISSION_KEY,DEC_EMISSION_GRP,did)
        #pub_key = self.get_pub_key(vkey)
        #if pub_key.startswith(DGT_ADDR_PREF):
        #    return (pub_key,DEC_WALLET_GRP,did)
        if is_alias(vkey):
            # alias 
            return (key_to_dgt_addr(vkey),DEC_SYNONYMS_GRP,did)
        else:
            pub_key = self.get_pub_key(vkey)
            return (key_to_dgt_addr(pub_key) if not  pub_key.startswith(DGT_ADDR_PREF) else  vkey,DEC_WALLET_GRP,did)
        

    def get_random_addr(self):
        priv_key = self._context.new_random_private_key()
        pub_key = self._context.get_public_key(priv_key).as_hex()
        addr = key_to_dgt_addr(pub_key)
        #print("PUB",addr)
        return addr

    def load_json_proto(self,value):
        return  load_json_proto(value)

    @property
    def signer_as_hex(self):
        return self._signer.get_public_key().as_hex()

    def do_verbose(self,dec,verbose,off=True):
        # 
        return do_verbose(dec,verbose,off)
 

    # emission cmd parts
    def emission(self,args,wait=None):
        emission_key = ANY_EMISSION_KEY.format(args.name)
        if args.info > 0:
            # show current emission params
            token = self.show(args,emission_key)
            dec = cbor.loads(token.dec)  
            dec = self.do_verbose(dec,args.verbose)

            return {emission_key:token.group_code,"INFO":dec}

        info = self.load_json_proto(args.proto)
        set_param(info,DEC_TOTAL_SUM,args.total_sum,DEC_TOTAL_SUM_DEF)
        set_param(info,DEC_GRANULARITY,args.granularity,DEC_GRANULARITY_DEF)
        set_param(info,DEC_NAME,args.name,DEC_NAME_DEF)
        set_param(info,DEC_FEE,args.fee,DEC_FEE_DEF)
        set_param(info,DEC_NОMINAL,args.nominal,DEC_NОMINAL_DEF)
        set_param(info,DEC_NBURN,args.num_burn,DEC_NBURN_DEF)
        set_param(info,DEC_NОMINAL_NAME,args.nominal_name,DEC_NОMINAL_NAME_DEF)
        set_param(info,DEC_СORPORATE_SHARE,args.corporate_share,DEC_СORPORATE_SHARE_DEF)
        set_param(info,DEC_MINTING_SHARE,args.minting_share,DEC_MINTING_SHARE_DEF)
        admin_pub = self.get_pub_key(args.admin_pub_key) if args.admin_pub_key else DEC_ADMIN_PUB_KEY_DEF
        
        set_param(info,DEC_ADMIN_PUB_KEY,admin_pub,DEC_ADMIN_PUB_KEY_DEF)
        
        # take mint params
        mint_val = info[DEC_MINT_PARAM][DATTR_VAL] if DEC_MINT_PARAM in info else {DEC_MINT_COEF_UMAX: 10,DEC_MINT_COEF_T1:1 ,DEC_MINT_COEF_B2:1}
        if args.mint_umax:
            mint_val[DEC_MINT_COEF_UMAX] = float(args.mint_umax)
        if args.mint_t1:                               
            mint_val[DEC_MINT_COEF_T1] = float(args.mint_t1)
        if args.mint_b2:                               
            mint_val[DEC_MINT_COEF_B2] = float(args.mint_b2)
        set_param(info,DEC_MINT_PARAM,args.mint,mint_val)
        corp_keys = []
        if args.corporate_pub_key:
            # check when create corporate wallet - only owner this key have responsibilities for operation
            
            for pkey in args.corporate_pub_key:
                corp_keys.append(key_to_dgt_addr(self.get_pub_key(pkey)))
        else:
            corp_keys = [key_to_dgt_addr(self._signer.get_public_key().as_hex())]

        info[DEC_CORPORATE_PUB_KEY] = {DATTR_VAL : corp_keys}
        corp_acc = key_to_dgt_addr(self.get_pub_key(args.corporate_account)) if args.corporate_account else corp_keys[0]
        #print('CORP',corp_acc)
        set_param_field(info,DEC_СORPORATE_ACCOUNT,DEC_CORP_ACC_ADDR,corp_acc)

        for a,val in info.items():
            if a in EMISSION_UNVISIBLE_ATTR:
                if isinstance(val,dict) :
                    if not isinstance(val[DATTR_VAL],list):
                        val[DATTR_VAL] = key_to_dgt_addr(val[DATTR_VAL])
        if args.check > 0:
            #print("Emission's params={}".format(self.do_verbose(info,args.verbose))) #json.dumps(info, sort_keys=True, indent=4)))
            return self.do_verbose(info,args.verbose)

        finfo = {
                 
                 DEC_EMITTER : self._signer.get_public_key().as_hex(),
                 DEC_PAYLOAD : {
                                 DEC_TMSTAMP     : time.time(),
                                 DEC_EMISSION_OP : info,
                                 DEC_DID_VAL     : args.did
                               }
                }

        if args.emiss_signers:
            # for first time - fix list of signers
            ekeys = []
            for pkey in args.emiss_signers:
                ekeys.append(self.get_pub_key(pkey))

            #finfo[DEC_SIGN_MIN] =  args.emiss_sign_min if args.emiss_sign_min else info[DEC_EMISSION_INFO][DEC_DID_VAL][DEC_SIGN_MIN]
            #finfo[DEC_MULTI_SIGNERS] = ekeys 
            info[DEC_EMISSION_INFO][DATTR_VAL][DEC_MULTI_SIGNERS] = ekeys
            if args.emiss_sign_min:
                info[DEC_EMISSION_INFO][DATTR_VAL][DEC_SIGN_MIN] = args.emiss_sign_min
        else:
            if DEC_EMISSION_INFO not in info:
                print("Old emission proto - update emission.json")
                return
        # emission info 
        finfo[DEC_SIGN_MIN] = info[DEC_EMISSION_INFO][DATTR_VAL][DEC_SIGN_MIN]
        finfo[DEC_MULTI_SIGNERS] = info[DEC_EMISSION_INFO][DATTR_VAL][DEC_MULTI_SIGNERS]

        taddr = (DEC_ESIGNERS_KEY,DEC_EMISSION_GRP,args.did)
        #print('PROTO',info)
        #eaddr = self._get_full_addr(emission_key,tp_space=DEC_EMISSION_GRP,owner=args.did) #self._get_address(DEC_EMISSION_KEY)
        return self._send_transaction(DEC_EMISSION_OP, (emission_key,DEC_EMISSION_GRP,args.did), finfo, to=taddr, wait=wait if wait else TRANS_TOUT,din_ext=(SETTINGS_NAMESPACE,DGT_TOPOLOGY_SET_NM))

    def wallet_(self,args,wait=None,nsign=None):  
        # nsign - notary key for sign did info 
        # in case nsign is None we use owner wallet key 
        #print("DEC.wallet...")
        info = {}
        if nsign is None:
            nsign = self._signer

        did =  { DATTR_VAL     :  args.did if args.did else DEFAULT_DID,                             
                 NOTARY_PUBKEY :  nsign.get_public_key().as_hex()       
                }                                                       

        payload = cbor.dumps(did)                            
        psign = nsign.sign(payload)                          
        # notary sign                                                     
        info[DEC_DID_VAL] = { DEC_DID_VAL   : payload,       
                              DEC_SIGNATURE : psign          
                            } 
                                                                      
        info[DEC_WALLET_OPTS_OP] = self.get_wallet_opts(args,nsign)
        if args.info > 0:
            print("Wallet info={}".format(info))
            return
                                     
        info[DEC_TMSTAMP] = time.time() 
        #print("DEC.wallet {}".format(info))                                        
        return self._send_transaction(DEC_WALLET_OP, self._signer.get_public_key().as_hex(), info, to=None, wait=wait, din=None) # DEC_EMISSION_KEY 

    def wallet(self,args,wait=None):                                   
        info = self.wallet_info(args)                                  
        topts = info[DEC_TRANS_OPTS] 
        opts = info[DEC_CMD_OPTS] 
        if args.check > 0:                           
            #print("Wallet info={}".format(opts))    
            return opts                                                                  
        req = self.dec_req_sign(opts)                    
        # for notary less mode user sign with his own key              
        sign_req = self.notary_req_sign(req,self._signer)              
        #print('WALLET OPTS={} TOPTS={} REQ={}'.format(opts,topts,sign_req))                                   
        #return                                                        
        return self._send_sign_transaction(topts,sign_req,wait=wait if wait else 4)   



    def wallet_info(self,args,signer=None):                                          
        info = {}                                                                    
        tcurr = time.time()
        wallet = self.get_only_wallet_opts(args)                                                          
        info[DEC_WALLET_OP] = wallet                             
        #info[DEC_EMITTER] = signer.get_public_key().as_hex()                        
        info[DEC_TMSTAMP] = tcurr                                                    
        if args.did:                                                                 
            # refer to DID owner                                                     
            info[DEC_DID_VAL] = args.did 
        pubkey = self._signer.get_public_key().as_hex()
        waddr = key_to_dgt_addr(pubkey)
        wallet[DEC_WALLET_ADDR] = waddr
        din = [(DEC_EMISSION_KEY,DEC_EMISSION_GRP,DEFAULT_DID)]
        #addr = self._get_full_addr(waddr,tp_space=DEC_WALLET_GRP,owner=args.did)                                            
        opts = {                                                                     
                 DEC_CMD_OPTS   : info,                                              
                 DEC_TRANS_OPTS : { DEC_CMD    : DEC_WALLET_OP,                      
                                    DEC_CMD_ARG: (waddr,DEC_WALLET_GRP,args.did),
                                    DEC_CMD_DIN: din                      
                                  }                                                  
                }                                                                    
        return opts                                                                  

    def wallet_req(self,args):                                             
        info = self.wallet_info(args) 
        return self.user_sign_req(info)                                     

    def upd_wallet_opts(self,opts,args): 
        if not (args.spend_period or args.limit or args.status or args.role):             
            print('No new options set(limit,sped period and etc) {} '.format(opts))       
            return  False                                                                      
        if args.limit is not None:                                                        
            # set transfer                                                                
            opts[DEC_WALLET_LIMIT] = args.limit                                           
            print('NEW OPTS={}'.format(opts))                                             
        if args.spend_period:                                                             
            opts[DEC_SPEND_PERIOD] = args.spend_period                                    
        if args.status:                                                                   
            opts[DEC_WALLET_STATUS] = args.status                                         
        if args.role:                                                                     
            # add or revoke role                                                          
            is_revoke = args.revoke is not None                                           
            if is_revoke:                                                                 
                # drop role                                                               
                if DEC_WALLET_ROLE in opts and role in opts[DEC_WALLET_ROLE]: 
                    opts[DEC_WALLET_ROLE].remove(role)
                else:
                    print('This role ={} was not granted yet'.format(role))
                    return False
                
            else:                                                                         
                # grant role 
                if DEC_WALLET_ROLE in opts: 
                    if role in opts[DEC_WALLET_ROLE]: 
                        print('This role ={} already was granted'.format(role))    
                        return False 
                    opts[DEC_WALLET_ROLE].append(role)
                else:
                    opts[DEC_WALLET_ROLE] = [role]


        return True


    def get_only_wallet_opts(self,args):
        # load default options
        opts = self.load_json_proto(args.opts_proto)                      
        if args.limit is not None:                                        
            # set transfer                                                
            opts[DEC_WALLET_LIMIT] = args.limit                           
        if args.spend_period:                                             
            opts[DEC_SPEND_PERIOD] = args.spend_period                    
        if args.status:                              
            opts[DEC_WALLET_STATUS] = args.status   
        if args.role:                                   
            opts[DEC_WALLET_ROLE] = [args.role]   
        if args.token:
            opts[DEC_WALLET_TOKEN] = args.token
        if args.owner_pub_key:
            # wallet with multi sign
            
            signers = []
            for signer in args.owner_pub_key:
                signers.append(key_to_dgt_addr(self.get_pub_key(signer)))

            opts[DEC_WALLETS_OWNERS] = { DEC_ESIGN_NUM : args.sign_min if args.sign_min else 1,DEC_ESIGNERS : signers}
        #print("DEC.wallet opts{}".format(opts))
        return opts

    def get_wallet_opts(self,args,nsign):

        opts = self.get_only_wallet_opts(args)
        opts[NOTARY_PUBKEY] =  nsign.get_public_key().as_hex()            
        payload = cbor.dumps(opts)                                        
        psign = nsign.sign(payload)                                       
                                                                          
        return  { DEC_WALLET_OPTS_OP   : payload, DEC_SIGNATURE : psign  }                                      
                                                                          
        
        
                                                                                                                                       
    def wallet_opts(self,args,wait=None,nsign=None):                                                                                                                
        # nsign - notary key for sign did info                                                                                                                 
        # in case nsign is None we use owner wallet key                                                                                                        
        info = {}                                                                                                                                              
        if nsign is None:                                                                                                                                      
            nsign = self._signer   
         
        opts =  { NOTARY_PUBKEY :  nsign.get_public_key().as_hex() }                                                                   

        if args.limit is not None:               
            # set transfer                       
            opts[DEC_WALLET_LIMIT] = args.limit  
        if args.spend_period:                          
            opts[DEC_SPEND_PERIOD] = args.spend_period 
        if args.status:                            
            opts[DEC_WALLET_STATUS] = args.status 
        if args.role:
            # grand or revoke                                
            opts[DEC_WALLET_ROLE] = '-'+args.role  if args.revoke > 0 else  args.role   
            
             
        payload = cbor.dumps(opts)                                                                                                                              
        psign = nsign.sign(payload)                                                                                                                            
                                                                                                                                                               
        info[DEC_WALLET_OPTS_OP] = { DEC_WALLET_OPTS_OP   : payload,                                                                                                         
                                     DEC_SIGNATURE : psign                                                                                                            
                                   }                                                                                                                                  
        info[DEC_TMSTAMP] = time.time() 
        waddr = (key_to_dgt_addr(self._signer.get_public_key().as_hex()),DEC_WALLET_GRP,args.did)
        return self._send_transaction(DEC_WALLET_OPTS_OP,waddr, info, to=None, wait=wait if wait else TRANS_TOUT, din=None) # DEC_EMISSION_KEY            



    def birth(self,args,wait=None):
        token = self.get_object(DEC_EMISSION_GRP,args.did,ANY_EMISSION_KEY.format(args.name))
        try:
            dec = cbor.loads(token.dec)  
        except  Exception as ex:
            dec = {}
        tmstamp = dec[DEC_TMSTAMP] if DEC_TMSTAMP in dec else 0
        return tmstamp2str(tmstamp)


    def total_supply(self,args,wait=None):  
        token = self.get_object(DEC_EMISSION_GRP,args.did,ANY_EMISSION_KEY.format(args.name))
        try:
            dec = cbor.loads(token.dec) #if token.group_code == DEC_NAME_DEF else {} 
        except Exception as ex:
            dec = {}
        return {DEC_TOTAL_SUM : dec[DEC_TOTAL_SUM][DATTR_VAL] if DEC_TOTAL_SUM in dec else 0}
    
       
           
    def token_info(self,args,wait=None): 
        tname =  ANY_EMISSION_KEY.format(args.name)  
        token = self.get_object(DEC_EMISSION_GRP,args.did,tname)
        info = {}    
        #print(token.group_code,)
        if token.group_code == args.name :
            dec = cbor.loads(token.dec)
            #print('DEC=',dec)
            for attr,aval in dec.items():
                if attr not in [DEC_MINTING_TOTAL,DEC_СORPORATE_TOTAL,DEC_SALE_TOTAL]:
                    val = aval
                    if attr == DEC_TMSTAMP:
                        val = tmstamp2str(aval) #time.strftime(DEC_TSTAMP_FMT, time.gmtime(aval))
                    elif attr == DEC_NBURN:
                        if DEC_TMSTAMP in aval:
                            aval[DEC_TMSTAMP] = tmstamp2str(aval[DEC_TMSTAMP]) #time.strftime(DEC_TSTAMP_FMT, time.gmtime(aval[DEC_TMSTAMP]))
                    elif attr == DEC_WAIT_TO_DATE:
                        if DATTR_VAL in aval:                                
                            aval[DATTR_VAL] = tmstamp2str(aval[DATTR_VAL]) 
                    
                    info[attr] = val 

        info = self.do_verbose(info,args.verbose)
            
        return info
        
    def burn(self,args,wait=None):   
        info = {}
        if args.passkey and args.sum:
            binfo = { DEC_PASSKEY   : key_to_dgt_addr(args.passkey),
                      DEC_TOTAL_SUM : args.sum
                     }
            
            info[DEC_EMITTER] = self._signer.get_public_key().as_hex()                             
            info[DEC_PAYLOAD] = {                                                                  
                                  DEC_BURN_OP : binfo,                                              
                                  DEC_TMSTAMP : time.time(),                                             
                                  DEC_DID_VAL : DEFAULT_DID if args.did is None else args.did      
                                }                                                                  


            #print('PROTO',info)   
            tname = ANY_EMISSION_KEY.format(args.name)  
            #addr = self._get_full_addr(tname,tp_space=DEC_EMISSION_GRP,owner=args.did)                                                            
            return self._send_transaction(DEC_BURN_OP, (tname,DEC_EMISSION_GRP,args.did), info, to=None, wait=wait if wait else TRANS_TOUT)
        else:
            print('Set  passkey and burn_sum argument')

    def change_mint(self,args,wait=None):
        info = {}                                                                                    
        if args.passkey:                                                                
            info[DEC_PASSKEY] = key_to_dgt_addr(args.passkey) 
            if args.mint:
                try:
                    info[DEC_MINT_PARAM] = json.loads(args.mint) 
                except Exception as ex :
                    print('Cant load ({}) - {}'.format(args.mint,ex))
                    return
            elif args.mint_umax or args.mint_t1 or args.mint_b2 or args.mint_period:
                # take mint params 
                mint_val = {}                                                                                                                                    
                if args.mint_umax:                                                                                                                                     
                    mint_val[DEC_MINT_COEF_UMAX] = float(args.mint_umax)                                                                                               
                if args.mint_t1:                                                                                                                                       
                    mint_val[DEC_MINT_COEF_T1] = float(args.mint_t1)                                                                                                   
                if args.mint_b2:                                                                                                                                       
                    mint_val[DEC_MINT_COEF_B2] = float(args.mint_b2)
                if args.mint_period:                                         
                    mint_val[DEC_MINT_PERIOD] = float(args.mint_period)                                                                                                        
                info[DEC_MINT_PARAM] = mint_val
            else:
                print('Set some mint params')
                return 

            info[DEC_EMITTER] = self._signer.get_public_key().as_hex()
            print('PROTO',info)                                                                      
            return self._send_transaction(DEC_CHANGE_MINT_OP, (ANY_EMISSION_KEY.format(args.name),DEC_EMISSION_GRP,DEFAULT_DID), info, to=None, wait=wait if wait else TRANS_TOUT)
        else:                                                                                        
            print('Set  passkey')                                              


    def distribute(self,args,wait=None):    
        token = self.get_object(DEC_EMISSION_GRP,args.did,ANY_EMISSION_KEY.format(args.name))               
        info = {}                                         
        if token.group_code == args.name :             
            dec = cbor.loads(token.dec)                        
            for attr in [DEC_TOTAL_SUM,DEC_MINTING_TOTAL,DEC_MINTING_REST,DEC_СORPORATE_TOTAL,DEC_СORPORATE_REST,DEC_SALE_TOTAL,DEC_SALE_REST]:
                info[attr] = dec[attr] if not isinstance(dec[attr],dict) else dec[attr][DATTR_VAL]
        return info                                       



    def faucet(self,args,wait=None):  
        if args.passkey:  
            info = {}                                                              
            info[DEC_PASSKEY] = key_to_dgt_addr(args.passkey)                                                        
            info[DATTR_VAL]   = args.value                                       
            print('PROTO',info) 
            to =  (ANY_EMISSION_KEY.format(args.name),DEC_EMISSION_GRP,DEFAULT_DID)
            waddr = self.key_to_addr(args.pubkey,did=args.did)
            info[DEC_EMITTER] = self._signer.get_public_key().as_hex() 
            info[DEC_TMSTAMP] = time.time()                                                                   
            return self._send_transaction(DEC_FAUCET_OP, waddr, info, to=to, wait=wait if wait else TRANS_TOUT)  
        else:                                                                                       
            print('Set  passkey argument')                                           

    def tips(self,args,wait=None):
        tips = self.get_tips(args.name,args.cmd,args.did)       
        info = {DEC_TIPS_OP: tips}                                                                                   
        return info  

    def alias_to_addr(self,alias,did):
        token = self.get_object(DEC_SYNONYMS_GRP,did,alias)     
        try:                                                                                      
            dec = cbor.loads(token.dec)                                                           
        except  Exception as ex:                                                                  
            dec = {}  
        #print("DEC",dec)                                                                            
        return  dec[DEC_WALLET_OPTS_OP][DEC_WALLET_ADDR] if DEC_WALLET_OPTS_OP in dec and DEC_WALLET_ADDR in dec[DEC_WALLET_OPTS_OP] else alias

    def get_tips(self,tname,cmd,did):  
        result = self._send_request("gates")
        try:
            gates = yaml.safe_load(result)['data']
        except Exception as ex:
            gates = {}
        
        
        tips = 0.0  
        try:
            token = self.get_object(DEC_EMISSION_GRP,did,ANY_EMISSION_KEY.format(tname))
            if token.group_code == tname :                                                     
                dec = cbor.loads(token.dec)                                                        
                if DEC_TIPS_OP in dec:                                                             
                    val = dec[DEC_TIPS_OP][DATTR_VAL]                                              
                    if cmd in val:
                        tips = val[cmd]
        except Exception as ex:
            pass                  
        gates['DGT'] = {'tips' : tips }  
        return gates                                                                            


    #                            
    # emission cmd parts End
    #  
    # minting cmd parts 
    def mint(self,args,wait=None): 
        info = {}
        if args.sum:                                                                                              
            info[DATTR_VAL]   = args.sum                                                                            
        if args.did:
            info[DEC_DID_VAL] = args.did

        info[DEC_TMSTAMP] = time.time()
        to = [(DEC_HEART_BEAT_KEY,DEC_EMISSION_GRP,DEFAULT_DID),(ANY_EMISSION_KEY.format(args.name),DEC_EMISSION_GRP,DEFAULT_DID)]
        din = None # (ANY_EMISSION_KEY.format(args.name),DEC_EMISSION_GRP,DEFAULT_DID)
        return self._send_transaction(DEC_MINT_OP, (args.pubkey,DEC_WALLET_GRP,args.did), info, to=to, wait=wait if wait else TRANS_TOUT,din=din)                  


    def heart_beat(self,args,wait=None):      
        info = {}                                                                                       
        if args.passkey:                                                                                    
            info[DATTR_VAL]   = args.passkey                                                                
        if args.period:                                                                                    
            info[DEC_HEART_BEAT_PERIOD] = args.period  

        info[DEC_TMSTAMP] = time.time()
                                                                    
        self._send_transaction(DEC_HEART_BEAT_OP, (DEC_HEART_BEAT_KEY,DEC_EMISSION_GRP,DEFAULT_DID), info, to=None, wait=wait,din=None) #DEC_EMISSION_KEY) 

    def make_heart_beat_tnx(self,passkey=None,period=None,peers=[]):
        info = {}                                
        if passkey:                              
            info[DATTR_VAL]   = passkey          
        if period:                               
            info[DEC_HEART_BEAT_PERIOD] = period
        info[DEC_HEART_BEAT_PEERS] = peers # list peers which participate in consensus
        info[DEC_TMSTAMP] = time.time()
        return self._make_transaction(DEC_HEART_BEAT_OP,(DEC_HEART_BEAT_KEY,DEC_EMISSION_GRP,DEFAULT_DID),info,to=None,din=(DEC_EMISSION_KEY,DEC_EMISSION_GRP,DEFAULT_DID))

    
    def seal_count(self,args,wait=None):                            
        pass  
                                                    
    #
    # banking cmd parts  
    # 
    def balance_of(self,args,wait=None):
        return self.get_balance_of(args,args.pubkey,wait)

    def get_balance_of(self,args,pubkey,wait=None):  
        token = self.get_object(DEC_WALLET_GRP if not is_alias(pubkey) else DEC_SYNONYMS_GRP, args.did, pubkey)
        return token

    def send(self,args,wait=None): 
        # use this cmd for sending token to corporate wallet 
        # use as name _DEC_EMISSION_KEY_
        info = {}
        send_opts = {DATTR_VAL : args.amount}
        #eaddr = self._get_full_addr(DEC_EMISSION_KEY,tp_space=DEC_EMISSION_GRP,owner=DEFAULT_DID)
        din = [(DEC_EMISSION_KEY,DEC_EMISSION_GRP,DEFAULT_DID)]
        if args.asset_type:
            send_opts[DEC_ASSET_TYPE] = args.asset_type             
        if args.trans_id:
            send_opts[DEC_TRANS_ID] = args.trans_id
        if args.role:                             
            send_opts[DEC_WALLET_ROLE] = args.role     
            din.append(args.role) 
        to_addr =  args.to  
        nm_addr = args.name             
        if args.direct > 0 :
            # take wallet addr from alias
            if  is_alias(args.to):
                to_addr =  self.alias_to_addr(args.to,args.didto)
                #print('to',to_addr)
            if  is_alias(args.name):                                 
                nm_addr =  self.alias_to_addr(args.name,args.did)
                #print('from',nm_addr)  
            #return to_addr

        if args.did:                     
            info[DEC_DID_VAL] = args.did 

        info[DEC_EMITTER] = self._signer.get_public_key().as_hex()
        info[DEC_TMSTAMP] = time.time()
        info[DEC_SEND_OP] = send_opts
        faddr = self.key_to_addr(nm_addr,args.did)
        taddr = [self.key_to_addr(to_addr,args.didto)]
        if args.trans_id:
            taddr.append((DEC_TRANS_KEY.format(args.trans_id),DEC_EMISSION_GRP,args.did))
        #print('F',faddr,'T',taddr)
        send_opts[DEC_CMD_TO_GRP] = taddr[0][1]
        if args.check:
            return send_opts
        return self._send_transaction(DEC_SEND_OP, faddr, info, to=taddr, wait=wait if wait else TRANS_TOUT,din=din)  

    def pay(self,args,wait=None,control=False):
        info = self.pay_info(args)    
        if args.check > 0:
            return info[DEC_CMD_OPTS]
        topts = info[DEC_TRANS_OPTS]                                   
        req = self.dec_req_sign(info[DEC_CMD_OPTS])                    
        # for notary less mode user sign with his own key  
 
        sign_req = self.notary_req_sign(req,self._signer)              
        #print('PREQ',sign_req,topts)                                   
        #return    
        return self._send_sign_transaction(topts,sign_req,wait= TRANS_TOUT if wait is None  else wait)   
        

    def pay_info(self,args):
        pay_opts = {}
        pay_opts = {DATTR_VAL : args.amount}                                   
        if args.asset_type:                                                
            pay_opts[DEC_ASSET_TYPE] = args.asset_type
        if args.trans_id:                               
            pay_opts[DEC_TRANS_ID] = args.trans_id                              
        #if args.did:                                                       
        #    pay_opts[DEC_DID_VAL] = args.did                                   
        #daddr = self._get_full_addr(args.to,tp_space=DEC_WALLET_GRP,owner=args.didto) 
        #eaddr = self._get_full_addr(DEC_EMISSION_KEY,tp_space=DEC_EMISSION_GRP,owner=DEFAULT_DID)
        to_addr =  args.to                                         
        nm_addr = args.name                                        
        if args.direct > 0 :                                       
            # take wallet addr from alias                          
            if  is_alias(args.to):                                 
                to_addr =  self.alias_to_addr(args.to,args.didto)  
            if  is_alias(args.name):                               
                nm_addr =  self.alias_to_addr(args.name,args.did)  
                print("from",nm_addr)



        taddr = self.key_to_addr(to_addr,args.didto) 
        pay_opts[DEC_CMD_TO_GRP]  = taddr[1]                                                               
        to = [taddr]                                                     
        din = [(DEC_EMISSION_KEY,DEC_EMISSION_GRP,DEFAULT_DID)]                                           
        if args.target :                                                   
            # target with invoice 
            # to wallet is owner target
            pay_opts[DEC_TARGET_INFO] = args.target 
            #taddr = self._get_full_addr(args.target,tp_space=DEC_TARGET_GRP,owner=args.didto)                                          
            to.append((args.target,DEC_TARGET_GRP,args.didto))                                         
        if args.trans_id:                                                                 
            to.append((DEC_TRANS_KEY.format(args.trans_id),DEC_EMISSION_GRP,DEFAULT_DID))     
            
            
                                                                               
        if args.provement_key:                                             
            # invoice ID for controle                                      
            pay_opts[DEC_PROVEMENT_KEY] = args.provement_key                   
        if args.role:                                                      
            pay_opts[DEC_WALLET_ROLE] = args.role                              
            din.append(args.role)                                          
                                                                           
        info = {
                 DEC_PAY_OP  : pay_opts,
                 DEC_TMSTAMP : time.time()
               }                                                                   
        if args.did:                                                                
            # refer to DID owner                                                    
            info[DEC_DID_VAL] = args.did 
        faddr = self.key_to_addr(nm_addr,args.did)                                              
        opts = {                                                                    
                 DEC_CMD_OPTS   : info,                                             
                 DEC_TRANS_OPTS : { DEC_CMD    : DEC_PAY_OP,                     
                                    DEC_CMD_ARG: faddr ,
                                    DEC_CMD_TO : to,
                                    DEC_CMD_DIN: din                    
                                  }                                                 
                }                                                                   
        return opts                                                                                                   





    def pay_req(self,args): 
        # make pay request                                            
        info = self.pay_info(args)  
        return self.user_sign_req(info)                                   
    
     
    def invoice(self,args,wait=None):   
        inv = {DATTR_VAL : args.amount}                                                                         
        tcurr = time.time()
        inv[DEC_PROVEMENT_KEY] = args.prove_key 
        inv[DEC_CUSTOMER_KEY] = args.customer if args.customer else None
        if args.available_till:                                                                                   
            inv[AVAILABLE_TILL] = tcurr + args.available_till                                                         
        
        din = [(DEC_EMISSION_KEY,DEC_EMISSION_GRP,DEFAULT_DID)]
        if args.customer:
            din.append(args.customer) 
        pkey = self._signer.get_public_key().as_hex()
        target = self.get_target_addr(pkey,args.target)
        info = { 
                 DEC_EMITTER : pkey,  
                 DEC_PAYLOAD : {                                                                  
                              DEC_INVOICE_OP : inv,                                              
                              DEC_TMSTAMP : tcurr,                                             
                              DEC_DID_VAL : args.did
                            }
              }                                                                  

        if args.check > 0:
            return inv
        #iaddr = self._get_full_addr(args.target,owner=args.did)                                                                                                     
        return self._send_transaction(DEC_INVOICE_OP, (target,DEC_TARGET_GRP,args.did), info, to=None, wait=wait if wait else TRANS_TOUT,din=din)  
     
    def get_target_addr(self,pkey,tid):
        return key_to_dgt_addr("{}.{}".format(pkey,tid)) if not tid.startswith(DGT_ADDR_PREF) else tid

    def get_target_opts(self,args):
        target = self.load_json_proto(args.target_proto)
        pkey = self._signer.get_public_key().as_hex()
        target[DEC_TARGET_PRICE] = args.price
        target[DEC_TARGET_INFO] = args.target if args.target else DEC_TARGET_INFO_DEF
        target[DEC_TARGET_ID] = args.target_id
        target[DEC_TARGET_ADDR] = self.get_random_addr() if False else self.get_target_addr(pkey,args.target_id)
        owner = key_to_dgt_addr(pkey)
        
        target[DEC_OWNER] = owner #key_to_dgt_addr(self._signer.get_public_key().as_hex(),pref="0x")
        #print(type(owner),owner)
        for key,val in target.items():
            if key not in TARGET_VISIBLE_ATTR:
                target[key] = key_to_dgt_addr(val,pref="")
        if args.invoice > 0:                                                                 
            target[DEC_INVOICE_OP] = {DEC_CUSTOMER_KEY : None, DEC_TARGET_PRICE :args.price} 
        return target

    def target_info(self,args,signer=None):
        # full info for target                                             
        info = {}                                                               
        tcurr = time.time() 
        target = self.get_target_opts(args) 
        tips = self.get_this_tips(DEC_NAME_DEF,DEC_TARGET_OP,args.did,gate=args.gate)
        info[DEC_TARGET_OP] = target 
        
        #info[DEC_EMITTER] = signer.get_public_key().as_hex()              
        info[DEC_TMSTAMP] = tcurr 
        info[DEC_TIPS_OP] = {DEC_TIPS_OP : args.tips,GATE_ADDR_ATTR :tips[GATE_ADDR_ATTR]}  
        
        if args.did:                                                            
            # refer to DID owner  
            info[DEC_DID_VAL] = args.did  
            #addr = self._get_full_addr(taddr,owner=args.did)
        #else:
        #    addr = self._get_address(taddr)
        opts = {
                 DEC_CMD_OPTS   : info,
                 DEC_TRANS_OPTS : { DEC_CMD     : DEC_TARGET_OP,
                                    DEC_CMD_ARG : (target[DEC_TARGET_ADDR],DEC_TARGET_GRP,args.did),
                                    DEC_CMD_DIN : [(DEC_EMISSION_KEY,DEC_EMISSION_GRP,DEFAULT_DID)]
                                  },
                 DEC_TIPS_OP : tips
                } 
        
        if args.tips > 0.0:                                   
            opts[DEC_TRANS_OPTS][DEC_CMD_TO] = [(target[DEC_OWNER],DEC_WALLET_GRP,args.did),(tips[GATE_ADDR_ATTR],DEC_WALLET_GRP,DEFAULT_DID)]
            opts[DEC_TRANS_OPTS][DEC_CMD_DIN_EXT] = (SETTINGS_NAMESPACE,DGT_TOPOLOGY_SET_NM)
                                             
        return opts

    def get_this_tips(self,tname,op,did,gate=DEFAULT_GATE):
        tips = self.get_tips(tname,op,did)
        for nest,val in tips.items():
            if GATE_ADDR_ATTR in val :
                if (gate == DEFAULT_GATE and DEFAULT_GATE in val) or nest == gate:
                    val[DEFAULT_GATE] = nest
                    return val
        return 0.0

    def target(self,args,wait=5):
          
        info = self.target_info(args) 
        if  args.check > 0: 
            # show params
            info[DEC_CMD_OPTS][DEC_TIPS_OP] = info[DEC_TIPS_OP]         
            return info[DEC_CMD_OPTS]  

        topts = info[DEC_TRANS_OPTS] 
        req = self.dec_req_sign(info[DEC_CMD_OPTS])
         
        # for notary less mode user sign with his own key                                                                                                     
        sign_req = self.notary_req_sign(req,self._signer)
        ret =  self._send_sign_transaction(topts,sign_req,wait=wait if wait else TRANS_TOUT) 
        fret = { "addr" : info[DEC_CMD_OPTS][DEC_TARGET_OP][DEC_TARGET_ADDR],"ret" : { "status" : ret[0],"batch-id": ret[1]}}

        return fret

    def get_alias_opts(self,args):                                           
        alias = self.get_only_wallet_opts(args)
        # keep hashed alias 
        alias[DEC_ALIAS_OP] = key_to_dgt_addr(args.alias_name) 
        if args.disable:
            # for already created aliase - disable them
            alias[DEC_ALIAS_DIS] = True
        return alias                                                         


    def alias(self,args,wait=None):                                                                                                                        
                                                                                                                                                          
        tcurr = time.time()                                                                                                                               
        info = {}                                                                                                                                         
        alias = self.get_alias_opts(args)                                                                                                                   
                                                                                                                                                          
        info[DEC_EMITTER] = self._signer.get_public_key().as_hex() 
        alias[DEC_WALLET_ADDR]  =  args.addr if args.addr else   key_to_dgt_addr(info[DEC_EMITTER])                                                                                   
        info[DEC_PAYLOAD] = {                                                                                                                             
                              DEC_ALIAS_OP : alias,                                                                                                         
                              DEC_TMSTAMP : tcurr,                                                                                                        
                              DEC_DID_VAL : DEFAULT_DID if args.did is None else args.did                                                                 
                            } 
        din = [(DEC_EMISSION_KEY,DEC_EMISSION_GRP,DEFAULT_DID)]                                                                                                                            
        
        return self._send_transaction(DEC_ALIAS_OP, (alias[DEC_ALIAS_OP],DEC_SYNONYMS_GRP,args.did), info, to=None, wait=wait if wait else TRANS_TOUT,din=din)       


    def user_sign_req(self,info):                                                  
        topts = info[DEC_TRANS_OPTS]                                            
        req = self.dec_req_sign(info[DEC_CMD_OPTS])                             
        return {DEC_CMD_OPTS : req, DEC_TRANS_OPTS: info[DEC_TRANS_OPTS]}       

    def target_req(self,args): 
        info = self.target_info(args) 
        return self.user_sign_req(info)                
        
        

    def dec_req_sign(self,info):  
        # sign dec request by owner 
        # info - data relating to dec operation
        #  

        # this is header of request with owner sign
        req_header = {
                DEC_EMITTER     : self._signer.get_public_key().as_hex(),
                DEC_PAYLOAD     : info,
            
        }                                                                           
        payload = cbor.dumps(req_header)                                                                           
        psignature = self._signer.sign(payload)   
        # 
        #  NotaryRequest is body of request with signed header  
        #  
        req = {
                DEC_EMITTER          : req_header[DEC_EMITTER],
                DEC_NOTARY_REQ_SIGN  : psignature,
                DEC_PAYLOAD          : payload
            }
        #ret = self._signer.verify(psign, payload,self._context.pub_from_hex(info[DEC_EMITTER]) )            
        #if not ret:                                                                                         
        #    print('BAD SIGN')                                                                               
        return req                                                                            

    def notary_req_sign(self,req,nsigner):
        # this is header of notary signed request
        notary_hdr = {
                    DEC_NOTARY_KEY      : nsigner.get_public_key().as_hex(),
                    DEC_NOTARY_REQ_SIGN : req[DEC_NOTARY_REQ_SIGN] 
                 }
        hpayload = cbor.dumps(notary_hdr)
        hsignature = nsigner.sign(hpayload)
        # this is user request signed twice - user and notary
        notary_request_sign = {
                                DEC_HEADER_PAYLOAD : hpayload, # keep signature for user signed request
                                DEC_HEADER_SIGN    : hsignature,
                                DEC_PAYLOAD        : req[DEC_PAYLOAD] # keep user public key 
                              }
        return notary_request_sign

    def notary_approve(self,req,wait=None):
        return self._send_sign_transaction(req[DEC_TRANS_OPTS],req[DEC_CMD_OPTS],wait=wait)

    def get_role_opts(self,args):
        role = self.load_json_proto(args.role_proto)   
        if args.limit is not None:                     
            # set transfer                             
            role[DEC_WALLET_LIMIT] = args.limit        
        if args.type is not None:                      
            # set transfer                             
            role[DEC_ROLE_TYPE] = args.type
        #if args.did is not None:
        #    role[DEC_DID_VAL] = args.did
        return role            



    def role(self,args,wait=None):                                                                                      
        
        tcurr = time.time()  
        info = {}                                                                                             
        role = self.get_role_opts(args)
            
        info[DEC_EMITTER] = self._signer.get_public_key().as_hex()                                                        
        info[DEC_PAYLOAD] = {
                              DEC_ROLE_OP : role,
                              DEC_TMSTAMP : tcurr,
                              DEC_DID_VAL : DEFAULT_DID if args.did is None else args.did
                            }
        #role_addr = self._get_full_addr(args.role_id,tp_space=DEC_ROLE_GRP,owner=args.did)
        return self._send_transaction(DEC_ROLE_OP, (args.role_id,DEC_ROLE_GRP,args.did), info, to=None, wait=wait if wait else TRANS_TOUT,din=None)                   
                                                                                                                          
        
    def do_addr(self,args):
        pub_key = self.get_pub_key(args.key)
        addr = key_to_dgt_addr(pub_key)
        return addr

    def bank_list(self,args,wait=None):                                                
        pass   
    #  Banking cmd parts END
    #                                                                 
    def set(self, name, value, wait=None):
        return self._send_transaction(DEC_SET_OP, (name,DEC_SIMPLE_GRP,DEFAULT_DID), value, to=None, wait=wait)

    def inc(self, name, value, wait=None):
        return self._send_transaction(DEC_INC_OP, (name,DEC_SIMPLE_GRP,DEFAULT_DID), value, to=None, wait=wait)

    def dec(self, name, value, wait=None):
        return self._send_transaction(DEC_DEC_OP, (name,DEC_SIMPLE_GRP,DEFAULT_DID), value, to=None, wait=wait)

    def trans(self, name, value, to, wait=None):
        return self._send_transaction(DEC_TRANS_OP, (name,DEC_SIMPLE_GRP,DEFAULT_DID), value, to=to, wait=wait)

    def list(self,args):
        if False:
            # for test only
            test_eth_list()
            return []
        pref = self._get_prefix() if args.type is None and args.did is None else self._get_full_prefix(args.type,args.did)
        #print('PREF',pref)
        limit = ''
        if args.limit:
            limit = "&limit={}".format(args.limit)
        if args.start: 
            saddr =  args.start.split(':') 
            if len(saddr) > 1:
                stp = saddr[1]
                name,tp = self.get_name_tp(saddr[0],stp) 
                   
                saddress = self._get_full_addr(name,tp,args.did if args.did else DEFAULT_DID)
            else:
                saddress = saddr[0]
            limit += "&start={}".format(saddress)
            #print("PAGING",saddress,limit)  

        result = self._send_request("state?address={}{}".format(pref,limit))
        #print('res',result)
        try:
            sres = yaml.safe_load(result)
            encoded_entries = sres["data"]

            dlist = [
                cbor.loads(base64.b64decode(entry["data"]))
                for entry in encoded_entries
            ]
            if "paging" in sres and "next_position" in sres["paging"]:
                print("NEXT",sres["paging"]["next_position"])
            return dlist

        except BaseException:
            return None
    def show(self,args, name):
        #print("emission_key",args.type,name,args.did)
        return self.get_object(args.type,args.did,name)

    def corpaccount(self,args):
        emission_key = ANY_EMISSION_KEY.format(args.name)
        #print("emission_key",emission_key,args.did)
        token = self.get_object(DEC_EMISSION_GRP,args.did,emission_key)  #  DEC_TARGET_GRP   
                                                                         
        dec = cbor.loads(token.dec)  
        #print("token",dec)
        if DEC_СORPORATE_ACCOUNT in dec:
            addr = dec[DEC_СORPORATE_ACCOUNT][DATTR_VAL][DEC_CORP_ACC_ADDR]
            owners = dec[DEC_CORPORATE_PUB_KEY][DATTR_VAL]
            try:
                token = self.get_object(DEC_WALLET_GRP,args.did,addr)
            except Exception as ex:
                print("not created yet",addr)
                return dec
            dec = cbor.loads(token.dec)
            dec[DEC_CORPORATE_PUB_KEY] = owners
        else:
            dec = {'account' : "undefined"}
        return dec              

    def get_name_tp(self,addr,tp):
        if addr in [DEC_HEART_BEAT_KEY,DEC_EMISSION_KEY,DEC_ESIGNERS_KEY] or DEC_TRANS_KEY.format('') in addr :            
            tp = DEC_EMISSION_GRP                                    
            name = addr
        elif tp == DEC_SIMPLE_GRP:
            name = addr                                              
        elif is_alias(addr):                                         
            # check alias                                            
            name = key_to_dgt_addr(addr)                             
            tp = DEC_SYNONYMS_GRP  
            #name1 = key_to_dgt_addr(self.get_pub_key(addr))   
            #print("get_pub_key")           
                                              
            #print("treat as alias",name,name1) 
        else:                                                        
            name,tp = self.get_pub_key(addr), DEC_WALLET_GRP  
            #print("get_pub_key") 
            if not name.startswith(DGT_ADDR_PREF):
                name = key_to_dgt_addr(name)
                
        #print("name,tp",name,tp)
        return name,tp                        

    def get_object(self,tp,did, addr):

        npart = addr.split("::")
        if len(npart) > 1:
            name,did = npart[0],npart[1] 
        else:
            name,tp = self.get_name_tp(addr,tp)    
        #print('get_object,',name,tp,did)    
        address = self._get_full_addr(name,tp,did) 
        #print(name,tp,did,'ADDR',address)
        result = self._send_request("state/{}".format(address), name=name,)

        try:
            val = cbor.loads(base64.b64decode(yaml.safe_load(result)["data"]))[name]
            token = DecTokenInfo()       
            token.ParseFromString(val)
            return token 
        except BaseException:
            return None

    def _get_status(self, batch_id, wait):
        try:
            result = self._send_request('batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            vres = yaml.safe_load(result)
            data = vres['data'][0]
            status = data['status']
            if status == 'INVALID':
                print("Transaction invalid={}".format(data['invalid_transactions'][0]['message']))
            return status
        except BaseException as err:
            raise DecClientException(err)

    def _get_prefix(self):
        return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]

    def _get_full_prefix(self,tp=None,owner=None):                                    
        fam_pref =  self._get_prefix() 
        tp_pref = self._get_type_prefix(DEC_TARGET_GRP if tp is None else tp)
        own_pref = self._get_user_prefix(owner) if owner else ''
        return ''.join([fam_pref,tp_pref,own_pref]) 

    def _get_type_prefix(self,tp_space):                                  
        return _sha256(tp_space.encode('utf-8'))[0:2]

    def _get_user_prefix(self,user):              
        return _sha256(user.encode('utf-8'))[:22]     

    def _get_address(self, name,space=None):
        prefix = self._get_prefix()
        dec_address = _sha512(name.encode('utf-8'))[64:]
        return prefix + dec_address

    def _get_full_addr(self, name,tp_space=DEC_TARGET_GRP,owner="def"):
        #c2939e264c1029697ee358715d3a14a2add817c4b0165144b5eb1f51756bcd9685098e
        #0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
        prefix = self._get_prefix()  
        tp_prefix = self._get_type_prefix(tp_space)
        usr_prefix = self._get_user_prefix(owner)                         
        dec_address = _sha256(name.encode('utf-8'))[:40]     
        return ''.join([prefix,tp_prefix,usr_prefix,dec_address])                          

        
    def _send_request(self, suffix, data=None, content_type=None, name=None):

        if self.url.startswith("http://") or self.url.startswith("https://"):
            url = "{}/{}".format(self.url, suffix)
        else:
            url = "{}://{}/{}".format('https' if os.environ.get('HTTPS_MODE') == '--http_ssl' else 'http',self.url, suffix)
        
        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = self._requests.post(url, headers=headers, data=data,verify=False)
            else:
                result = self._requests.get(url, headers=headers,verify=False) 

            if result.status_code == 404:
                raise DecClientException("No such key: {}".format(name))

            elif not result.ok:
                raise DecClientException("Error {}: {}".format(result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise DecClientException('Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise DecClientException(err)

        return result.text

    def _make_transaction(self, verb, name, value, to=None,din=None,din_ext=None):                                                                  
        val = {                                                                                                                                   
            DEC_CMD    : verb,                                                                          
            DEC_CMD_ARG: name,                                                                                                                             
            DEC_CMD_VAL: value, # sign twice                                                                                                                            
        }                                                                                                                                        
        if to is not None:  
            if not isinstance(to,list):    
                to = [to]  
            #tval = to[0]                                                                                                               
            val[DEC_CMD_TO] = to #tval[0] if isinstance(tval,tuple) else tval                                                                                                                      
                                                                                                                                                  
        hex_pubkey =  self._signer.get_public_key().as_hex()                                                                                                                                       
        sign_val = {} 
                                                                                                                                                
        # Construct the address                                                                                                                   
        address = self._get_full_addr(name[0],name[1],name[2])#self._get_address(name) 
        #print('NAME',address)                                                                                                        
        inputs = [address]                                                                                                                        
        outputs = [address]                                                                                                                       
        if to is not None: 
            for tval in to:
                address_to = self._get_full_addr(tval[0],tval[1],tval[2]) if isinstance(tval,tuple) else self._get_address(tval)
                inputs.append(address_to)                                                                                                             
                outputs.append(address_to) 
                #print("TO",tval[0],address_to)
        dinputs = []                                                                                                            
        if din is not None:                                                                                                                       
            for ain in (din if isinstance(din,list) else [din]):                                                                                                                   
                address_in = self._get_full_addr(ain[0],ain[1],ain[2]) if isinstance(ain,tuple) else self._get_address(ain)                                                                                               
                inputs.append(address_in) 
                dinputs.append((FAMILY_NAME,ain[0],ain[1],ain[2])) #(FAMILY_NAME,ain[0] if isinstance(ain,tuple) else ain))

        if din_ext is not None:
            # external family 
            dinputs_ext = din_ext if isinstance(din_ext,list) else [din_ext]
            for fam,ain in dinputs_ext:
                if fam == SETTINGS_NAMESPACE:
                    address_in = _make_settings_key(ain)
                    inputs.append(address_in)
                    dinputs.append((fam,ain))
        # input list
        val[DATTR_INPUTS] = dinputs
                                                                                                                                                  
        #print("in={} out={} din={}".format(inputs,outputs,dinputs))
        payload = cbor.dumps(val)
        psign = self._signer.sign(payload) # for fool notary mode this is notary node sign 
        sign_val[DEC_SIGNATURE] =  psign
        sign_val[DEC_PUBKEY]    = hex_pubkey
        sign_val[DATTR_VAL]     =  payload                                                                                         
        spayload = cbor.dumps(sign_val)  
        
        #print("PSIGN={}".format(psign))                                                                                                               
        header = TransactionHeader(                                                                                                               
            signer_public_key=hex_pubkey,                                                                             
            family_name=FAMILY_NAME,                                                                                                              
            family_version=FAMILY_VERSION,                                                                                                        
            inputs=inputs,                                                                                                                        
            outputs=outputs,                                                                                                                      
            dependencies=[],                                                                                                                      
            payload_sha512=_sha512(spayload),                                                                                                      
            batcher_public_key=hex_pubkey,                                                                            
            nonce=hex(random.randint(0, 2**64))                                                                                                   
        ).SerializeToString()                                                                                                                     
                                                                                                                                                  
        signature = self._signer.sign(header)                                                                                                     
                                                                                                                                                  
        transaction = Transaction(                                                                                                                
            header=header,                                                                                                                        
            payload=spayload,                                                                                                                      
            header_signature=signature                                                                                                            
        ) 
        return transaction                                                                                                                                        


    def _send_transaction(self, verb, name, value, to=None, wait=None,din=None,din_ext=None):
        transaction = self._make_transaction(verb,name,value,to,din,din_ext)
        batch_list = self._create_batch_list([transaction])
        batch_id = batch_list.batches[0].header_signature

        if wait and wait > 0:
            wait_time = 0
            start_time = time.time()
            response = self._send_request(
                "batches", batch_list.SerializeToString(),
                'application/octet-stream',
            )
            #print("RESPONSE={}".format(response))
            status = 'PENDING'
            while wait_time < wait:
                status = self._get_status(
                    batch_id,
                    wait - int(wait_time),
                )
                wait_time = time.time() - start_time
                #print("STATUS={}".format(status))
                if status != 'PENDING':
                    return (status,batch_id) #response

            return (status,batch_id) # response

        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
        )

    def _send_sign_transaction(self, topts, info,wait=None): 
        to      = topts[DEC_CMD_TO] if DEC_CMD_TO in topts else None
        din     = topts[DEC_CMD_DIN] if DEC_CMD_DIN in topts else None
        din_ext = topts[DEC_CMD_DIN_EXT] if DEC_CMD_DIN_EXT in topts else None
        return self._send_transaction(topts[DEC_CMD], topts[DEC_CMD_ARG], info, to=to, wait=wait,din=din,din_ext=din_ext)


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


