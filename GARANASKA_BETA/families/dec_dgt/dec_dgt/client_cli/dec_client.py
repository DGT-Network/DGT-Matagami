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

from dgt_signing import create_context
from dgt_signing import CryptoFactory
from dgt_signing import ParseError

from dgt_sdk.protobuf.transaction_pb2 import TransactionHeader
from dgt_sdk.protobuf.transaction_pb2 import Transaction
from dgt_sdk.protobuf.batch_pb2 import BatchList
from dgt_sdk.protobuf.batch_pb2 import BatchHeader
from dgt_sdk.protobuf.batch_pb2 import Batch
from dec_common.protobuf.dec_dgt_token_pb2 import DecTokenInfo

from dec_dgt.client_cli.exceptions import DecClientException
from dec_dgt.client_cli.dec_attr import *
from dgt_validator.gossip.fbft_topology import DGT_TOPOLOGY_SET_NM

# settings family
from dgt_settings.processor.utils import _make_settings_key,SETTINGS_NAMESPACE

def _sha512(data):
    return hashlib.sha512(data).hexdigest()

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
    if attr in info:
        if val:
            info[attr][DATTR_VAL] = val
    else:
        info[attr] = {DATTR_VAL : val if val else def_val}


class DecClient:
    def __init__(self, url=None, keyfile=None,signer=None,backend=None):
        self.url = url

        if keyfile is not None:
            print("use keyfile {}".format(keyfile))
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
        elif signer:
            self._signer = signer

    def load_json_proto(self,value):
        if isinstance(value,dict):                        
            info = value                                  
        else:                                             
            with open(value,"r",encoding='utf8') as cert_file:            
                try:                                      
                    info =  json.load(cert_file)          
                                                          
                except Exception as ex: 
                    print('Cant load file {} - {}'.format(value,ex))                  
                    info = {}  
        return info                           
    @property
    def signer_as_hex(self):
        return self._signer.get_public_key().as_hex()
    # emission cmd parts
    def emission(self,args,wait=None):
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
        # take mint params
        mint_val = info[DEC_MINT_PARAM][DATTR_VAL] if DEC_MINT_PARAM in info else {DEC_MINT_COEF_UMAX: 10,DEC_MINT_COEF_T1:1 ,DEC_MINT_COEF_B2:1}
        if args.mint_umax:
            mint_val[DEC_MINT_COEF_UMAX] = float(args.mint_umax)
        if args.mint_t1:                               
            mint_val[DEC_MINT_COEF_T1] = float(args.mint_t1)
        if args.mint_b2:                               
            mint_val[DEC_MINT_COEF_B2] = float(args.mint_b2)
        set_param(info,DEC_MINT_PARAM,args.mint,mint_val)

        if args.corporate_pub_key:
            # check when create corporate wallet - only owner this key have responsibilities for operation
            info[DEC_CORPORATE_PUB_KEY] = {DATTR_VAL : args.corporate_pub_key}
        else:
            info[DEC_CORPORATE_PUB_KEY] = {DATTR_VAL : self._signer.get_public_key().as_hex()}

        info[DEC_TMSTAMP] = time.time()
        info[DEC_EMITTER] = self._signer.get_public_key().as_hex()
        #print('PROTO',info)
        self._send_transaction(DEC_EMISSION_OP, DEC_EMISSION_KEY, info, to=None, wait=wait,din_ext=(SETTINGS_NAMESPACE,DGT_TOPOLOGY_SET_NM))

    def wallet(self,args,wait=None,nsign=None):  
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
                                                             
        info[DEC_DID_VAL] = { DEC_DID_VAL   : payload,       
                              DEC_SIGNATURE : psign          
                            } 
                                                                      
        info[DEC_WALLET_OPTS_OP] = self.get_wallet_opts(args,nsign)
        
                                     
        info[DEC_TMSTAMP] = time.time() 
        #print("DEC.wallet {}".format(info))                                        
        return self._send_transaction(DEC_WALLET_OP, self._signer.get_public_key().as_hex(), info, to=None, wait=wait, din=None) # DEC_EMISSION_KEY 

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
            
        print("DEC.wallet opts{}".format(opts))
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
        return self._send_transaction(DEC_WALLET_OPTS_OP, self._signer.get_public_key().as_hex(), info, to=None, wait=wait, din=None) # DEC_EMISSION_KEY            



    def birth(self,args,wait=None):
        token = self.show(DEC_EMISSION_KEY)
        dec = cbor.loads(token.dec) if token.group_code == DEC_NAME_DEF else {}   
        tmstamp = dec[DEC_TMSTAMP] if DEC_TMSTAMP in dec else 0
        return tmstamp


    def total_supply(self,args,wait=None):  
        token = self.show(DEC_EMISSION_KEY)                                     
        dec = cbor.loads(token.dec) if token.group_code == DEC_NAME_DEF else {} 
        return dec[DEC_TOTAL_SUM] if DEC_TOTAL_SUM in dec else 0
    
       
           
    def token_info(self,args,wait=None):    
        token = self.show(DEC_EMISSION_KEY)
        info = {}    
        if token.group_code == DEC_NAME_DEF :
            dec = cbor.loads(token.dec)
            for attr,aval in dec.items():
                if attr not in [DEC_PASSKEY,DEC_MINTING_TOTAL,DEC_СORPORATE_TOTAL,DEC_SALE_TOTAL,DEC_TMSTAMP]:
                    info[attr] = aval[DATTR_VAL]
                
            
        return info
        
    def burn(self,args,wait=None):   
        info = {}
        if args.passkey and args.sum:
            info[DEC_PASSKEY] = args.passkey
            info[DEC_TOTAL_SUM] = args.sum
            print('PROTO',info)                                                                 
            self._send_transaction(DEC_BURN_OP, DEC_EMISSION_KEY, info, to=None, wait=wait)
        else:
            print('Set  passkey and burn_sum argument')

    def change_mint(self,args,wait=None):
        info = {}                                                                                    
        if args.passkey:                                                                
            info[DEC_PASSKEY] = args.passkey 
            if args.mint:
                try:
                    info[DEC_MINT_PARAM] = json.loads(args.mint) 
                except Exception as ex :
                    print('Cant load ({}) - {}'.format(args.mint,ex))
                    return
            elif args.mint_umax or args.mint_t1 or args.mint_b2:
                # take mint params 
                mint_val = {}                                                                                                                                    
                if args.mint_umax:                                                                                                                                     
                    mint_val[DEC_MINT_COEF_UMAX] = float(args.mint_umax)                                                                                               
                if args.mint_t1:                                                                                                                                       
                    mint_val[DEC_MINT_COEF_T1] = float(args.mint_t1)                                                                                                   
                if args.mint_b2:                                                                                                                                       
                    mint_val[DEC_MINT_COEF_B2] = float(args.mint_b2)                                                                                                   
                info[DEC_MINT_PARAM] = mint_val
            else:
                print('Set some mint params')
                return 

            info[DEC_EMITTER] = self._signer.get_public_key().as_hex()
            print('PROTO',info)                                                                      
            self._send_transaction(DEC_CHANGE_MINT_OP, DEC_EMISSION_KEY, info, to=None, wait=wait)          
        else:                                                                                        
            print('Set  passkey')                                              


    def distribute(self,args,wait=None):    
        token = self.show(DEC_EMISSION_KEY)               
        info = {}                                         
        if token.group_code == DEC_NAME_DEF :             
            dec = cbor.loads(token.dec)                        
            for attr in [DEC_MINTING_TOTAL,DEC_СORPORATE_TOTAL,DEC_SALE_TOTAL]:
                info[attr] = dec[attr]
        return info                                       



    def faucet(self,args,wait=None):  
        if args.passkey:  
            info = {}                                                              
            info[DEC_PASSKEY] = args.passkey                                                        
            info[DATTR_VAL]   = args.value                                       
            print('PROTO',info)                                                                     
            self._send_transaction(DEC_FAUCET_OP, args.pubkey, info, to=DEC_EMISSION_KEY, wait=wait)  
        else:                                                                                       
            print('Set  passkey argument')                                           


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
        self._send_transaction(DEC_MINT_OP, args.pubkey, info, to=DEC_HEART_BEAT_KEY, wait=wait,din=[DEC_EMISSION_KEY])                  


    def heart_beat(self,args,wait=None):      
        info = {}                                                                                       
        if args.passkey:                                                                                    
            info[DATTR_VAL]   = args.passkey                                                                
        if args.period:                                                                                    
            info[DEC_HEART_BEAT_PERIOD] = args.period  

        info[DEC_TMSTAMP] = time.time()
                                                                    
        self._send_transaction(DEC_HEART_BEAT_OP, DEC_HEART_BEAT_KEY, info, to=None, wait=wait,din=None) #DEC_EMISSION_KEY) 

    def make_heart_beat_tnx(self,passkey=None,period=None,peers=[]):
        info = {}                                
        if passkey:                              
            info[DATTR_VAL]   = passkey          
        if period:                               
            info[DEC_HEART_BEAT_PERIOD] = period
        info[DEC_HEART_BEAT_PEERS] = peers
        info[DEC_TMSTAMP] = time.time()
        return self._make_transaction(DEC_HEART_BEAT_OP,DEC_HEART_BEAT_KEY,info,to=None,din=DEC_EMISSION_KEY)

    
    def seal_count(self,args,wait=None):                            
        pass  
                                                    
    #
    # banking cmd parts  
    # 
    def balance_of(self,args,wait=None):
        return self.get_balance_of(args.pubkey,wait)

    def get_balance_of(self,pubkey,wait=None):  
        token = self.show(pubkey)  
        return token

    def send(self,args,wait=None): 
        # use this cmd for sending token to corporate wallet 
        # use as name _DEC_EMISSION_KEY_
        info = {DATTR_VAL : args.amount}
        din = [DEC_EMISSION_KEY]
        if args.asset_type:
            info[DEC_ASSET_TYPE] = args.asset_type             
        if args.did:                                
            info[DEC_DID_VAL] = args.did
        if args.role:                             
            info[DEC_WALLET_ROLE] = args.role     
            din.append(args.role)                 



        info[DEC_EMITTER] = self._signer.get_public_key().as_hex()
        info[DEC_TMSTAMP] = time.time()
        return self._send_transaction(DEC_SEND_OP, args.name, info, to=args.to, wait=wait,din=din)  

    def pay(self,args,wait=None,control=False):      
        info = {DATTR_VAL : args.amount}                                                                         
        if args.asset_type:                                                                                      
            info[DEC_ASSET_TYPE] = args.asset_type                                                               
        if args.did:                                                                                             
            info[DEC_DID_VAL] = args.did                                                                         

        to = [args.to]
        din = [DEC_EMISSION_KEY]
        if args.target :
            # target with invoice
            to.append(args.target)

        if args.provement_key:      
            # invoice ID for controle                  
            info[DEC_PROVEMENT_KEY] = args.provement_key 
        if args.role:
            info[DEC_WALLET_ROLE] = args.role
            din.append(args.role)

        info[DEC_EMITTER] = self._signer.get_public_key().as_hex()
        info[DEC_TMSTAMP] = time.time()
        print('emmiter',info[DEC_EMITTER])
        if wait is None and control:
            # wait transaction commit
            wait = 10
        resp =  self._send_transaction(DEC_PAY_OP, args.name, info, to=to, wait=wait,din=din) 
        return resp
         
    
     
    def invoice(self,args,wait=None):   
        info = {DATTR_VAL : args.amount}                                                                         
        tcurr = time.time()
        info[DEC_PROVEMENT_KEY] = args.prove_key 
        info[DEC_CUSTOMER_KEY] = args.customer if args.customer else None
        if args.available_till:                                                                                   
            info[AVAILABLE_TILL] = tcurr + args.available_till                                                         
        info[DEC_TMSTAMP] = tcurr 
        din = [DEC_EMISSION_KEY]
        if args.customer:
            din.append(args.customer) 
        info[DEC_EMITTER] = self._signer.get_public_key().as_hex()                                                                                                       
        return self._send_transaction(DEC_INVOICE_OP, args.target, info, to=None, wait=wait,din=din)   

    def get_target_opts(self,args):
        target = {}
        target[DEC_TARGET_PRICE] = args.price
        target[DEC_TARGET_INFO] = args.target if args.target else DEC_TARGET_INFO_DEF
        if args.invoice > 0:                                                                 
            target[DEC_INVOICE_OP] = {DEC_CUSTOMER_KEY : None,DEC_TARGET_PRICE :args.price} 
        return target


    def target(self,args,wait=None):                                                                                                          
        info = {}                                                                                                       
        tcurr = time.time()                                                                                                                    
        info[DEC_TARGET_OP] = self.get_target_opts(args)
        info[DEC_EMITTER] = self._signer.get_public_key().as_hex()   
        info[DEC_TMSTAMP] = tcurr   
        if args.did:                         
            # refer to DID owner             
            info[DEC_DID_VAL] = args.did                                                                                                                
        return self._send_transaction(DEC_TARGET_OP, args.target_id, info, to=None, wait=wait,din=None) 
     
    def get_role_opts(self,args):
        role = self.load_json_proto(args.role_proto)   
        if args.limit is not None:                     
            # set transfer                             
            role[DEC_WALLET_LIMIT] = args.limit        
        if args.type is not None:                      
            # set transfer                             
            role[DEC_ROLE_TYPE] = args.type
        return role            



    def role(self,args,wait=None):                                                                                      
        
        tcurr = time.time()  
        info = {}                                                                                             
        role = self.get_role_opts(args)
            
        info[DEC_EMITTER] = self._signer.get_public_key().as_hex()                                                        
        info[DEC_TMSTAMP] = tcurr 
        info[DEC_ROLE_OP] = role 
        if args.did:
            # refer to DID owner
            info[DEC_DID_VAL] = args.did
        return self._send_transaction(DEC_ROLE_OP, args.role_id, info, to=None, wait=wait,din=None)                   
                                                                                                                          
        
    
    def bank_list(self,args,wait=None):                                                
        pass   
    #  Banking cmd parts END
    #                                                                 
    def set(self, name, value, wait=None):
        return self._send_transaction(DEC_SET_OP, name, value, to=None, wait=wait)

    def inc(self, name, value, wait=None):
        return self._send_transaction(DEC_INC_OP, name, value, to=None, wait=wait)

    def dec(self, name, value, wait=None):
        return self._send_transaction(DEC_DEC_OP, name, value, to=None, wait=wait)

    def trans(self, name, value, to, wait=None):
        return self._send_transaction(DEC_TRANS_OP, name, value, to=to, wait=wait)

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
            result = self._send_request(
                'batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise DecClientException(err)

    def _get_prefix(self):
        return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]

    def _get_address(self, name,space=None):
        prefix = self._get_prefix()
        dec_address = _sha512(name.encode('utf-8'))[64:]
        return prefix + dec_address

    def _send_request(self, suffix, data=None, content_type=None, name=None):
        if self.url.startswith("http://"):
            url = "{}/{}".format(self.url, suffix)
        else:
            url = "http://{}/{}".format(self.url, suffix)

        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if result.status_code == 404:
                raise DecClientException("No such key: {}".format(name))

            elif not result.ok:
                raise DecClientException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise DecClientException(
                'Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise DecClientException(err)

        return result.text

    def _make_transaction(self, verb, name, value, to=None,din=None,din_ext=None):                                                                  
        val = {                                                                                                                                   
            'Verb': verb,                                                                                                                         
            'Name': name,                                                                                                                         
            'Value': value,                                                                                                                       
        }                                                                                                                                         
        if to is not None:                                                                                                                        
            val['To'] = to                                                                                                                        
                                                                                                                                                  
        hex_pubkey =  self._signer.get_public_key().as_hex()                                                                                                                                       
        sign_val = {} 
                                                                                                                                                
        # Construct the address                                                                                                                   
        address = self._get_address(name)                                                                                                         
        inputs = [address]                                                                                                                        
        outputs = [address]                                                                                                                       
        if to is not None: 
            for tval in to if isinstance(to,list) else [to]:
                address_to = self._get_address(tval)                                                                                                    
                inputs.append(address_to)                                                                                                             
                outputs.append(address_to) 
        dinputs = []                                                                                                            
        if din is not None:                                                                                                                       
            for ain in (din if isinstance(din,list) else [din]):                                                                                                                   
                address_in = self._get_address(ain)                                                                                               
                inputs.append(address_in) 
                dinputs.append((FAMILY_NAME,ain))

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
                                                                                                                                                  
        #print("in={} out={}".format(inputs,outputs))
        payload = cbor.dumps(val)
        psign = self._signer.sign(payload)
        sign_val[DEC_SIGNATURE] =  psign
        sign_val[DEC_PUBKEY] = hex_pubkey
        sign_val[DATTR_VAL] =  payload                                                                                         
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
                    return status #response

            return status # response

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


