# Copyright 2020 DGT NETWORK INC © Stanislav Parsov 
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
import os         
import hvac       
import requests   
import json
import time
import cbor
import subprocess

import bgt_bot_api.exceptions as errors
from dgt_signing.core import X509_COUNTRY_NAME,X509_STATE_OR_PROVINCE_NAME,X509_LOCALITY_NAME,X509_ORGANIZATION_NAME,X509_COMMON_NAME,X509_DNS_NAME,X509_SERIAL_NUMBER
from x509_cert.client_cli.xcert_client import (XcertClient,KEYKEEPER_ID,NOTARY_LEADER_ID,NOTARY_FOLOWER_ID,
                                               NOTARY_TOKEN,NOTARY_URL,NOTARY_NAME,NOTARY_STIME,
                                               XCERT_BEFORE_TM,XCERT_AFTER_TM,NOTARY_UNSEAL_KEYS,NOTARY_ROOT_TOKEN,
                                               NOTARY_CONF_NM,write_conf,read_conf
                                               )

LOGGER = logging.getLogger(__name__)
SHARES = 1 #5       
THRESHOLD = 1 #3    
CONNECT_ATTEMPT = 10
TIMEOUT_VAULT_READY=8 
RECOVERY_SHARES=1
RECOVERY_THRESHOLD=1
SEAL_NODE_NM = 'n1'

policy = '''
path "secret/*" {
    capabilities = ["create", "update", "delete", "list", "read"]
}
path "secret/data/" {
    capabilities = ["create", "update", "delete", "list", "read"]
}
'''
policy_nm = 'dev-policy'
vconf_fnm = NOTARY_CONF_NM
class Vault(object):
    def __init__(self, vault_url,notary=None,lead_addr=None,opts=None):
        self._vault_url = vault_url
        self._vault_token = None # vault_token
        self._notary = notary
        self._keys = {}
        self._rest_api = opts.url
        self._crypto_back = opts.crypto_back
        self._rest = self.init_rest_api()
        self._notary_id =  KEYKEEPER_ID if notary == SEAL_NODE_NM else (NOTARY_LEADER_ID if lead_addr is None else NOTARY_FOLOWER_ID)
        LOGGER.info(f'TRY CONNECT TO NOTARY={self._notary} vault={vault_url} CRYPTO={self._crypto_back} REST={self._rest}')
        
        try:
            self._client = hvac.Client(url=self._vault_url,token=self._vault_token,verify=False)
            self._client.token = self._vault_token
        except Exception as ex:
            LOGGER.info(f"CANT OPEN CONNECT err={ex}")

        self.is_init = None
        for n in range(CONNECT_ATTEMPT):
            try:
                self.is_init = self._client.sys.is_initialized()
            except Exception as ex:
                LOGGER.info(f"VAULT IS NOT READY err={ex}")
                time.sleep(TIMEOUT_VAULT_READY)
        if self.is_init is None:
            LOGGER.info(f"VAULT IS NOT READY")
            return 

        if not self.is_init:
            LOGGER.info(f"NEEDS INITIALIZATION...")
            result = self._client.sys.initialize(SHARES, THRESHOLD,
                                                  recovery_shares=RECOVERY_SHARES if notary != SEAL_NODE_NM else None,
                                                  recovery_threshold=RECOVERY_THRESHOLD if notary != SEAL_NODE_NM else None
                                                 )             
            self._root_token = result[NOTARY_ROOT_TOKEN] 
            # save root token
            self._vault_token = self._root_token                            
            self._keys = result['keys']                                     
            self._client.token = self._vault_token 
            
            LOGGER.info(f"token={self._root_token} keys={self._keys}") 
            self.is_init = True 
            write_conf({NOTARY_ROOT_TOKEN:self._root_token,NOTARY_UNSEAL_KEYS:self._keys})
            self.unseal()

            if notary == SEAL_NODE_NM and False:
                # for n1
                self.enable_secrets_engine('kv',"transit")
                self.create_key(name="unseal_key")
                #self.create_or_update_secret("transit/keys/unseal_key",secret=self._keys)
                list_keys_response = self._client.secrets.transit.read_key(name='unseal_key')
                LOGGER.info(f"TRANSIT KEY={list_keys_response} ...")

            if notary != SEAL_NODE_NM and lead_addr is None:
                #read_response = self._client.sys.read_init_status()
                read_response = self._client.sys.read_health_status(method='GET',active_code=100)
                LOGGER.info(f"READ STATUS {read_response}...")
                status = self._client.sys.read_leader_status()
                LOGGER.info(f"READ_LEADER_STATUS {status}...")
                #self.create_or_update_secret("cubbyhole/user_key",secret="mykey")

            self.upd_meta_xcert({NOTARY_TOKEN:self._root_token,NOTARY_URL:self._vault_url},self._notary_id,init=True)
            if notary == SEAL_NODE_NM:
                # subprocess.call
                ret = os.system(f"export VAULT_ADDR={self._vault_url} VAULT_TOKEN={self._root_token};vault secrets enable transit && vault write -f transit/keys/unseal_key")
                LOGGER.info(f"SAVE  SECRETS {ret}...")
            elif lead_addr is None:
                # leader - # enable kv engine
                kv_enable = False
                for n in range(CONNECT_ATTEMPT):
                    self.create_policy(policy=policy,name=policy_nm)    
                    kv_enable = self.enable_secrets_engine('kv',"secret/data/")  
                    if kv_enable:
                        LOGGER.info(f"KV  SECRETS ENABLE")
                        break
                    time.sleep(6)
                # for n1 
                # vault secrets enable transit           
                #  vault write -f transit/keys/unseal_key 
        else:
            # for follower node status is already initialized
            LOGGER.info(f"ALREADY INITIALIZED ...")
            vconf = read_conf()
            if vconf != {}:
                self._keys = vconf[NOTARY_UNSEAL_KEYS]
                self._vault_token = vconf[NOTARY_ROOT_TOKEN]
                self._client.token = self._vault_token
                self.unseal()
                self.upd_meta_xcert({NOTARY_TOKEN:self._vault_token,NOTARY_URL:self._vault_url},self._notary_id)
            else:
                if notary != SEAL_NODE_NM and lead_addr is not None:
                    for n in range(CONNECT_ATTEMPT):
                        self._is_sealed = self._client.sys.is_sealed()
                        LOGGER.info(f"CHECK[{n}] SEALED {self._is_sealed}...")
                        if not self._is_sealed :
                            break

            #list_keys_response = self._client.secrets.transit.read_key(name='unseal_key')
            #LOGGER.info(f"TRANSIT KEY={list_keys_response} ...")



            if notary != SEAL_NODE_NM and lead_addr is None:            
                status = self._client.sys.read_leader_status()   
                LOGGER.info(f"READ_LEADER_STATUS {status}...")  



        #sdown = self._client.sys.step_down()
        LOGGER.info(f"CONNECTED to={vault_url}")
        if False:
            raft_config = self._client.sys.read_raft_config()
            led_status = None #self._client.sys.read_leader_status()
            LOGGER.info(f"RAFT={raft_config} leader={led_status}")
            
        
        
        if self.is_init:
            if lead_addr is not None:
                self.join_cluster(lead_addr)

            if notary == SEAL_NODE_NM and False:
                list_keys_response = self._client.secrets.transit.read_key(name='unseal_key')   
                LOGGER.info(f"TRANSIT KEY={list_keys_response} ...")                            

            #self.create_policy(policy=policy,name=policy_nm)
            self.list_policies()
            self.read_policy(name=policy_nm)
            self.list_mounted_secrets_engines()
            #self.enable_secrets_engine('kv',"secret/data/")
            # testing only
            #self.create_xcert({'email':"trt@mail.ru"},uid='foo')
            
    def unseal(self):
        self._is_sealed = self._client.sys.is_sealed()                                 
        if  self._is_sealed:                                                           
            LOGGER.info(f"TRY TO UNSEAL")                                              
            unseal_response = self._client.sys.submit_unseal_keys(self._keys)          
            LOGGER.info(f"UNSEAL DONE {unseal_response}")                              
            self._is_sealed = self._client.sys.is_sealed()                             
                                                                                       
    def join_cluster(self,lead_addr):
        try:                                                                            
            ret = self._client.sys.join_raft_cluster(leader_api_addr=lead_addr) 
            LOGGER.info(f"JOIN CLUSTER {lead_addr} ret={ret}")        
        except Exception as ex:                                                         
            LOGGER.info(f"CANT JOIN CLUSTER {lead_addr} err={ex}")                                 


    def list_policies(self):
        try:                                                                           
            policies = self._client.sys.list_policies() #['data']['policies']          
            LOGGER.info(f"POLICIES={policies}")                                        
        except hvac.exceptions.Forbidden as ex:  
            LOGGER.info(f"LIST POLICIES err ={ex}")
        except hvac.exceptions.VaultDown as ex:
            LOGGER.info(f"LIST POLICIES err ={ex}") 
        except    Exception as ex:
            LOGGER.info(f"LIST POLICIES err ={ex}")

    def create_policy(self,policy=None,name=None):
        try:
            self._client.sys.create_or_update_policy(
                name=name,
                policy=policy,
            )
        except Exception as ex:
            LOGGER.info(f"CANT CREATE POLICY err={ex}")

    def read_policy(self,name):
        try:
            policy = self._client.sys.read_policy(name=name)
            LOGGER.info(f"POLICY={name} POLICY={policy}")
        except Exception as ex:                         
            LOGGER.info(f"CANT READ POLICY={name} err={ex}") 

    def enable_secrets_engine(self,engine,path):
        try: 
            self._client.sys.enable_secrets_engine(engine, path=path)
            return True
        except Exception as ex:                               
            LOGGER.info(f"CANT ENABLE {engine} {path} err={ex}")
            return False  

    def list_mounted_secrets_engines(self):
        try:
            secrets_engines_list = self._client.sys.list_mounted_secrets_engines()
            LOGGER.info(f"ENGINES={secrets_engines_list['data'] if 'data' in secrets_engines_list else secrets_engines_list}")
            
        except Exception as ex:                         
            LOGGER.info(f"CANT READ MOUNTED_SECRETS_ENGINES err={ex}") 

    def get_xcert(self,uid='456125525'):
        # check xcert for user with uid
        kvc = f"{uid}"
        LOGGER.info(f"TRY TO GET XCERT={kvc}..")
        try:                                                                       
            read_response = self._client.secrets.kv.read_secret_version(path=kvc)        
            LOGGER.info(f"read_response={read_response}") 
            return read_response['data']                               
        except hvac.exceptions.InvalidPath:                                        
            LOGGER.info(f"UNDEFINED={kvc}") 
        except hvac.exceptions.Forbidden as ex:
            LOGGER.info(f"READ SECRET err={ex}")
        except Exception as ex:
            LOGGER.info(f"READ SECRET err={ex}")
            raise errors.VaultNotReady

    def create_xcert(self,args,proto,uid='456125525'):
        LOGGER.info(f"CREATE XCERT[{uid}]={args}")
        #args['uid'] = uid
        did = args['did'] if 'did' in args else uid
        if self.create_or_update_secret(f"{uid}",args):
            # 
            self.upd_user_xcert(proto,str(uid))
            return did
        

    def create_or_update_secret(self,path,secret=None):                                            
        LOGGER.info(f"create_or_update_secret [{path}]={secret}")                                          
        try:                                                                                
            create_response = self._client.secrets.kv.v2.create_or_update_secret(           
                 path=path,                                                                  
                 secret=secret,                                                               
            )                                                                               
            LOGGER.info(f"SUCCESSFULLY CREATE SECRET={path}")                                   
            return True                                                                      
        except Exception as ex:                                                             
            LOGGER.info(f"CANT CREATE SECRET={path} err={ex}") 
            
    def create_key(self,name='unseal_key',ktype='aes256-gcm96'):
        try:
            ret = self._client.secrets.transit.create_key(name=name,key_type=ktype,allow_plaintext_backup=False,derived=False, exportable=False)
            LOGGER.info(f"CREATED key={name} ret={ret}")
            self._client.secrets.transit.update_key_configuration(
                name=name,
                exportable=False,min_decryption_version=1, min_encryption_version=0
                )
            gen_key_response = self._client.secrets.transit.generate_data_key(
                    name=name,
                    key_type='plaintext',
                    )
            LOGGER.info(f"generate data key={name} ret={gen_key_response}")




            LOGGER.info(f"UPDATE key={name} ret={ret}")
        except Exception as ex:
            LOGGER.info(f"CANT CREATE key={name} err={ex}") 

    def init_rest_api(self):
        try:                                                                                                                    
            LOGGER.info(f"CRYPTO BACK={self._crypto_back}")                                                                                 
            client = XcertClient(url=self._rest_api,keyfile=os.path.join("/project/peer", "keys","notary.priv"),backend=self._crypto_back)       
        except Exception as ex:                                                                                                 
            LOGGER.info(f"CANT CREATE XCERT CLIENT {ex}")                                                                             
            client = None
        return client 
    
    def upd_meta_xcert(self,info,key,init=False):
        # meta cert for keykeeper and raft node
        if self._rest is None:
            return
        info[NOTARY_NAME] = self._notary
        info[NOTARY_STIME] = int(time.time())
        if init:
            response = self._rest.set(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM) 
        else:
            response = self._rest.crt(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM)
        LOGGER.info(f"RESPONSE ={response}") 
        
    def upd_user_xcert(self,info,key):                                                                                                                                                                  
        # user cert                                                                                   
        if self._rest is None:
            LOGGER.info(f"REST CLIENT NOT READY")                                                                                                   
            return   
                     
        
        response = self._rest.crt(info,key,XCERT_BEFORE_TM,XCERT_AFTER_TM)                                                   
        LOGGER.info(f"USER XCERT RESPONSE ={response}")                                                                                     
