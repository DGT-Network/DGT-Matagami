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
import json

FAMILY_NAME ="dec"
FAMILY_VERSION ="1.0"

ANY_EMISSION_KEY = "_{}_EMISSION_KEY_"
DEC_EMISSION_KEY = "_DEC_EMISSION_KEY_"
DEC_HEART_BEAT_KEY  = "_DEC_HEART_BEAT_"
DEC_NAME_DEF = "DEC"
DEC_WALLET  = 'accounts'
DEC_WALLET_ALIAS = "aliases"
DEC_INVOICE_DEF = "INVOICE"
# objects groups
DEC_TARGET_GRP = "targets"
DEC_ROLE_GRP   = "roles"
DEC_WALLET_GRP   = "accounts"
DEC_EMISSION_GRP   = "emissions"
DEC_SYNONYMS_GRP   = "aliases"
#
DEC_HEART = "HEARTBEAT"
DEC_TOTAL_SUM_DEF = 8589869056
DEC_GRANULARITY_DEF = 7
DEC_NОMINAL_DEF = 0.8
DEC_NОMINAL_NAME_DEF = "USD"
DEC_СORPORATE_SHARE_DEF = 10
DEC_MINTING_SHARE_DEF = 80
DEC_NBURN_DEF = 3
DEC_FEE_DEF = 1
AVAILABLE_TILL_DEF        = 60*60*100
DEC_WAIT_TO_DATE_DEF = 60*60*24*3
DEC_MINT_PERIOD_DEF = 60*2
DEC_HEART_BEAT_PERIOD_DEF = 60*3
DEFAULT_DID = "did:notary:30563010:000000000"
DEFAULT_GATE = "this"
GATE_ADDR_ATTR = "addr"
DEC_WALLET_LIMIT_DEF  = 1000
DEC_SPEND_PERIOD_DEF = 4
DEC_TARGET_DEF = "any target"
DEC_TARGET_INFO_DEF = "empty target"
DEC_ROLE_DEF        = "def_role"
DEC_ADMIN_PUB_KEY_DEF = "12345"
DEC_PASSKEY_DEF = "passkey"
DEC_TSTAMP_FMT = "%Y-%m-%d %H:%M:%S"
# DEC attributes
DEC_NAME              = "name"              
DEC_SYMBOL            = "symbol"            
DEC_TOTAL_SUM         = "total_sum"         
DEC_ADMIN_PUB_KEY     = "admin_pub_key"     
DEC_WAIT_TO_DATE      = "wait_to_date"      
DEC_GRANULARITY       = "granularity"       
DEC_PASSKEY           = "passkey"           
DEC_LINK              = "link"              
DEC_NОMINAL           = "nominal"           
DEC_NОMINAL_NAME      = "nominal_name"      
DEC_СORPORATE_ACCOUNT = "corporate_account" 
DEC_MINTING_SHARE     = "minting_share"     
DEC_СORPORATE_SHARE   = "corporate_share"
DEC_SALE_SHARE        = "sale_share"   
DEC_MINT_PARAM        = "mint_param"
DEC_MINT_COEF_UMAX    = "Umax"   
DEC_MINT_COEF_B2      = "B2"
DEC_MINT_COEF_T1      = "T1"
DEC_MINT_PERIOD       = "mint_period"       
DEC_NBURN             = "nBurn"             
DEC_FEE               = "fee"
DEC_TMSTAMP           = "timestamp"
DEC_MINT_TMSTAMP      = "mint_timestamp"
DEC_MINTING_TOTAL     = "mint_total"
DEC_MINTING_REST      = "mint_rest"
DEC_СORPORATE_TOTAL   = "corporate_total"
DEC_СORPORATE_REST    = "corporate_rest"  
DEC_SALE_TOTAL        = "sale_total"
DEC_SALE_REST         = "sale_rest" 
DEC_ASSET_TYPE        = "asset_type"
DEC_DID_VAL           = "did" 
DEC_TARGET            = "target"
DEC_TARGET_ID         = "name"
DEC_TARGET_ADDR         = "addr"
DEC_TARGET_URL        = "url" 
DEC_PROVEMENT_KEY     = "provement_key"  
DEC_CUSTOMER_KEY      = "customer"
AVAILABLE_TILL        = "available_till" 
DEC_CORPORATE_PUB_KEY = "corporate_pub_key"
DEC_HEART_BEAT_PERIOD = "heart_period"
DEC_HEART_BEAT_TOTAL = "heart_total"
DEC_HEART_BEAT_CURR  = "heart_curr"
DEC_HEART_BEAT_PEERS = "heart_peers"
DEC_LAST_HEART_TMSTAMP = "last_heart_tstamp"
DEC_MINT_REWARD      = "mint_reward"
DEC_PUBKEY           = "dec_pubkey"
NOTARY_PUBKEY        = "notary_pubkey"
DEC_SIGNATURE        = "dec_sign"
DEC_EMITTER          = "emitter"
DEC_OWNER            = "owner"
DEC_NOTARY_KEY       = "notary_key"
DEC_NOTARY_REQ_SIGN  = "notary_req_sign"
DEC_SPEND_TMSTAMP      = "spend_timestamp"
DEC_SPEND_PERIOD      = "spend_period"
DEC_WALLET_STATUS     = "status"
DEC_WALLET_ROLE       = "role"
DEC_WALLET_TOKEN      = "token"
DEC_WALLET_STATUS_ON     = "on"
DEC_WALLET_STATUS_OFF     = "off"
DEC_WALLET_ADDR         = "addr"
DEC_TARGET_INFO     = "target_info"
DEC_TARGET_PRICE     = "target_price"
DEC_ROLE_TYPE        = "role_type"
DEC_HEADER_PAYLOAD = "hpayload"   
DEC_PAYLOAD        = "payload"    
DEC_HEADER_SIGN    = "header_sign"
DEC_CMD_OPTS       = "opts"
DEC_TRANS_OPTS     = "topts"
DEC_CMD            = 'Verb'   
DEC_CMD_ARG        = 'Name'   
DEC_CMD_TO         = 'To'
DEC_CMD_TO_GRP     =  'to_grp'
DEC_CMD_VAL        = 'Value'    
DEC_CMD_DIN        = 'Din'    
DEC_CMD_DIN_EXT    = 'DinExt' 



#DEC_WALLET_DID       = "wallet_did"
# wallet properties
DEC_WALLET_LIMIT  = "limit"
#
DATTR_VAL  = "val"
DATTR_COMM = "comm"
DATTR_INPUTS = 'data_inputs'
# DEC TPROC operation
DEC_EMISSION_OP     = 'emission'
DEC_WALLET_OP       = 'account'
DEC_WALLET_OPTS_OP  = "opts"
DEC_ROLE_OP         = 'role'
DEC_ROLES_OP        = "roles"
DEC_GOODS_OP        = "goods"
DEC_BIRTH_OP        = 'birth'
DEC_TOTAL_SUPPLY_OP = 'totalsupply'
DEC_TOKEN_INFO_OP   = 'tokeninfo'
DEC_BURN_OP         = 'burn'
DEC_CHANGE_MINT_OP  = 'changemint'
DEC_DISTRIBUTE_OP   = 'distribute'
DEC_FAUCET_OP       = 'faucet'
DEC_TIPS_OP         = 'tips'
DEC_ALIAS_OP         = 'alias'

#
DEC_MINT_OP         = 'mint'
DEC_HEART_BEAT_OP   = 'heartbeat'
DEC_SEAL_COUNT_OP    = "sealcount"
#
DEC_BALANCE_OF_OP   = "balanceof"
DEC_SEND_OP         = "send"
DEC_PAY_OP          = "pay"
DEC_INVOICE_OP      = "invoice"
DEC_TARGET_OP       = "target"
DEC_BANK_LIST_OP    = "bank_list"
DEC_APPROVALS       = "approvals"
DEC_APPROVAL        = "approval"
DEC_NOTARY_REQ      = "notary_req"
DEC_NOTARY_APPROVE  = "notary_approve"
#
DEC_CRT_OP = 'crt'
DEC_SET_OP = 'set'
DEC_UPD_OP = 'upd'
DEC_INC_OP = 'inc'
DEC_DEC_OP = 'dec'
DEC_TRANS_OP = 'trans'

VALID_VERBS = DEC_EMISSION_OP, DEC_WALLET_OP,DEC_ALIAS_OP, DEC_WALLET_OPTS_OP, DEC_BURN_OP, DEC_CHANGE_MINT_OP, DEC_FAUCET_OP, DEC_SEND_OP, DEC_PAY_OP, DEC_INVOICE_OP, DEC_TARGET_OP, DEC_ROLE_OP, DEC_MINT_OP, DEC_HEART_BEAT_OP, DEC_SET_OP, DEC_INC_OP, DEC_DEC_OP, DEC_TRANS_OP
VALID_VERBS_WITH_TO = DEC_TRANS_OP, DEC_FAUCET_OP, DEC_SEND_OP, DEC_PAY_OP, DEC_MINT_OP,DEC_TARGET_OP
DEC_TYPES = DEC_NAME_DEF,DEC_INVOICE_DEF,DEC_WALLET,DEC_HEART,DEC_TARGET_GRP,DEC_ROLE_GRP,DEC_SYNONYMS_GRP
MIN_VALUE = 0
MAX_VALUE = 4294967295

MAX_NAME_LENGTH = 20

TARGET_VISIBLE_ATTR =  DEC_TARGET_ID,DEC_TARGET_URL,DEC_TARGET_ADDR,DEC_TARGET_PRICE,DEC_TARGET_INFO,DEC_OWNER
LONG_NAME_OPS = DEC_WALLET_OP,DEC_ALIAS_OP,DEC_WALLET_OPTS_OP,DEC_MINT_OP,DEC_SEND_OP,DEC_PAY_OP,DEC_TARGET_OP,DEC_INVOICE_OP,DEC_FAUCET_OP
EMISSION_UNVISIBLE_ATTR = DEC_PASSKEY,DEC_ADMIN_PUB_KEY,DEC_CORPORATE_PUB_KEY

DEC_PROTO_FILE_NM = "/project/dgt/etc/dec/emission.json"
DEC_COMM_FILE_NM = "/project/dgt/etc/dec/comment.json" 
DEC_OPTS_PROTO_FILE_NM = "/project/dgt/etc/dec/wallet_opts.json"
DEC_ROLE_PROTO_FILE_NM = "/project/dgt/etc/dec/role.json"
DEC_TARGET_PROTO_FILE_NM = "/project/dgt/etc/dec/target.json"

DEC_PROTO = {                                                                 
    "COUNTRY_NAME"              : "CA",                                         
    "STATE_OR_PROVINCE_NAME"    : "ONTARIO",                                    
    "LOCALITY_NAME"             : "BARRIE",                                     
    "ORGANIZATION_NAME"         : "YOUR ORGANIZATION NAME" ,                    
    "COMMON_NAME"               : "NODE SAMPLE",                                
    "DNS_NAME"                  : "dgt.world",                                  
    "EMAIL_ADDRESS"             : "adminmail@mail.com",                         
    "PSEUDONYM"                 : "dgt00000000000000000",                       
    "JURISDICTION_COUNTRY_NAME" : "CA",                                         
    "BUSINESS_CATEGORY"         : "YOUR BUSINESS CATEGORY",                     
    "USER_ID"                   : "000000000000000001"                          
} 
DEF_WALLET_OPTS = {
"role"        : ["def_role"],         
"limit"       : 10001,                
"spend_period": 61,                   
"token"       : "DEC",                
"status"      : "off"                  
}
# external family                                                                            
SETTINGS_NAMESPACE = '000000'  

def load_json_proto(value):                                                                                                                           
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
