# Copyright 2016, 2022 DGT NETWORK INC © Stanislav Parsov
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

import argparse
import getpass
import logging
import os
import sys
import traceback
import pkg_resources
import cbor
import yaml
from colorlog import ColoredFormatter
from dgt_sdk.processor.log import log_configuration
from x509_cert.client_cli.generate import add_generate_parser
from x509_cert.client_cli.generate import do_generate
from x509_cert.client_cli.populate import add_populate_parser
from x509_cert.client_cli.populate import do_populate
#from x509_cert.client_cli.create_batch import add_create_batch_parser
#from x509_cert.client_cli.create_batch import do_create_batch
from x509_cert.client_cli.load import add_load_parser
from x509_cert.client_cli.load import do_load
#from x509_cert.client_cli.xcert_workload import add_workload_parser
#from x509_cert.client_cli.xcert_workload import do_workload

from x509_cert.client_cli.notary_client import NotaryClient
from x509_cert.client_cli.exceptions import XcertCliException,XcertClientException
from x509_cert.client_cli.xcert_attr import (XCERT_CRT_OP,XCERT_SET_OP,XCERT_UPD_OP,XCERT_WALLETS_OP,KEYKEEPER_ID)
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo
# DEC 
from dec_dgt.client_cli.dec_attr import (DEC_WALLET_OP,DEC_WALLET_OPTS_OP,DEC_WALLET_LIMIT_DEF,DEC_WALLET_LIMIT,
                                         DEC_OPTS_PROTO_FILE_NM,DEC_ROLE_PROTO_FILE_NM,DEC_ROLE_OP,DEC_ROLES_OP,DEC_GOODS_OP,DEC_TARGET_OP,DEC_PAY_OP,
                                         DEC_APPROVALS,DEC_APPROVAL,DEC_TARGET_PROTO_FILE_NM,DEC_NAME_DEF,DEFAULT_GATE
                                         )

DISTRIBUTION_NAME = 'x509-cert'

CRYPTO_BACK = 'openssl'
DEFAULT_URL = 'http://127.0.0.1:8008'

DGT_TOP = os.environ.get('DGT_TOP','dgt')
XCERT_PROTO_FILE = f"/project/{DGT_TOP}/etc/certificate.json"

def do_yaml(data):                                                               
    return yaml.dump(data,explicit_start=True,indent=4,default_flow_style=False) 


def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)

    if verbose_level == 0:
        clog.setLevel(logging.WARN)
    elif verbose_level == 1:
        clog.setLevel(logging.INFO)
    else:
        clog.setLevel(logging.DEBUG)

    return clog


def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(verbose_level)
    logger.addHandler(create_console_handler(verbose_level))
    log_configuration(log_dir="/project/peer/logs", name="notary")
    #console_out = logging.StreamHandler()                                                                                                 
    #thandler = TimedRotatingFileHandler(opts.log_file,when="D",interval=2,backupCount=30)                                                 
    #logging.basicConfig(handlers=(console_out,),level=verbose_level)  




def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument(
        '-v', '--verbose',
        action='count',
        help='enable more verbose output')
    parent_parser.add_argument(             
        '-y', '--yaml',                  
        action='count',
        default=1,                     
        help='enable yaml  output') 
    parent_parser.add_argument(                                                 
        '--check',                                                              
        action='count',                                                         
        default=0,                                                              
        help='Just show all params for operation')                              
                                                                                
    parent_parser.add_argument(                                                 
        '-cb', '--crypto_back',                                                 
        type=str,                                                               
        choices=["openssl","bitcoin"] ,                                         
        help='Specify a crypto back openssl/bitcoin',                           
        default=CRYPTO_BACK                                                     
        ) 
    parent_parser.add_argument(                             
        '-U','--url',                                     
        type=str,                                    
        default="http://api-dgt-c1-1:8108",          
        help='specify URL of REST API')              
    parent_parser.add_argument(                             
        '-NU','--notary_url',                              
        type=str,                                    
        help='Specify URL of NOTARY REST API',       
        default='http://telebot-dgt:8203'            
        )
    parent_parser.add_argument(                                                 
        '--wait',                                                        
        nargs='?',                                                                                                   
        const=sys.maxsize,                                               
        type=int,                                                                                                                               
        help='set time, in seconds, to wait for transaction to commit')  
    parent_parser.add_argument(             
        '-tk','--token',              
        type=str, 
        default= DEC_NAME_DEF,                  
        help='Type of token')  

    parent_parser.add_argument(                                     
        '--tips',                                                   
        default=0.0,                                                
        type=float,                                                 
        help='Set tips for transaction(reward for acceptor peer)')  

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (DGT) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        parents=[parent_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    add_set_parser(subparsers, parent_parser)
    add_upd_parser(subparsers, parent_parser)
    add_crt_parser(subparsers, parent_parser)
    add_wallet_parser(subparsers, parent_parser)
    add_wallets_parser(subparsers, parent_parser)
    add_role_parser(subparsers, parent_parser)
    add_roles_parser(subparsers, parent_parser)
    add_goods_parser(subparsers, parent_parser)
    add_target_parser(subparsers, parent_parser)
    add_pay_parser(subparsers, parent_parser)
    add_approvals_parser(subparsers, parent_parser)
    add_approval_parser(subparsers, parent_parser)
    add_show_parser(subparsers, parent_parser)
    add_info_parser(subparsers, parent_parser)
    add_list_parser(subparsers, parent_parser)
    add_init_parser(subparsers, parent_parser)
    """
    add_generate_parser(subparsers, parent_parser)
    add_load_parser(subparsers, parent_parser)
    add_populate_parser(subparsers, parent_parser)
    add_create_batch_parser(subparsers, parent_parser)
    add_workload_parser(subparsers, parent_parser)
    """
    return parser


def add_set_parser(subparsers, parent_parser):
    message = 'Create an xcert certificate with params into <value>.'

    parser = subparsers.add_parser(
        'set',
        parents=[parent_parser],
        description=message,
        help='Sets an xcert value')
    parser.add_argument(                
        '--user',                       
        type=str,
        default="/project/peer/keys/notary.priv",                       
        help='specify User private key for signing certificate')       


    parser.add_argument(
        'value',
        type=str,
        default=XCERT_PROTO_FILE,
        help='xcert atributes JSON or File name')


    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(                                                
        '--before',                                                       
        type=int,                                                       
        help='set time, in day - cert is valid before')
    parser.add_argument(                                
        '--after',                                      
        type=int,
        default=10,                                       
        help='set time, in day - cert is valid after') 




def do_set(args):
    value, wait, user = args.value, args.wait, args.user
    client = _get_client(args)
    response = client.set(value,user,args.before,args.after,wait)
    print(response)


def add_upd_parser(subparsers, parent_parser):
    message = 'Update xcert certificate with params into <value>.'

    parser = subparsers.add_parser(
        'upd',
        parents=[parent_parser],
        description=message,
        help='Update xcert atributes')
    parser.add_argument(
        'value',
        type=str,
        default=XCERT_PROTO_FILE,
        help='specify xcert atributes to update')
    parser.add_argument(
        '--user',
        type=str,
        default="/project/peer/keys/notary.priv",
        help='specify User name')

 
    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(                                   
        '--before',                                       
        type=int,                                         
        help='set time, in day - cert is valid before')   
    parser.add_argument(                                  
        '--after',                                        
        type=int,
        default=10,                                         
        help='set time, in day - cert is valid after')    
    
                              


def do_upd(args):
    value, wait, user = args.value, args.wait, args.user
    client = _get_client(args)
    response = client.upd( value,user,args.before,args.after,wait)
    print(response)

def add_crt_parser(subparsers, parent_parser):
    message = 'Create an xcert certificate for user-id with params into <--proto>.'

    parser = subparsers.add_parser(
        'crt',
        parents=[parent_parser],
        description=message,
        help='Update xcert atributes')

    parser.add_argument(   
        'user_id',              
        type=str,                 
        help='Specify user ID')   

    parser.add_argument(
        '--proto',
        type=str,
        default=XCERT_PROTO_FILE,
        help='specify xcert atributes to create')


    parser.add_argument(
        '--user',
        type=str,
        default="/project/peer/keys/notary.priv",
        help='Specify private key for user who ask operation')

      
    parser.add_argument(                                
        '--notary',                                     
        action='count',                                 
        default=0,                                      
        help='Use Notary for control operation')   
    
    parser.add_argument(
        '--keyfile',
        type=str,
        default="/project/peer/keys/notary.priv",
        help="Identify file containing notary's private key")

 
    parser.add_argument(                                   
        '--before',                                       
        type=int,                                         
        help='set time, in day - cert is valid before')   
    parser.add_argument(                                  
        '--after',                                        
        type=int,
        default=10,                                         
        help='set time, in day - cert is valid after')    

def do_crt(args):                                                          
                  
    client = _get_client(args)                                             
    response = client.do_crt(args, args.wait) # ( value,user_id,args.before,args.after,wait)         
    print(response)                                                        

def add_wallet_parser(subparsers, parent_parser):                                                                                               
    message = 'Create wallet for  DEC token.'                                                                                                   
                                                                                                                                                
    parser = subparsers.add_parser(                                                                                                             
        DEC_WALLET_OP,                                                                                                                          
        parents=[parent_parser],                                                                                                                
        description=message,                                                                                                                    
        help='Create wallet and add them into did wallet list')   
                                                                                                                    
    parser.add_argument(
        'pkey',
        type=str,
        help='Specify wallet owner private key file')
    
                                                                                                                                                
    parser.add_argument(                                                                                                                        
        '--did','-d',                                                                                                                           
        type=str,                                                                                                                               
        help="DID value " # {'sign' : 'notary sign for did structure','did' :{'val' : 'did value','nkey' : 'notary public key'} }")                     
        )                                                                                                                                        
    parser.add_argument(                                                                                                              
        '--cmd','-c',                                                                                                                 
        type=str,
        default=DEC_WALLET_OP,                                                                                                                     
        help="Wallet cmd: wallet|opts (default - wallet)" 
        )                                                                                                                             
    parser.add_argument(          
        '--limit','-l',             
        type=int,                 
        #default=DEC_WALLET_LIMIT_DEF,    
        help="Wallet dec transfer limit "        
        )                         
    parser.add_argument(                       
        '--spend_period','-sp',                        
        type=int,                              
        #default=DEC_WALLET_LIMIT_DEF,         
        help="Wallet spending period"      
        )   
    parser.add_argument(                     
        '--status','-st',              
        type=str,                            
        #default=DEC_WALLET_LIMIT_DEF,       
        help="Wallet status"        
        )  
    
    parser.add_argument(                        
       '--role','-r',                           
       type=str,                                
       help="Wallet role name"                  
       )                                        
                                                                                                                                                                                                           
    parser.add_argument(                                 
        '--opts_proto',                                  
        type=str,                                        
        default=DEC_OPTS_PROTO_FILE_NM,                  
        help='Proto file with wallet permisions params') 
    parser.add_argument(                                                  
      '--owner_pub_key','-pk',                                            
      type=str,                                                           
      nargs='+',                                                          
      help='Owner public key for managing multi signed account'           
      )                                                                                                                                                                                                              
    parser.add_argument(                                                                                                                        
        '--keyfile',                                                                                                                            
        type=str,                                                                                                                               
        default="/project/peer/keys/notary.priv",                                                                                            
        help="Identify file containing notary's private key (by default - current notary key)")   

    parser.add_argument(                                
        '--notary',                                     
        action='count',                                 
        default=0,                                      
        help='Use Notary for control operation')    
    
        


def do_wallet(args):
    client = _get_client(args) 
    client.init_dec(args.pkey)   
    response = client.wallet(args, args.wait)  

    print(response)                                                                              

def add_wallets_parser(subparsers, parent_parser):                                                                                                                  
    message = 'Create wallet for  DEC token.'                                                                                                                      
                                                                                                                                                                   
    parser = subparsers.add_parser(                                                                                                                                
        XCERT_WALLETS_OP,                                                                                                                                             
        parents=[parent_parser],                                                                                                                                   
        description=message,                                                                                                                                       
        help='Print list wallet relating to DID')                                                                                                                                      
                                                                                                                                                                   
    parser.add_argument(                                                                                                                                           
        'did',                                                                                                                                                    
        type=str,                                                                                                                                                  
        help='specify DID owner of wallets')                                                                                                              
                                                                                                                                                                   
    parser.add_argument(                                    
        '--opts_proto',                                     
        type=str,                                           
        default=DEC_OPTS_PROTO_FILE_NM,                     
        help='Proto file with wallet permisions params')    
    
                                                                                                                                                                   
    parser.add_argument(                                                                                                                                           
        '--keyfile',                                                                                                                                               
        type=str,                                                                                                                                                  
        default="/project/peer/keys/notary.priv",                                                                                                                  
        help="Identify file containing notary's private key (by default - current notary key)")                                                                           

def do_wallets(args):                                
    client = _get_client(args)                      
    response = client.wallets(args)       
    print(response)                                 

def add_role_parser(subparsers, parent_parser):                                                             
    message = 'Create role with <role_id> and attach it for <did>'                                                                         
    parser = subparsers.add_parser(                                                                         
        DEC_ROLE_OP,                                                                                        
        parents=[parent_parser],                                                                            
        description=message,                                                                                
        help='Create role')                                                                      
                                                                                                            
    parser.add_argument(                                                                                    
        'role_id',                                                                                          
        type=str,                                                                                           
        help='Role ID') 

    parser.add_argument(                           
        'did',                                     
        type=str,                                  
        help='specify DID owner of role')       
                                                                                        
                                                                                                            
    parser.add_argument(                                                                                    
        '--type',                                                                                           
        type=str,                                                                                           
        help='Role type')                                                                                   
                                                                                                            
    parser.add_argument(                                                                                    
        '--role_proto',                                                                                     
        type=str,                                                                                           
        default=DEC_ROLE_PROTO_FILE_NM,                                                                     
        help='Role proto file')                                                                             
                                                                                                            
    parser.add_argument(                                                                                    
        '--limit','-l',                                                                                     
        type=str,                                                                                           
        help='Send limit')                                                                                  
                                                                                                            
                                                                     
    parser.add_argument(                                                                                    
        '--keyfile',                                                                                        
        type=str,                                                                                           
        default="/project/peer/keys/notary.priv",                                                        
        help="Identify file containing owner private key") 
                                                     
                                       
def do_role(args):                                                                                                                                  
    client = _get_client(args) 
    client.init_dec(args.keyfile)            
    response = client.role(args)        
    print(response)                        

def add_roles_parser(subparsers, parent_parser):                                                                      
    message = 'Get roles list <did>'                                                   
    parser = subparsers.add_parser(                                                                                  
        DEC_ROLES_OP,                                                                                                 
        parents=[parent_parser],                                                                                     
        description=message,                                                                                         
        help='Get roles')                                                                                          
                                                                                                                     
    parser.add_argument(                                                                                             
        'did',                                                                                                       
        type=str,                                                                                                    
        help='specify DID owner of roles')                                                                            
                                                                                                                     
                                                                                                                     
    parser.add_argument(                                                                                             
        '--keyfile',                                                                                                 
        type=str,                                                                                                    
        default="/project/peer/keys/notary.priv",                                                                    
        help="Identify file containing owner private key")                                                           
                                                                                                                     

def do_roles(args):                       
    client = _get_client(args)           
    #client.init_dec(args.keyfile)        
    response = client.roles(args)         
    print(response)                      

def add_target_parser(subparsers, parent_parser):                                                           
    message = 'Target for sale <target_id> <did> <price>'                                                         
    parser = subparsers.add_parser(                                                                         
        DEC_TARGET_OP,                                                                                      
        parents=[parent_parser],                                                                            
        description=message,                                                                                
        help='Create target for sale')                                                                      
                                                                                                            
    parser.add_argument(                                                                                    
        'target_id',                                                                                        
        type=str,                                                                                           
        help='Target ID')                                                                                   
    parser.add_argument(                    
        'did',                              
        type=str,                           
        help='Specify DID owner of target')  
    
                                                                                                            
    parser.add_argument(                                                                                    
        'price',                                                                                            
        type=float,                                                                                         
        help='Target price')  
                                                                                  
    parser.add_argument(                                    
        '--pkey',                                           
        type=str,                                         
        help='specify target owner private key file')     
    
    parser.add_argument(                       
        '--target_proto',                      
        type=str,                              
        default=DEC_TARGET_PROTO_FILE_NM,      
        help='Target proto file')              
                                                                                                          
    parser.add_argument(                                                                                    
        '--target','-tg',                                                                                   
        type=str,                                                                                           
        help='Target specification') 
                                                                           
    parser.add_argument(                                                                   
        '--invoice','-i',                                                                  
        action='count',                                                                    
        default=0,                                                                         
        help='Invoice free')
     
    parser.add_argument(              
        '--notary',             
        action='count',               
        default=0,                    
        help='Use Notary for control operation') 
    parser.add_argument(                          
        '--gate','-g',                            
        type=str,                                 
        default=DEFAULT_GATE,                                                                                           
        help='Default gate for transaction')                                                                      
    parser.add_argument(                                                                                    
        '--keyfile',                                                                                        
        type=str,                                                                                           
        default="/project/peer/keys/notary.priv",                                                        
        help="Identify file containing notary private key")                                                  
                                                                                                           

def do_target(args):                          
    client = _get_client(args)               
    client.init_dec(args.keyfile if args.pkey is None else args.pkey)           
    response = client.target(args)            
    print(response)                          


def add_goods_parser(subparsers, parent_parser):                                                 
    message = 'Get goods list for <did>'                                                             
    parser = subparsers.add_parser(                                                              
        DEC_GOODS_OP,                                                                            
        parents=[parent_parser],                                                                 
        description=message,                                                                     
        help='Get goods for did')                                                                        
                                                                                                 
    parser.add_argument(                                                                         
        'did',                                                                                   
        type=str,                                                                                
        help='specify DID owner of goods')                                                       
                                                                                                 
                                                                                                 
    parser.add_argument(                                                                         
        '--keyfile',                                                                             
        type=str,                                                                                
        default="/project/peer/keys/notary.priv",                                                
        help="Identify file containing owner private key")                                       
                                                                                                 
                                                                                                  
                                                                                                 



def do_goods(args):                               
    client = _get_client(args)                    
    #client.init_dec(args.keyfile)                
    response = client.goods(args)                 
    print(response)                               

def add_pay_parser(subparsers, parent_parser):                                                                                                
    message = 'Pay DEC <from> <to> <amount> [for --target <target>].'                                                                                                
    parser = subparsers.add_parser(                                                                                                           
        DEC_PAY_OP,                                                                                                                           
        parents=[parent_parser],                                                                                                              
        description=message,                                                                                                                  
        help='Pay token for target')                                                                                                                 
    parser.add_argument(                                                                                                                      
        'name',                                                                                                                               
        type=str,                                                                                                                             
        help='From wallet')                                                                                                                   
    parser.add_argument(                                                                                                                      
        'to',                                                                                                                                 
        type=str,                                                                                                                             
        help='to wallet')                                                                                                                     
    parser.add_argument(                                                                                                                      
        'amount',                                                                                                                             
        type=int,                                                                                                                             
        help='number token for transfer')                                                                                                     
                                                                                                                                              
    parser.add_argument(                                                                                                                      
        '--did','-d',                                                                                                                         
        type=str,                                                                                                                             
        help='DID of owner <from wallet>')                                                                                                                           
    # with out target works like send                                                                                                         
    parser.add_argument(                                                                                                                      
        '--target','-tg',                                                                                                                     
        type=str,                                                                                                                             
        help='Target object')                                                                                                                 
    parser.add_argument(                                                                                                                      
        '--asset_type','-at',                                                                                                                 
        type=str,                                                                                                                             
        help='passkey for special operation')                                                                                                 
    parser.add_argument(                                                                                                                      
        '--priv_key','-priv',                                                                                                                   
        type=str,                                                                                                                             
        help='Private key of customer')  
                                                                                                                         
    parser.add_argument(                                                                                                                      
        '--provement_key','-prov',                                                                                                            
        type=str,                                                                                                                             
        help='Provement key refer to prov key from invoice')                                                                                  
    parser.add_argument(                                                                                                                      
       '--role','-r',                                                                                                                         
       type=str,                                                                                                                              
       help="Wallet role name"                                                                                                                
       )                                                                                                                                      
    parser.add_argument(                                                                                                                      
        '--keyfile',                                                                                                                          
        type=str,
        default="/project/peer/keys/notary.priv",                                                                                                                             
        help="identify file containing user's private key")
    
    parser.add_argument(                              
        '--notary',                                   
        action='count',                               
        default=0,                                    
        help='Use Notary for control operation')      
                                                      
                                                                                                                                              
def do_pay(args):                                                                                                                             
    client = _get_client(args)   
    client.init_dec(args.keyfile if args.priv_key is None else args.priv_key)                                                                                                             
    response = client.pay(args, args.wait)                                                                                                    
    print(response)                                                                                                                           



def add_init_parser(subparsers, parent_parser):
    message = 'Init new notary.'

    parser = subparsers.add_parser(
        'init',
        parents=[parent_parser],
        description=message,
        help='Init vault node')
    parser.add_argument(
        'value',
        type=str,
        default='n1',
        help='specify notary node name (n1/n2/n3)')
    parser.add_argument(
        '-la','--leader-addr',
        type=str,
        default=None,
        help='specify notary leader addr(http://vault-n2:8300)')
    parser.add_argument(                                         
        '-va','--vault-addr',                                   
        type=str,                                                
        default=None,                                            
        help='specify own notary addr(http://vault-n2:8300)') 


    parser.add_argument(
        '--keyfile',
        type=str,
        default="/project/peer/keys/notary.priv",
        help="Identify file containing notary's private key")


    parser.add_argument(                                   
        '--before',                                       
        type=int,
        default=0,                                         
        help='set time, in day - cert is valid before')   
    parser.add_argument(                                  
        '--after',                                        
        type=int,
        default=100,                                         
        help='set time, in day - cert is valid after')    

def do_init(args):                                                               
    name, wait = args.value, args.wait                     
    client = _get_client(args,init=True)                                                  
    response = client.init(name,wait)              
    print(response)                                                             
                                                                                
def add_show_parser(subparsers, parent_parser):
    message = 'Shows the xcert for key <name>.'

    parser = subparsers.add_parser(
        'show',
        parents=[parent_parser],
        description=message,
        help='Display the specified by user public key x509 certificate')

    parser.add_argument(
        'name',
        type=str,
        help='certificate of key to show')

    parser.add_argument(                                       
        '--keyfile',                                           
        type=str,                                              
        help="identify file containing user's private key")    







def do_show(args):
    name = args.name
    client = _get_client(args)
    value = client.show_secret(name)
    if value is None :
        print("NO XCERT FOR KEY={}".format(name))
        return
    token = X509CertInfo()
    token.ParseFromString(value)
    #xcert = cbor.loads(token.xcert)
    xcert = client.load_xcert(token.xcert)

    if client.is_notary_info(name):
        val = client.get_xcert_notary_attr(xcert) 
        nkey = client.get_pub_key(xcert)

        if args.yaml > 0:
            val = do_yaml(val)
            
        print("NOTARY KEY={} \n{}".format(nkey,val))
    if args.yaml > 0: 
        try:
            xcert = do_yaml(xcert)
        except Exception as ex:
            xdict = client.xcert_to_dict(xcert)
            #print(xdict)
            xdict[name] = '-Cert'
            xdict['valid'] = "{}->{}".format(xcert.not_valid_before,xcert.not_valid_after)
            xcert = do_yaml(xdict)
            print(xcert)
    else:
        print('{}:valid={}->{} {}'.format(name,xcert.not_valid_before,xcert.not_valid_after,xcert))


def add_info_parser(subparsers, parent_parser):                                  
    message = 'Show notary info.'                                  
                                                                                 
    parser = subparsers.add_parser(                                              
        'info',                                                                  
        parents=[parent_parser],                                                 
        description=message,                                                     
        help='Display notary raft config')        
                                                                                 
    parser.add_argument(                         
        '--raft',                              
        action='count',                          
        default=0,                                                                              
        help='Show notary raft config')
    parser.add_argument(                
        '--seal',                       
        action='count',                 
        default=0,                      
        help='Show seal keeper info') 
    parser.add_argument(                 
        '--list',                       
        #action='count',
        nargs='?', 
        type=str,                
        #default=0,                      
        help='Show list of secrets')   
    parser.add_argument(                    
        '-r','--recursive',                          
        action='count',                    
        default=0,                         
        help='Show List recursively')      
    parser.add_argument(                  
        '-m','--meta',               
        action='count',                   
        default=0,                        
        help='Show meta info for secrets')     

                                           
    parser.add_argument(                                                         
        '--keyfile',                                                             
        type=str,                                                                
        help="identify file containing user's private key")                      
                                                                                 
                                                                                 
                                                                                 




def do_info(args):                                                                                               
    client = _get_client(args) 

    if args.raft > 0:
        value = client.show_raft_info(args)                                                                             
        print("RAFT CONGIG: {}".format(do_yaml(value))) 
    if args.list:  
        if False and args.meta > 0 :
            #
            client._vault.delete_secret(args.list)
        else:
            value = client.get_info_list(args)     
            print("SECRETS LIST:{}: \n{}".format(args.list,value))  

    if args.seal > 0:
        stat = client.show_seal_status()
        print("SEAL STATUS: \n{}".format(do_yaml(stat)))
        return
        value = client.show(KEYKEEPER_ID)
        if value is None :                                               
            print("SEAL KEEPER NOT REGISTRED")                    
            return                                                       
        token = X509CertInfo()                                           
        token.ParseFromString(value)                                     
        xcert = client.load_xcert(token.xcert) 
        val = client.get_xcert_notary_attr(xcert)        
        nkey = client.get_pub_key(xcert)                 
        print("SEAL KEY={} \n{}".format(nkey,do_yaml(val)))  
                                  
                 

def add_list_parser(subparsers, parent_parser):
    message = 'Shows all xcert.'

    parser = subparsers.add_parser(
        'list',
        parents=[parent_parser],
        description=message,
        help='Displays all X509 certificates')

    parser.add_argument(                                    
        '--keyfile',                                        
        type=str,                                           
        help="identify file containing user's private key") 


 

def do_list(args):
    client = _get_client(args)
    results = client.list()
    token = X509CertInfo()
    for pair in results:
        for name, value in pair.items():
            token.ParseFromString(value)
            try:    
                xcert = client.load_xcert(token.xcert)
                #print(f'load xcert token={token.xcert}')
                print(f'{name}: valid={xcert.not_valid_before}/{xcert.not_valid_after} {xcert}')
            except Exception as ex:
                print(f'Cant load xcert {name}: token={token.xcert}')


def add_approvals_parser(subparsers, parent_parser):                                          
    message = 'Shows all approvals.'                                                         
                                                                                         
    parser = subparsers.add_parser(                                                      
        DEC_APPROVALS,                                                                          
        parents=[parent_parser],                                                         
        description=message,                                                             
        help='Displays all notary approvals')                                           
                                                                                         
                                                     
    parser.add_argument(                                                                 
        '--keyfile',                                                                     
        type=str,                                                                        
        help="identify file containing user's private key")                              
                                                                                         



def do_approvals(args):
    client = _get_client(args)
    results = client.approvals(args)
    print("approvals={}".format(results))

def add_approval_parser(subparsers, parent_parser):            
    message = 'Show approval with name.'                            
                                                                
    parser = subparsers.add_parser(                             
        DEC_APPROVAL,                                          
        parents=[parent_parser],                                
        description=message,                                    
        help='Displays  notary approval with name') 
                      
    parser.add_argument(                     
        'name',                              
        type=str,                            
        help='Name of approval') 
      
    parser.add_argument(                                  
        '--approve',                                       
        action='count',                                   
        default=0,                                        
        help='Approve notary request with name')   
    parser.add_argument(                            
        '--status',                                
        action='count',                             
        default=0,                                  
        help='Check request status with name')
    parser.add_argument(                       
        '-del','--delete',                            
        action='count',                        
        default=0,                             
        help='Delete notary approve request') 
    
               
                                                                
    parser.add_argument(                                        
        '--keyfile',                                            
        type=str, 
        default="/project/peer/keys/notary.priv",                                              
        help="identify file containing notary's private key")     
                                                                
                                                                
                                                                
                                                                
def do_approval(args):                                         
    client = _get_client(args) 
    if args.approve > 0:
        client.init_dec(args.keyfile)# if args.pkey is None else args.pkey)                                 
    results = client.approval(args)                            
    print("approval={}".format(results))                       


def _get_client(args,init=False):
    url     = DEFAULT_URL if args.url is None else args.url
    keyfile = _get_keyfile(args)
    backend = args.crypto_back
    if init:
        notary= args.value
        lurl = args.leader_addr
        vurl = args.vault_addr
        print("VAULT INIT url={}".format(vurl))
        client =  NotaryClient(url=url,keyfile=keyfile,backend=backend,vault_url=vurl,notary=notary,lead_addr=lurl)                                       
     
    else:
        client =  NotaryClient(url=url,keyfile=keyfile,backend=backend)

    if not client.init_vault():                
        #LOGGER.info("VAULT NOT READY EXIT") 
        print("VAULT NOT READY EXIT")       
        sys.exit(1)
    return client   
                                
def _get_keyfile(args):
    try:
        if args.keyfile is not None:
            return args.keyfile
    except AttributeError:
        return None

    return '/project/peer/keys/notary.priv'


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)

    if args.verbose is None:
        verbose_level = 0
    else:
        verbose_level = args.verbose
    setup_loggers(verbose_level=verbose_level)
    
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == XCERT_SET_OP:
        do_set(args)
    elif args.command == XCERT_UPD_OP:
        do_upd(args)
    elif args.command == XCERT_CRT_OP:
        do_crt(args)
    elif args.command == XCERT_WALLETS_OP:
        do_wallets(args)
    elif args.command == DEC_WALLET_OP:
        do_wallet(args)

    elif args.command == DEC_ROLE_OP:  
        do_role(args)  
    elif args.command == DEC_ROLES_OP:        
        do_roles(args) 
        
    elif args.command == DEC_TARGET_OP:
        do_target(args)

    elif args.command == DEC_GOODS_OP:         
        do_goods(args)                          
    elif args.command == DEC_PAY_OP:    
        do_pay(args)                       
    elif  args.command == DEC_APPROVALS:
        do_approvals(args)

    elif args.command == DEC_APPROVAL:
        do_approval(args)

    elif args.command == 'show':
        do_show(args)
    elif args.command == 'info':      
        do_info(args)                 
    elif args.command == 'list':
        do_list(args)
    elif args.command == 'init':    
        do_init(args)               
    else:                                                                   
        raise XcertCliException("invalid command: {}".format(args.command)) 

    
    


def main_wrapper():
    # pylint: disable=bare-except
    try:
        main()
    except (XcertCliException, XcertClientException) as err:
        logging.info("Error: {}".format(err))
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
