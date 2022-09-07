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
from colorlog import ColoredFormatter

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
from x509_cert.client_cli.xcert_attr import (XCERT_CRT_OP,XCERT_SET_OP,XCERT_UPD_OP,XCERT_WALLETS_OP)
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo
# DEC 
from dec_dgt.client_cli.dec_attr import DEC_WALLET_OP,DEC_WALLET_OPTS_OP,DEC_WALLET_LIMIT_DEF,DEC_WALLET_LIMIT,DEC_OPTS_PROTO_FILE_NM

DISTRIBUTION_NAME = 'x509-cert'

CRYPTO_BACK = 'openssl'
DEFAULT_URL = 'http://127.0.0.1:8008'

DGT_TOP = os.environ.get('DGT_TOP')
XCERT_PROTO_FILE = f"/project/{DGT_TOP}/etc/certificate.json"
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
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))


def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument(
        '-v', '--verbose',
        action='count',
        help='enable more verbose output')

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
    add_show_parser(subparsers, parent_parser)
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
        '--url',
        type=str,
        default="http://api-dgt-c1-1:8108",
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for transaction to commit')
    parser.add_argument(                                                
        '--before',                                                       
        type=int,                                                       
        help='set time, in day - cert is valid before')
    parser.add_argument(                                
        '--after',                                      
        type=int,
        default=10,                                       
        help='set time, in day - cert is valid after') 


    parser.add_argument(              
        '-cb', '--crypto_back',               
        type=str,                             
        help='Specify a crypto back',         
        default=CRYPTO_BACK)                    


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
        '--url',
        type=str,
        default="http://api-dgt-c1-1:8108",
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for transaction to commit')
    parser.add_argument(                            
        '-cb', '--crypto_back',                     
        type=str,                                   
        help='Specify a crypto back openssl/bitcoin',               
        default=CRYPTO_BACK)
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
    message = 'Create an xcert certificate with params into <value>.'

    parser = subparsers.add_parser(
        'crt',
        parents=[parent_parser],
        description=message,
        help='Update xcert atributes')
    parser.add_argument(
        'value',
        type=str,
        default=XCERT_PROTO_FILE,
        help='specify xcert atributes to create')
    parser.add_argument(
        '--user',
        type=str,
        default="/project/peer/keys/notary.priv",
        help='specify User name')

    parser.add_argument(
        '--url',
        type=str,
        default="http://api-dgt-c1-1:8108",
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for transaction to commit')
    parser.add_argument(                            
        '-cb', '--crypto_back',                     
        type=str,                                   
        help='Specify a crypto back openssl/bitcoin',               
        default=CRYPTO_BACK)
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
    value, wait, user = args.value, args.wait, args.user                   
    client = _get_client(args)                                             
    response = client.crt( value,user,args.before,args.after,wait)         
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
        help='specify wallet owner private key file')
    
                                                                                                                                                
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
        '--url',                                                                                                                                
        type=str,                                                                                                                               
        help='specify URL of REST API',                                                                                                         
        default='http://api-dgt-c1-1:8108')                                                                                                     
                                                                                                                                                
    parser.add_argument(                                                                                                                        
        '--keyfile',                                                                                                                            
        type=str,                                                                                                                               
        default="/project/peer/keys/notary.priv",                                                                                            
        help="Identify file containing notary's private key (by default - current notary key)")                                                        
    parser.add_argument(                                      
        '-cb', '--crypto_back',                              
        type=str,                                            
        help='Specify a crypto back openssl/bitcoin',        
        default=CRYPTO_BACK)                                 
    
                                                                                                                                                
    parser.add_argument(                                                                                                                        
        '--wait',                                                                                                                               
        nargs='?',                                                                                                                              
        const=sys.maxsize,                                                                                                                      
        type=int,                                                                                                                               
        help='set time, in seconds, to wait for transaction to commit')                                                                         



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
        '--url',                                                                                                                                                   
        type=str,                                                                                                                                                  
        help='specify URL of REST API',                                                                                                                            
        default='http://api-dgt-c1-1:8108')                                                                                                                        
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
    parser.add_argument(                                                                                                                                           
        '-cb', '--crypto_back',                                                                                                                                    
        type=str,                                                                                                                                                  
        help='Specify a crypto back openssl/bitcoin',                                                                                                              
        default=CRYPTO_BACK)                                                                                                                                       

def do_wallets(args):                                
    client = _get_client(args)                      
    response = client.wallets(args)       
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
        '--url',
        type=str,
        default="http://api-dgt-c1-1:8108",
        help='specify URL of REST API DGT network')

    parser.add_argument(
        '--keyfile',
        type=str,
        default="/project/peer/keys/notary.priv",
        help="Identify file containing notary's private key")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for transaction to commit')
    parser.add_argument(                            
        '-cb', '--crypto_back',                     
        type=str,                                   
        help='Specify a crypto back openssl/bitcoin',               
        default=CRYPTO_BACK)

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
        '--url',
        type=str,
        default="http://api-dgt-c1-1:8108",
        help='specify URL of REST API')
    parser.add_argument(                                       
        '--keyfile',                                           
        type=str,                                              
        help="identify file containing user's private key")    


    parser.add_argument(                            
        '-cb', '--crypto_back',                     
        type=str,                                   
        help='Specify a crypto back',               
        default=CRYPTO_BACK)                          






def do_show(args):
    name = args.name
    client = _get_client(args)
    value = client.show(name)
    token = X509CertInfo()
    token.ParseFromString(value)
    #xcert = cbor.loads(token.xcert)
    xcert = client.load_xcert(token.xcert)

    if client.is_notary_info(name):
        val = client.get_xcert_notary_attr(xcert) 
        nkey = client.get_pub_key(xcert)
        print("NOTARY KEY={} DATA={}".format(nkey,val))

    print('{}:valid={}->{} {}'.format(name,xcert.not_valid_before,xcert.not_valid_after,xcert))


def add_list_parser(subparsers, parent_parser):
    message = 'Shows all xcert.'

    parser = subparsers.add_parser(
        'list',
        parents=[parent_parser],
        description=message,
        help='Displays all X509 certificates')

    parser.add_argument(
        '--url',
        type=str,
        default="http://api-dgt-c1-1:8108",
        help='specify URL of REST API')
    parser.add_argument(                                    
        '--keyfile',                                        
        type=str,                                           
        help="identify file containing user's private key") 


    parser.add_argument(                   
        '-cb', '--crypto_back',            
        type=str,                          
        help='Specify a crypto back openssl/bitcoin',      
        default=CRYPTO_BACK)                 


def do_list(args):
    client = _get_client(args)
    results = client.list()
    token = X509CertInfo()
    for pair in results:
        for name, value in pair.items():
            token.ParseFromString(value)
            xcert = client.load_xcert(token.xcert)
            print(f'{name}: valid={xcert.not_valid_before}/{xcert.not_valid_after} {xcert}')


def _get_client(args,init=False):
    url     = DEFAULT_URL if args.url is None else args.url
    keyfile = _get_keyfile(args)
    backend = args.crypto_back
    if init:
        notary= args.value
        lurl = args.leader_addr
        vurl = args.vault_addr

        return NotaryClient(url=url,keyfile=keyfile,backend=backend,vault_url=vurl,notary=notary,lead_addr=lurl)                                       
     
    else:
        return NotaryClient(url=url,keyfile=keyfile,backend=backend)


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
    elif args.command == 'show':
        do_show(args)
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
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
