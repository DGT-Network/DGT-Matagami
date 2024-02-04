# Copyright 2016, 2017 DGT NETWORK INC © Stanislav Parsov
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
import yaml
import cbor

from colorlog import ColoredFormatter

from deth.client_cli.generate import add_generate_parser
from deth.client_cli.generate import do_generate
from deth.client_cli.populate import add_populate_parser
from deth.client_cli.populate import do_populate
from deth.client_cli.create_batch import add_create_batch_parser
from deth.client_cli.create_batch import do_create_batch
from deth.client_cli.load import add_load_parser
from deth.client_cli.load import do_load
from deth.client_cli.deth_workload import add_workload_parser
from deth.client_cli.deth_workload import do_workload

from deth.client_cli.deth_client import DethClient
from deth.client_cli.exceptions import DethCliException
from deth.client_cli.exceptions import DethClientException
from deth_common.protobuf.deth_pb2 import DethTransaction as BgtTokenInfo,EvmEntry
from deth.client_cli.deth_attr import *


ENABLE_EXTRA_CMD = False
DISTRIBUTION_NAME = 'dgt-deth'
MAX_VALUE = 4294967295
CRYPTO_BACK="openssl"
DEFAULT_URL = 'http://api-dgt-c1-1:8108'

DGT_API_URL = os.environ.get('DGT_API_URL',DEFAULT_URL) or DEFAULT_URL
def check_range(value):
    ivalue = int(value)
    if ivalue < 0 or ivalue > MAX_VALUE:
        raise argparse.ArgumentTypeError("{} is not in the range [0, {}]".format(value,MAX_VALUE))
    return ivalue

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

def do_yaml(data):                                                                  
    return yaml.dump(data,explicit_start=True,indent=4,default_flow_style=False)    

def do_cmd(func,args):
    response = func(args,args.wait)
    if isinstance(response,dict) or isinstance(response,tuple):    
        response = do_yaml(response)  
    print(response) 




def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output')

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth) version {}')
        .format(version),
        help='display version information')
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
        help='Specify URL of REST API',                                                                  
        default=DGT_API_URL)                                                                             
    parent_parser.add_argument(                                                                          
        '--wait',                                                                                        
        nargs='?',                                                                                       
        const=sys.maxsize, 
        default=6,                                                                              
        type=int,                                                                                        
        help='Set time, in seconds, to wait for transaction to commit')                                  
    parent_parser.add_argument(                                                                          
        '--access_token','-atok',                                                                        
        type=str,                                                                                        
        default=None,                                                                                    
        help='Access token')                                                                             


    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        parents=[parent_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    add_crt_parser(subparsers, parent_parser)
    add_call_parser(subparsers, parent_parser)
    
    add_smart_parser(subparsers, parent_parser)
    add_send_parser(subparsers, parent_parser)
    add_show_parser(subparsers, parent_parser)
    add_list_parser(subparsers, parent_parser)
    if ENABLE_EXTRA_CMD:
        add_perm_parser(subparsers, parent_parser)
        add_generate_parser(subparsers, parent_parser)
        add_load_parser(subparsers, parent_parser)
        add_populate_parser(subparsers, parent_parser)
        add_create_batch_parser(subparsers, parent_parser)
        add_workload_parser(subparsers, parent_parser)

    return parser


def add_crt_parser(subparsers, parent_parser):
    message = 'Sends transaction to create account.'

    parser = subparsers.add_parser(
        DETH_CRT_OP,
        parents=[parent_parser],
        description=message,
        help='Create an EVM account')
    """
    parser.add_argument(
        'name',
        type=str,
        help='name of key to set')

    parser.add_argument(
        'value',
        type=check_range,
        help='amount to set')

    """
    parser.add_argument(
        '-key','--keyfile',
        type=str,
        help="identify file containing user's private key")



def do_crt(args):
    client = _get_client(args)
    do_cmd(client.crt,args)
   

def add_call_parser(subparsers, parent_parser):
    message = 'Call smart method <name> <func>.'

    parser = subparsers.add_parser(
        DETH_CALL_OP,
        parents=[parent_parser],
        description=message,
        help='Call smart method')

    parser.add_argument(
        'name',
        type=str,
        help='identify name of smart contract')

    parser.add_argument(
        'func',
        type=str,
        help='identify name of smart contract function')

    #parser.add_argument(                                       
    #    '-p','--path',                                         
    #    type=str,                                              
    #    help='Smart contract path')
    parser.add_argument(            
        '-a','--args',              
        type=str,                   
        help='Smart contract function args') 
                                
                                                               
    #parser.add_argument(                                       
    #    '-op','--out_path',                                    
    #    type=str,                                              
    #    default="/project/peer/etc/contracts",                 
    #    help='Smart contract output path')                     


    parser.add_argument(
        '-key','--keyfile',
        type=str,
        help="identify file containing user's private key")



def do_call(args):
    client = _get_client(args)
    do_cmd(client.call,args)
    


def add_perm_parser(subparsers, parent_parser):
    message = 'Sends an bgt transaction to decrement <name> by <value>.'

    parser = subparsers.add_parser(
        DETH_PERM_OP,
        parents=[parent_parser],
        description=message,
        help='Decrements an bgt value')

    parser.add_argument(
        'name',
        type=str,
        help='identify name of key to decrement')

    parser.add_argument(
        'value',
        type=check_range,
        help='amount to decrement')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")


def add_smart_parser(subparsers, parent_parser):
    message = 'Sends  transaction for smart contract <name> create  .'

    parser = subparsers.add_parser(
        DETH_SMART_OP,
        parents=[parent_parser],
        description=message,
        help='Smart contract create')

    parser.add_argument(
        'name',
        type=str,
        help='identify name of smart contract')

    parser.add_argument(                                   
        '-p','--path',                                
        type=str,                                          
        help='Smart contract path')                        

    parser.add_argument(
        '-op','--out_path',
        type=str,
        default="/project/peer/etc/contracts",
        help='Smart contract output path')
    #gas_price
    parser.add_argument(                      
        '-gas','--gas_amount',                     
        type=int,
        default=0,                             
        help='Gas amount ')  
    parser.add_argument(           
        '-gasp','--gas_price',     
        type=int,
        default=1,                  
        help='Gas price ')        
    parser.add_argument(
        '-comp', '--compile',
        action='count',
        default=0,
        help='First compile contract')
    parser.add_argument(
        '-upd', '--update',
        action='count',
        default=0,
        help='Update contract version')
    parser.add_argument(                                    
        '-skey','--smart_keyfile',                                 
        type=str,                                           
        help="identify file containing smart contract addr or private key") 

    parser.add_argument(
        '-key','--keyfile',
        type=str,
        help="identify file containing user's private key")

 

def do_perm(args):
    client = _get_client(args)
    do_cmd(client.perm,args)


def do_smart(args):
    client = _get_client(args)
    do_cmd(client.smart,args)


                                                                                   
def add_send_parser(subparsers, parent_parser):                                    
    message = 'Sends <value> to <to> .'           
                                                                                   
    parser = subparsers.add_parser(                                                
        DETH_SEND_OP,                                                              
        parents=[parent_parser],                                                   
        description=message,                                                       
        help='Send an money')                                            
                                                                                   
    parser.add_argument(                                                           
        'to',                                                                    
        type=str,                                                                  
        help='Recipient key')                                  
                                                                                   
    parser.add_argument(                                                           
        'value',                                                                   
        type=check_range,                                                          
        help='amount to send')                                                
                                                                                   
    parser.add_argument(                                                           
        '-key','--keyfile',                                                               
        type=str,                                                                  
        help="identify file containing user's private key")                        



def do_send(args):                                                       
    client = _get_client(args)
    do_cmd(client.send,args)                                           
    

def add_show_parser(subparsers, parent_parser):
    message = 'Shows the value of the key <name>.'

    parser = subparsers.add_parser(
        'show',
        parents=[parent_parser],
        description=message,
        help='Displays the specified ETH account')

    parser.add_argument(
        'name',
        type=str,
        help='name of key to show')

def print_token(client,name,token,filter=DETH_ALL,verb=True):
    data = {'key'   :name,
                    DETH_ACCOUNT:{                                    
                    'address':token.account.address.hex(),                    
                    'balance':token.account.balance,                          
                    'nonce':token.account.nonce,

                    }
            }


    if token.account.code is not None and len(token.account.code) > 0:
        if filter == DETH_ACCOUNT:
            return
        code = cbor.loads(token.account.code)
        smart = client.get_smart_api(token.account.address,code[DETH_SMART_ABI])
        data[DETH_ACCOUNT][DETH_SMART_CODE] = {
                                  DETH_SMART_NAME : code[DETH_SMART_NAME],
                                  DETH_SMART_PATH : code[DETH_SMART_PATH],
                                  DETH_SMART_FUNCS: smart.all_functions() if verb else [f['name'] for f in smart.functions._functions if f["type"] == 'function'],
                                 }

    elif filter == DETH_SMART:
        return
    ret = do_yaml(data)   
    print(ret)                        


def do_show(args):
    name = args.name
    client = _get_client(args)
    value = client.show(name)
    token = EvmEntry()
    token.ParseFromString(value)
    print_token(client,name,token)
    
    #print('{}: {} addr={} bal={}'.format(name,token,token.account.address.hex(),token.account.balance))


def add_list_parser(subparsers, parent_parser):
    message = 'Shows the all ETH accounts.'

    parser = subparsers.add_parser(
        'list',
        parents=[parent_parser],
        description=message,
        help='Displays all ETH accounts')

    parser.add_argument(                                                                           
        '-tp','--type',                                                                            
        type=str,
        default=DETH_ALL,                                                                                  
        choices=[DETH_ALL,DETH_SMART,DETH_ACCOUNT] ,   
        help='Type of account to filter')                                                              


def do_list(args):
    client = _get_client(args)
    results = client.list()
    token = EvmEntry()
    for pair in results:
        for name, value in pair.items():
            token.ParseFromString(value)
            print_token(client,name,token,filter=args.type,verb=args.verbose > 0)


def _get_client(args):
    return DethClient(
        url=args.url,
        keyfile=_get_keyfile(args),
        token=args.access_token)


def _get_keyfile(args):
    try:
        if args.keyfile is not None:
            return args.keyfile
    except AttributeError:
        return None

    real_user = getpass.getuser()
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".dgt", "keys")

    return '{}/{}.priv'.format(key_dir, real_user)


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

    if args.command == DETH_CRT_OP:
        do_crt(args)
    
    elif args.command == DETH_SEND_OP:    
        do_send(args)                     
    elif args.command == DETH_CALL_OP:
        do_call(args)
    elif args.command == DETH_PERM_OP:
        do_perm(args)
    elif args.command == DETH_SMART_OP:
        do_smart(args)
    elif args.command == DETH_SHOW_OP:
        do_show(args)
    elif args.command == DETH_LIST_OP:
        do_list(args)
    elif args.command == 'generate':
        do_generate(args)
    elif args.command == 'populate':
        do_populate(args)
    elif args.command == 'load':
        do_load(args)
    elif args.command == 'create_batch':
        do_create_batch(args)
    elif args.command == 'workload':
        do_workload(args)

    else:
        raise DethCliException("invalid command: {}".format(args.command))


def main_wrapper():
    # pylint: disable=bare-except
    try:
        main()
    except (DethCliException, DethClientException) as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
