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
import cbor
from colorlog import ColoredFormatter

from dgt_stuff.client_cli.generate import add_generate_parser
from dgt_stuff.client_cli.generate import do_generate
from dgt_stuff.client_cli.populate import add_populate_parser
from dgt_stuff.client_cli.populate import do_populate
from dgt_stuff.client_cli.create_batch import add_create_batch_parser
from dgt_stuff.client_cli.create_batch import do_create_batch
from dgt_stuff.client_cli.load import add_load_parser
from dgt_stuff.client_cli.load import do_load
from dgt_stuff.client_cli.stuff_workload import add_workload_parser
from dgt_stuff.client_cli.stuff_workload import do_workload

from dgt_stuff.client_cli.stuff_client import StuffClient
from dgt_stuff.client_cli.exceptions import StuffCliException
from dgt_stuff.client_cli.exceptions import StuffClientException
from stuff_common.protobuf.smart_stuff_token_pb2 import StuffTokenInfo

DISTRIBUTION_NAME = 'dgt-stuff'


CRYPTO_BACK="openssl"

DEFAULT_URL = 'http://api-dgt-c1-1:8108'
#DGT_API_URL = 'https://api-dgt-c1-1:8108' if os.environ.get('HTTPS_MODE') == '--http_ssl' else 'http://api-dgt-c1-1:8108'
DGT_API_URL = os.environ.get('DGT_API_URL',DEFAULT_URL) or DEFAULT_URL

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

    add_set_parser(subparsers, parent_parser)
    add_upd_parser(subparsers, parent_parser)
    add_dec_parser(subparsers, parent_parser)
    add_trans_parser(subparsers, parent_parser)
    add_show_parser(subparsers, parent_parser)
    add_list_parser(subparsers, parent_parser)

    add_generate_parser(subparsers, parent_parser)
    add_load_parser(subparsers, parent_parser)
    add_populate_parser(subparsers, parent_parser)
    add_create_batch_parser(subparsers, parent_parser)
    add_workload_parser(subparsers, parent_parser)

    return parser


def add_set_parser(subparsers, parent_parser):
    message = 'Sends an bgt transaction to set <name> to <value>.'

    parser = subparsers.add_parser(
        'set',
        parents=[parent_parser],
        description=message,
        help='Sets an stuff value')

    parser.add_argument(
        'name',
        type=str,
        help='name of key to set')

    parser.add_argument(
        'value',
        type=str,
        help='stuff atributes JSON')
    parser.add_argument(
        '--user',
        type=str,
        help='specify User name')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

 

def do_set(args):
    name, value, wait, user = args.name, args.value, args.wait, args.user
    client = _get_client(args)
    response = client.set(name, value, wait,user)
    print(response)


def add_upd_parser(subparsers, parent_parser):
    message = 'Sends an bgt transaction to increment <name> by <value>.'

    parser = subparsers.add_parser(
        'upd',
        parents=[parent_parser],
        description=message,
        help='Update stuff atributes')

    parser.add_argument(
        'name',
        type=str,
        help='identify name of key to increment')

    parser.add_argument(
        'value',
        type=str,
        help='specify stuff atributes to update')
    parser.add_argument(
        '--user',
        type=str,
        help='specify User name')


    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")



def do_upd(args):
    name, value, wait, user = args.name, args.value, args.wait, args.user
    client = _get_client(args)
    response = client.upd(name, value, wait, user)
    print(response)


def add_dec_parser(subparsers, parent_parser):
    message = 'Sends an bgt transaction to decrement <name> by <value>.'

    parser = subparsers.add_parser(
        'dec',
        parents=[parent_parser],
        description=message,
        help='Decrements an bgt value')

    parser.add_argument(
        'name',
        type=str,
        help='identify name of key to decrement')

    parser.add_argument(
        'value',
        type=int,
        help='amount to decrement')


    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")


def add_trans_parser(subparsers, parent_parser):
    message = 'Sends an bgt transaction from <name> to  <to> by <value>.'

    parser = subparsers.add_parser(
        'trans',
        parents=[parent_parser],
        description=message,
        help='transfer an bgt value from vallet to vallet')

    parser.add_argument(
        'name',
        type=str,
        help='identify name of key transfer from')

    parser.add_argument(
        'value',
        type=int,
        help='amount to transfer')

    parser.add_argument(
        'to',
        type=str,
        help='identify name of key transfer to')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")



def do_dec(args):
    name, value, wait = args.name, args.value, args.wait
    client = _get_client(args)
    response = client.dec(name, value, wait)
    print(response)

def do_trans(args):
    name, value,to, wait = args.name, args.value, args.to, args.wait
    client = _get_client(args)
    response = client.trans(name, value, to, wait)
    print(response)


def add_show_parser(subparsers, parent_parser):
    message = 'Shows the value of the key <name>.'

    parser = subparsers.add_parser(
        'show',
        parents=[parent_parser],
        description=message,
        help='Displays the specified bgt value')

    parser.add_argument(
        'name',
        type=str,
        help='name of key to show')



def do_show(args):
    name = args.name
    client = _get_client(args)
    value = client.show(name)
    token = StuffTokenInfo()
    token.ParseFromString(value)
    stuff = cbor.loads(token.stuff)
    print('{}: {}={} user={}'.format(name,token.group_code,stuff,token.user))


def add_list_parser(subparsers, parent_parser):
    message = 'Shows the values of all keys in bgt state.'

    parser = subparsers.add_parser(
        'list',
        parents=[parent_parser],
        description=message,
        help='Displays all bgt values')



def do_list(args):
    client = _get_client(args)
    results = client.list()
    token = StuffTokenInfo()
    for pair in results:
        for name, value in pair.items():
            token.ParseFromString(value)
            stuff = cbor.loads(token.stuff)
            print('{}: {}={}'.format(name,token.group_code,stuff))


def _get_client(args):
    return StuffClient(
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

    if args.command == 'set':
        do_set(args)
    elif args.command == 'upd':
        do_upd(args)
    elif args.command == 'dec':
        do_dec(args)
    elif args.command == 'trans':
        do_trans(args)
    elif args.command == 'show':
        do_show(args)
    elif args.command == 'list':
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
        raise StuffCliException("invalid command: {}".format(args.command))


def main_wrapper():
    # pylint: disable=bare-except
    try:
        main()
    except (StuffCliException, StuffClientException) as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
