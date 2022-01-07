# Copyright 2016, 2018 NTRlab
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

from smart_bgt.client_cli.smart_bgt_client import SmartBgtClient

from colorlog import ColoredFormatter
from smart_bgt.client_cli.generate import add_generate_parser
from smart_bgt.client_cli.generate import do_generate
from smart_bgt.client_cli.populate import add_populate_parser
from smart_bgt.client_cli.populate import do_populate
from smart_bgt.client_cli.create_batch import add_create_batch_parser
from smart_bgt.client_cli.create_batch import do_create_batch
from smart_bgt.client_cli.load import add_load_parser
from smart_bgt.client_cli.load import do_load
from smart_bgt.client_cli.smart_bgt_workload import add_workload_parser
from smart_bgt.client_cli.smart_bgt_workload import do_workload



from smart_bgt.client_cli.exceptions import SmartBgtCliException
from smart_bgt.client_cli.exceptions import SmartBgtClientException


DISTRIBUTION_NAME = 'smart-bgt'

DEFAULT_URL = 'http://127.0.0.1:8008'


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

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        parents=[parent_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    add_init_parser(subparsers, parent_parser)
    add_transfer_parser(subparsers, parent_parser)
    add_allowance_parser(subparsers, parent_parser)
    add_generate_key_parser(subparsers, parent_parser)
    add_show_parser(subparsers, parent_parser)
    add_list_parser(subparsers, parent_parser)
    add_balance_of_parser(subparsers, parent_parser)
    add_total_supply_parser(subparsers, parent_parser)

    add_generate_parser(subparsers, parent_parser)
    add_load_parser(subparsers, parent_parser)
    add_populate_parser(subparsers, parent_parser)
    add_create_batch_parser(subparsers, parent_parser)
    add_workload_parser(subparsers, parent_parser)

    return parser


def add_init_parser(subparsers, parent_parser):
    message = 'Sends an bgt transaction to init <name> to <value>.'

    parser = subparsers.add_parser(
        'init',
        parents=[parent_parser],
        description=message,
        help='Make BGT emission')

    parser.add_argument(
        'full_name',
        type=str,
        help='')

    parser.add_argument(
        'private_key',
        type=str,
        help='')

    parser.add_argument(
        'ethereum_address',
        type=str,
        help='')

    parser.add_argument(
        'num_bgt',
        type=str,
        help='')

    parser.add_argument(
        'bgt_price',
        type=str,
        help='')

    parser.add_argument(
        'dec_price',
        type=str,
        help='')

    parser.add_argument(
        '--url',
        type=str,
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


def add_transfer_parser(subparsers, parent_parser):
    message = 'Sends an num_bgt transaction to transfer <from_addr> to <to_addr>.'

    parser = subparsers.add_parser(
        'transfer',
        parents=[parent_parser],
        description=message,
        help='Make BGT transfer')

    parser.add_argument(
        'from_addr',
        type=str,
        help='')

    parser.add_argument(
        'to_addr',
        type=str,
        help='')

    parser.add_argument(
        'num_bgt',
        type=str,
        help='')

    parser.add_argument(
        'group_id',
        type=str,
        help='')

    parser.add_argument(
        '--url',
        type=str,
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


def add_allowance_parser(subparsers, parent_parser):
    message = 'Check: try to send an num_bgt from <from_addr>.'

    parser = subparsers.add_parser(
        'allowance',
        parents=[parent_parser],
        description=message,
        help='Check BGT transfer')

    parser.add_argument(
        'from_addr',
        type=str,
        help='')

    parser.add_argument(
        'num_bgt',
        type=str,
        help='')

    parser.add_argument(
        'group_id',
        type=str,
        help='')

    parser.add_argument(
        '--url',
        type=str,
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


def add_balance_of_parser(subparsers, parent_parser):
    message = 'Check balance of <addr>.'

    parser = subparsers.add_parser(
        'balance_of',
        parents=[parent_parser],
        description=message,
        help='Check balance of <addr>')

    parser.add_argument(
        'addr',
        type=str,
        help='')

    parser.add_argument(
        '--url',
        type=str,
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


def add_total_supply_parser(subparsers, parent_parser):
    message = 'Check total supply of <token name>.'

    parser = subparsers.add_parser(
        'total_supply',
        parents=[parent_parser],
        description=message,
        help='Check total supply of <token name>')

    parser.add_argument(
        'token_name',
        type=str,
        help='')

    parser.add_argument(
        '--url',
        type=str,
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


def add_generate_key_parser(subparsers, parent_parser):
    message = 'Generate some key.'

    parser = subparsers.add_parser(
        'generate_key',
        parents=[parent_parser],
        description=message,
        help='Generate some key')

    parser.add_argument(
        '--url',
        type=str,
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

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')


def do_init(args):
    full_name, private_key, ethereum_address, num_bgt, bgt_price, dec_price, wait  = args.full_name, \
        args.private_key, args.ethereum_address, args.num_bgt, args.bgt_price, args.dec_price, args.wait
    client = _get_client(args)
    response = client.init(full_name, private_key, ethereum_address, num_bgt, bgt_price, dec_price, wait)
    print(response)


def do_transfer(args):
    from_addr, to_addr, num_bgt, group_id, wait = args.from_addr, args.to_addr, args.num_bgt, args.group_id, args.wait
    print("SMART_BGT>client_cli>smart_bgt_cli>do_transfer"
                 "\nfrom_addr=%s\nto_addr=%s\nnum_bgt=%s\ngroup_id=%s\nwait=%s",
                 from_addr, to_addr, num_bgt, group_id, wait)
    client = _get_client(args)
    response = client.transfer(from_addr, to_addr, num_bgt, group_id, wait)
    print(response)


def do_allowance(args):
    from_addr, num_bgt, group_id, wait = args.from_addr, args.num_bgt, args.group_id, args.wait
    client = _get_client(args)
    response = client.allowance(from_addr, num_bgt, group_id, wait)
    print(response)


def get_balance_of(args):
    addr, wait = args.addr, args.wait
    client = _get_client(args)
    response = client.balance_of(addr, wait)
    print(response)


def get_total_supply(args):
    token_name, wait = args.token_name, args.wait
    client = _get_client(args)
    response = client.total_supply(token_name, wait)
    print(response)


def do_generate_key(args):
    wait = args.wait
    client = _get_client(args)
    response = client.generate_key(wait)
    print(response)


def do_show(args):
    name = args.name
    client = _get_client(args)
    value = client.show(name)
    print('{}: {}'.format(name, value))


def add_list_parser(subparsers, parent_parser):
    message = 'Shows the values of all keys in smart bgt state.'

    parser = subparsers.add_parser(
        'list',
        parents=[parent_parser],
        description=message,
        help='Displays all smart bgt values')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')


def do_list(args):
    client = _get_client(args)
    results = client.list()
    for pair in results:
        for name, value in pair.items():
            print('{}: {}'.format(name, value))


def _get_client(args):
    return SmartBgtClient(
        url=DEFAULT_URL if args.url is None else args.url,
        keyfile=_get_keyfile(args))


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

    if args.command == 'init':
        do_init(args)
    elif args.command == 'balance_of':
        get_balance_of(args)
    elif args.command == 'total_supply':
        get_total_supply(args)
    elif args.command == 'transfer':
        do_transfer(args)
    elif args.command == 'allowance':
        do_allowance(args)
    elif args.command == 'generate_key':
        do_generate_key(args)
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
        raise SmartBgtCliException("invalid command: {}".format(args.command))


def main_wrapper():
    # pylint: disable=bare-except
    try:
        main()
    except (SmartBgtCliException, SmartBgtClientException) as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
