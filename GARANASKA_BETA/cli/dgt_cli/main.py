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

from __future__ import print_function

import argparse
import logging
import os
import traceback
import sys
import pkg_resources

from colorlog import ColoredFormatter

from dgt_cli.exceptions import CliException

from dgt_cli.keygen import add_keygen_parser
from dgt_cli.keygen import do_keygen
from dgt_cli.block import add_block_parser
from dgt_cli.block import do_block
from dgt_cli.batch import add_batch_parser
from dgt_cli.batch import do_batch
from dgt_cli.transaction import add_transaction_parser
from dgt_cli.transaction import do_transaction
from dgt_cli.state import add_state_parser
from dgt_cli.state import do_state
from dgt_cli.identity import add_identity_parser
from dgt_cli.identity import do_identity
from dgt_cli.settings import add_settings_parser
from dgt_cli.settings import do_settings
from dgt_cli.peer import add_peer_parser
from dgt_cli.peer import do_peer
from dgt_cli.token import add_token_parser  
from dgt_cli.token import do_token          
from dgt_cli.status import add_status_parser
from dgt_cli.status import do_status
from dgt_cli.head import add_dag_parser
from dgt_cli.head import do_dag

from dgt_cli.cli_config import load_cli_config


DISTRIBUTION_NAME = 'dgt-cli'


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
    """
    parent_parser.add_argument(             
        '--access_token','-atok',           
        type=str,                           
        default=None,                       
        help='Access token')                

    """


    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth-DGT) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to configure, manage, and use Dgt components.',parents=[parent_parser],
        )

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True

    add_batch_parser(subparsers, parent_parser)
    add_block_parser(subparsers, parent_parser)
    add_identity_parser(subparsers, parent_parser)
    add_keygen_parser(subparsers, parent_parser)
    add_peer_parser(subparsers, parent_parser)
    add_token_parser(subparsers, parent_parser)
    add_status_parser(subparsers, parent_parser)
    add_settings_parser(subparsers, parent_parser)
    add_state_parser(subparsers, parent_parser)
    add_transaction_parser(subparsers, parent_parser)
    add_dag_parser(subparsers,parent_parser)

    return parser


def main(prog_name=os.path.basename(sys.argv[0]), args=None,
         with_loggers=True):
    parser = create_parser(prog_name)
    if args is None:
        args = sys.argv[1:]
    args = parser.parse_args(args)

    load_cli_config(args)

    if with_loggers is True:
        if args.verbose is None:
            verbose_level = 0
        else:
            verbose_level = args.verbose
        setup_loggers(verbose_level=verbose_level)

    if args.command == 'keygen':
        do_keygen(args)
    elif args.command == 'block':
        do_block(args)
    elif args.command == 'token':    
        do_token(args)               
    elif args.command == 'batch':
        do_batch(args)
    elif args.command == 'transaction':
        do_transaction(args)
    elif args.command == 'state':
        do_state(args)
    elif args.command == 'identity':
        do_identity(args)
    elif args.command == 'settings':
        do_settings(args)
    elif args.command == 'peer':
        do_peer(args)
    elif args.command == 'status':
        do_status(args)
    elif args.command == 'dag':
        do_dag(args)
    else:
        raise CliException("invalid command: {}".format(args.command))


def main_wrapper():
    # pylint: disable=bare-except
    try:
        main()
    except CliException as e:
        print("Error: {}".format(e), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        sys.stderr.close()
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
