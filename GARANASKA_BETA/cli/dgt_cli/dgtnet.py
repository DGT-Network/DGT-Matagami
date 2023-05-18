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

import argparse
import logging
import os
import traceback
import sys
import pkg_resources

from colorlog import ColoredFormatter

from dgt_cli.exceptions import CliException
from dgt_cli.network_command.compare import add_compare_chains_parser
from dgt_cli.network_command.compare import do_compare_chains
from dgt_cli.network_command.list_blocks import add_list_blocks_parser
from dgt_cli.network_command.list_blocks import do_list_blocks
from dgt_cli.network_command.peers import add_peers_parser
from dgt_cli.network_command.peers import do_peers


DISTRIBUTION_NAME = 'dgtnet'


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Inspect status of a DGT network',
        parents=[parent_parser],)

    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')
    subparsers.required = True

    add_compare_chains_parser(subparsers, parent_parser)
    add_list_blocks_parser(subparsers, parent_parser)
    add_peers_parser(subparsers, parent_parser)

    return parser


def main(prog_name=os.path.basename(sys.argv[0]), args=None,with_loggers=True):
    parser = create_parser(prog_name)
    if args is None:
        args = sys.argv[1:]
    
    args = parser.parse_args(args)
    
    if with_loggers is True:
        if args.verbose is None:
            verbose_level = 0
        else:
            verbose_level = args.verbose
        setup_loggers(verbose_level=verbose_level)

    if args.subcommand == 'compare-chains':
        do_compare_chains(args)
    elif args.subcommand == 'list-blocks':
        do_list_blocks(args)
    elif args.subcommand == 'peers':
        do_peers(args)
    else:
        raise CliException('Invalid command: {}'.format(args.subcommand))


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
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth-DGT) version {}')
        .format(version),
        help='display version information')
    """
    parent_parser.add_argument(          
        '--access_token','-atok',        
        type=str,                        
        default=None,                    
        help='Access token')             
    """

    return parent_parser
