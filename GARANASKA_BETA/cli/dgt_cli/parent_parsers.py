# Copyright 2020 DGT NETWORK INC © Stanislav Parsov 
#
# Licensed under the Apache License, Version 2.0 (the 'License');
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

from argparse import ArgumentParser
import yaml
import time

def do_yaml(data):                                                               
    return yaml.dump(data,explicit_start=True,indent=4,default_flow_style=False) 

def do_tmstamp2str(val):                                      
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(val)) 


def base_http_parser():
    """Creates a parser with arguments specific to sending an HTTP request
    to the REST API.

    Returns:
        {ArgumentParser}: Base parser with default HTTP args
    """
    base_parser = ArgumentParser(add_help=False)

    base_parser.add_argument(
        '--url','-U',
        type=str,
        help="identify the URL of the validator's REST API "
        "(default: http://api-dgt-c1-1:8108)")
    base_parser.add_argument(      
        '--access_token','-atok',    
        type=str,                    
        default=None,                
        help='Access token')         


    return base_parser

def url_http_parser():
    """Creates a parser with arguments specific to sending an HTTP request
    to the REST API.

    Returns:
        {ArgumentParser}: Base parser with default HTTP args
    """
    base_parser = ArgumentParser(add_help=False)

    base_parser.add_argument(
        '--url','-U',
        type=str,
        help="identify the URL of the validator's REST API "
        "(default: http://api-dgt-c1-1:8108)")
    return base_parser


def user_http_parser():
    """Creates a parser with arguments specific to sending an HTTP request
    to the REST API.

    Returns:
        {ArgumentParser}: Base parser with default HTTP args
    """
    base_parser = ArgumentParser(add_help=False)

    base_parser.add_argument(
        '-u', '--user',
        type=str,
        metavar='USERNAME[:PASSWORD]',
        help='specify the user to authorize request')


    return base_parser


def base_list_parser():
    """Creates a parser with arguments specific to formatting lists
    of resources.

    Returns:
        {ArgumentParser}: Base parser with defaul list args
    """
    base_parser = ArgumentParser(add_help=False)

    base_parser.add_argument(
        '-F', '--format',
        action='store',
        default='default',
        choices=['csv', 'json', 'yaml', 'default'],
        help='choose the output format')

    return base_parser


def base_show_parser():
    """Creates a parser with arguments specific to formatting a
    single resource.

    Returns:
        {ArgumentParser}: Base parser with default show args
    """
    base_parser = ArgumentParser(add_help=False)

    base_parser.add_argument(
        '-k', '--key',
        type=str,
        help='show a single property from the block or header')
    base_parser.add_argument(
        '-F', '--format',
        action='store',
        default='yaml',
        choices=['yaml', 'json'],
        help='choose the output format (default: yaml)')

    return base_parser
