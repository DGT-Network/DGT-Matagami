 # Copyright 2023 DGT NETWORK INC © Stanislav Parsov 
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

from dgt_cli import format_utils as fmt
from dgt_cli.rest_client import RestClient
from dgt_cli.exceptions import CliException
from dgt_cli.parent_parsers import base_http_parser
from dgt_cli.parent_parsers import base_list_parser,do_tmstamp2str,do_yaml


def add_token_parser(subparsers, parent_parser):
    """Adds argument parser for the peer command

        Args:
            subparsers: Add parsers to this subparser object
            parent_parser: The parent argparse.ArgumentParser object
    """
    parser = subparsers.add_parser(
        'token',
        help='Get access token for user',
        #description="Provides a subcommand to list a validator's peers"
        )

    grand_parsers = parser.add_subparsers(title='subcommands',
                                          dest='subcommand')
    grand_parsers.required = True
    add_get_token_parser(grand_parsers, parent_parser)


def add_get_token_parser(subparsers, parent_parser):
    description = ('Get access token')

    parser = subparsers.add_parser(
        'get',
        description=description,
        parents=[base_http_parser(), base_list_parser()])

    parser.add_argument(                 
        '--client','-cli',               
        type=str,                               
        default="clientC",                           
        help='Client type')                    
    parser.add_argument(    
        '--scopes','-sc',  
        type=str,
        action='append',           
        default=None,  
        help='Scopes for client access') 



def do_token(args,url=None):
    if args.subcommand == 'get':
        do_get_token(args,url=url)

    else:
        raise CliException('Invalid command: {}'.format(args.subcommand))

TOK_EXPIRES_AT = "expires_at"
def do_get_token(args,url=None):
    burl = args.url if url is None else url
    rest_client = RestClient(base_url=burl,user=args.user,scopes=args.scopes,client=args.client)
    try:
        token = rest_client.get_token()
    except Exception as ex:
        print('ConnectionError:: {}'.format(ex))
        return
    
    if isinstance(token,dict) and TOK_EXPIRES_AT in token:
        token[TOK_EXPIRES_AT] =  do_tmstamp2str(token[TOK_EXPIRES_AT])
    if args.format == 'csv' or args.format == 'default':
        #print('token={}'.format(token))
        #fmt.print_json(token)
        print(do_yaml({k : v for k,v in token.items()}))
        #fmt.print_yaml({k : v for k,v in token.items()})

    elif args.format == 'json':
        fmt.print_json(token)

    elif args.format == 'yaml':
        fmt.print_yaml(token)
