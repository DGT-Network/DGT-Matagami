# Copyright 2016 DGT NETWORK INC © Stanislav Parsov
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

import os
import sys
import logging
import asyncio
import argparse
from urllib.parse import urlparse
import platform
import pkg_resources
from aiohttp import web
# add https
import ssl

from zmq.asyncio import ZMQEventLoop
from pyformance import MetricsRegistry
from pyformance.reporters import InfluxReporter

from dgt_sdk.processor.log import init_console_logging
from dgt_sdk.processor.log import log_configuration
from dgt_sdk.processor.config import get_log_config
from dgt_sdk.processor.config import get_log_dir
from dgt_sdk.processor.config import get_config_dir
from dgt_notary_api.messaging import Connection
from x509_cert.client_cli.notary_client import NotaryClient
#DGT handlers
from dgt_notary_api.notary_handlers import NotaryRouteHandler
from dgt_notary_api.state_delta_subscription_handler import StateDeltaSubscriberHandler
from dgt_notary_api.config import load_default_rest_api_config
from dgt_notary_api.config import load_toml_rest_api_config
from dgt_notary_api.config import merge_rest_api_config
from dgt_notary_api.config import RestApiConfig

from dgt_validator.database.indexed_database import IndexedDatabase
import cbor 

LOGGER = logging.getLogger(__name__)
DISTRIBUTION_NAME = 'dgt-notary-api'
NOTARY_PRIV_KEY = '/project/peer/keys/notary.priv'

NOTARY_DB_SIZE= 1024*1024*4
NOTARY_DB_FILENAME = '/project/peer/data/notary.lmdb'

HTTPS_SRV_KEY = '/project/peer/keys/http_srv.key'
HTTPS_SRV_CERT = '/project/peer/keys/http_srv.crt'
DGT_API_URL = 'https://api-dgt-c1-1:8108' if os.environ.get('HTTPS_MODE') == '--http_ssl' else 'http://api-dgt-c1-1:8108'

def deserialize_data(encoded):
    return cbor.loads(encoded)


def serialize_data(value):
    return cbor.dumps(value, sort_keys=True)


def parse_args(args):
    """Parse command line flags added to `rest_api` command.
    """
    parser = argparse.ArgumentParser(
        description='Starts the REST API application and connects to a '
        'specified validator.')

    parser.add_argument('-B', '--bind',
                        help='identify host and port for API to run on \
                        default: http://localhost:8008)',
                        action='append')
    parser.add_argument('-C', '--connect',
                        help='specify URL to connect to a running validator')
    parser.add_argument('-t', '--timeout',
                        help='set time (in seconds) to wait for validator \
                        response')
    parser.add_argument('--client-max-size',
                        type=int,
                        help='the max size (in bytes) of a request body')
    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='enable more verbose output to stderr')

    parser.add_argument('-hssl', '--http_ssl',      
                        action='count',             
                        default=0,                  
                        help='enable https mode')   

    parser.add_argument(                                            
        '--url',                                                    
        type=str,                                                   
        help="identify the URL of a validator's REST API",          
        default=DGT_API_URL) 
    parser.add_argument(                         
        '-cb', '--crypto-back',                  
        type=str,                                
        help='Specify a crypto back',            
        default='bitcoin')                                               

    parser.add_argument('--opentsdb-url',
                        help='specify host and port for Open TSDB database \
                        used for metrics')
    parser.add_argument('--opentsdb-url-off',                           
                        help='Switch off using metrics',                
                        type=str)                                       


    parser.add_argument('--opentsdb-db',
                        help='specify name of database for storing metrics')
    parser.add_argument('--opentsdb-username',
                        help='specify user name of database for storing metrics')
    parser.add_argument('--opentsdb-password',
                        help='specify user password of database for storing metrics')

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth) version {}')
        .format(version),
        help='display version information')

    return parser.parse_args(args)


def _query_index_keys(req):     
    LOGGER.info('_query_index_keys=%s',req)                                        
    keys = [val.encode() for key,val in req.items() if key == 'qid']
    return keys                              

def start_rest_api(host, port, connection, timeout, registry,client_max_size=None,vault=None,http_ssl=False):
    """Builds the web app, adds route handlers, and finally starts the app.
    """
    notary_db = IndexedDatabase(                                                                                                     
            NOTARY_DB_FILENAME,                                                                                                      
            serialize_data,                                                                                                        
            deserialize_data,                                                                                                      
            indexes={'query': _query_index_keys},                   
            flag='c',                                                                                                              
            _size=NOTARY_DB_SIZE,                                                                                                 
            dupsort=True                                                                                                           
            )
    if "ROOT" in notary_db:
        LOGGER.info('LIST REQUEST {}...\n'.format(notary_db.keys()))
        with notary_db.cursor() as curs:        
            for val in curs.iter():           
                LOGGER.info('VALUES=%s',val) 
        #notary_db.delete("ROOT")
    else:
        notary_db.put("ROOT", {'qid' : 'xxx'}) 

    loop = asyncio.get_event_loop()
    connection.open()
    app = web.Application(loop=loop, client_max_size=client_max_size)
    app.on_cleanup.append(lambda app: connection.close())

    # Add routes to the web app
    handler = NotaryRouteHandler(loop, connection, timeout, registry,vault=vault,db=notary_db)
    LOGGER.info('Creating handlers for validator at %s', connection.url)
    app.router.add_get('/show', handler.show_xcert)
    app.router.add_get('/list', handler.list_xcert)
    app.router.add_get('/crt', handler.crt_xcert)
    app.router.add_get('/upd', handler.upd_xcert)
    app.router.add_get('/wallets', handler.wallets)
    app.router.add_get('/roles', handler.roles)
    app.router.add_get('/goods', handler.goods)
    app.router.add_get('/balanceof', handler.balanceof)
    app.router.add_get('/approvals', handler.approvals)
    app.router.add_get('/approval', handler.approval)
    app.router.add_post('/notary_req', handler.notary_req)
    app.router.add_post('/notary_approve', handler.notary_approve)

    if False:
        app.router.add_post('/batches', handler.submit_batches)
        app.router.add_get('/batch_statuses', handler.list_statuses)
        app.router.add_post('/batch_statuses', handler.list_statuses)

        app.router.add_get('/state', handler.list_state)
        app.router.add_get('/state/{address}', handler.fetch_state)

        app.router.add_get('/blocks', handler.list_blocks)
        app.router.add_get('/blocks/{block_id}', handler.fetch_block)

        app.router.add_get('/batches', handler.list_batches)
        app.router.add_get('/batches/{batch_id}', handler.fetch_batch)
        
        app.router.add_get('/transactions', handler.list_transactions)
        app.router.add_get('/transactions/{transaction_id}',handler.fetch_transaction)

        app.router.add_get('/receipts', handler.list_receipts)
        app.router.add_post('/receipts', handler.list_receipts)
      
        app.router.add_get('/peers', handler.fetch_peers)
        app.router.add_get('/nodes', handler.fetch_nodes) # just for testing
        app.router.add_get('/status', handler.fetch_status)

    # ADD DGT handlers
    if False:
        app.router.add_get('/dag', handler.list_dag)
        app.router.add_get('/dag/{head_id}', handler.fetch_dag)
        app.router.add_get('/graph', handler.fetch_dag_graph)
        app.router.add_get('/topology', handler.fetch_topology)
        #ADD TP FAMILY handlers
        app.router.add_get('/tx_families', handler.tx_families)                           
        app.router.add_get('/run', handler.run_transaction)                               
        #app.router.add_get('/run_statuses',handler.list_statuses)  

    if False:
        app.router.add_post('/transactions', handler.post_transfer)
        app.router.add_get('/wallets/{address}', handler.get_wallet)
        app.router.add_post('/wallets', handler.post_wallet)
        app.router.add_post('/fee', handler.get_fee)
        app.router.add_get('/global_transactions', handler.get_global_transactions)
        app.router.add_post('/transactions/add_funds', handler.post_add_funds)
    #
    subscriber_handler = StateDeltaSubscriberHandler(connection)
    app.router.add_get('/subscriptions', subscriber_handler.subscriptions)
    app.on_shutdown.append(lambda app: subscriber_handler.on_shutdown())

    # Start app
    LOGGER.info('Starting NOTARY REST API on %s:%s HTTPS=%s', host, port,http_ssl)
    if http_ssl:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(HTTPS_SRV_CERT, HTTPS_SRV_KEY)
    else:
        ssl_context = None


    web.run_app(
        app,
        host=host,
        port=port,
        access_log=LOGGER,
        access_log_format='%r: %s status, %b size, in %Tf s'
        ,ssl_context=ssl_context)


def load_rest_api_config(first_config):
    default_config = load_default_rest_api_config()
    config_dir = get_config_dir()
    conf_file = os.path.join(config_dir, 'rest_api.toml')

    toml_config = load_toml_rest_api_config(conf_file)
    return merge_rest_api_config(
        configs=[first_config, toml_config, default_config])


class MetricsRegistryWrapper():
    def __init__(self, registry):
        self._registry = registry

    def gauge(self, name):
        return self._registry.gauge(
            ''.join([name, ',host=', platform.node()]))

    def counter(self, name):
        return self._registry.counter(
            ''.join([name, ',host=', platform.node()]))

    def timer(self, name):
        return self._registry.timer(
            ''.join([name, ',host=', platform.node()]))


def main():
    loop = ZMQEventLoop()
    asyncio.set_event_loop(loop)

    connection = None
    try:
        opts = parse_args(sys.argv[1:])
        opts_config = RestApiConfig(
            bind=opts.bind,
            connect=opts.connect,
            timeout=opts.timeout,
            opentsdb_url=opts.opentsdb_url,
            opentsdb_db=opts.opentsdb_db,
            opentsdb_username=opts.opentsdb_username,
            opentsdb_password=opts.opentsdb_password,
            client_max_size=opts.client_max_size)
        rest_api_config = load_rest_api_config(opts_config)
        url = None
        if "tcp://" not in rest_api_config.connect:
            url = "tcp://" + rest_api_config.connect
        else:
            url = rest_api_config.connect

        connection = Connection(url)

        log_config = get_log_config(filename="rest_api_log_config.toml")

        # If no toml, try loading yaml
        if log_config is None:
            log_config = get_log_config(filename="rest_api_log_config.yaml")

        if log_config is not None:
            log_configuration(log_config=log_config)
        else:
            log_dir = get_log_dir()
            log_configuration(log_dir=log_dir, name="rest-api")
        init_console_logging(verbose_level=opts.verbose)

        try:
            host, port = rest_api_config.bind[0].split(":")
            port = int(port)
        except ValueError as e:
            print("Unable to parse binding {}: Must be in the format"
                  " host:port".format(rest_api_config.bind[0]))
            sys.exit(1)

        wrapped_registry = None
        if rest_api_config.opentsdb_url:
            LOGGER.info("Adding metrics reporter: url=%s, db=%s",rest_api_config.opentsdb_url,rest_api_config.opentsdb_db)

            url = urlparse(rest_api_config.opentsdb_url)
            proto, db_server, db_port, = url.scheme, url.hostname, url.port

            registry = MetricsRegistry()
            wrapped_registry = MetricsRegistryWrapper(registry)

            reporter = InfluxReporter(
                registry=registry,
                reporting_interval=10,
                database=rest_api_config.opentsdb_db,
                prefix="dgt_notary_api",
                port=db_port,
                protocol=proto,
                server=db_server,
                username=rest_api_config.opentsdb_username,
                password=rest_api_config.opentsdb_password)
            reporter.start()
        # notary client add dec api
        vault = NotaryClient(opts.url,NOTARY_PRIV_KEY,opts.crypto_back)
        if not vault.init_vault():                
            LOGGER.info("VAULT NOT READY EXIT")        
            sys.exit(1)                           

        vault.init_dec(NOTARY_PRIV_KEY)
        start_rest_api(
            host,
            port,
            connection,
            int(rest_api_config.timeout),
            wrapped_registry,
            client_max_size=rest_api_config.client_max_size,
            vault = vault,
            http_ssl=opts.http_ssl > 0)
        # pylint: disable=broad-excpt
    except Exception as e:
        LOGGER.exception(e)
        sys.exit(1)
    finally:
        if connection is not None:
            connection.close()
