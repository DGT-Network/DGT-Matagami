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

import os
import sys
import logging
import asyncio
import argparse
import cbor
from urllib.parse import urlparse
import platform
import pkg_resources
from aiohttp import web

from zmq.asyncio import ZMQEventLoop
from pyformance import MetricsRegistry
from pyformance.reporters import InfluxReporter

from dgt_sdk.processor.log import init_console_logging
from dgt_sdk.processor.log import log_configuration
from dgt_sdk.processor.config import get_log_config
from dgt_sdk.processor.config import get_log_dir
from dgt_sdk.processor.config import get_config_dir
from dgt_validator.database.indexed_database import IndexedDatabase
from dgt_validator.database.lmdb_nolock_database import LMDBNoLockDatabase

from bgt_bot_api.messaging import Connection
#from sawtooth_rest_api.route_handlers import RouteHandler
#DGT handlers
#from bgt_bot_api.bgx_handlers import DgtRouteHandler
from bgt_bot_api.bot_handlers import Tbot
from bgt_bot_api.bgx_handlers import BgxTeleBot

from bgt_bot_api.state_delta_subscription_handler import StateDeltaSubscriberHandler
from bgt_bot_api.config import load_default_bot_api_config
from bgt_bot_api.config import load_toml_bot_api_config
from bgt_bot_api.config import merge_bot_api_config
from bgt_bot_api.config import BotApiConfig


LOGGER = logging.getLogger(__name__)
#logging.basicConfig(level=logging.INFO)
#LOGGER.setLevel(logging.INFO)
DISTRIBUTION_NAME = 'bgt-bot-api'
TOKEN='1205652427:AAFr0eynwihWGyvObUA0QSjOfKMwiH3HkZs'
TELE_DB_FILENAME = '/project/peer/data/telebot.lmdb'
DEFAULT_DB_SIZE= 1024*1024*4

def deserialize_data(encoded):
    return cbor.loads(encoded)


def serialize_data(value):
    return cbor.dumps(value, sort_keys=True)

def parse_args(args):
    """Parse command line flags added to `rest_api` command.
    """
    parser = argparse.ArgumentParser(
        description='Starts the BOT application and connects to a specified validator.')

    parser.add_argument('-B', '--bind',
                        help='identify host and port for API to run on \
                        default: http://localhost:8008)',
                        action='append')
    parser.add_argument('-C', '--connect',
                        nargs="+",
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


def start_bot_api(host, port, connection, timeout, registry,connects=None,client_max_size=None):
    """Builds the web app, adds route handlers, and finally starts the app.
    """
    #tele_db = LMDBNoLockDatabase(TELE_DB_FILENAME, 'c')
    tele_db = IndexedDatabase(
            TELE_DB_FILENAME,
            serialize_data,
            deserialize_data,
            indexes={'name': lambda dict: [dict['name'].encode()],'type': lambda dict: [dict['type'].encode()]},
            flag='c',
            _size=DEFAULT_DB_SIZE,
            dupsort=True
            )
    if "ROOT" in tele_db:
        LOGGER.info('TAKE ROOT FROM DB=%s', tele_db["ROOT"])
        #for key in tele_db.keys():
        LOGGER.info('KEYS=%s', list(tele_db.keys()))
        with tele_db.cursor() as curs:
            for val in curs.iter():
                LOGGER.info('values=%s',val)
        with tele_db.cursor(index='name') as curs:
            #values = list(curs.iter())
            for val in curs.iter():
                LOGGER.info('Name values=%s',val)
        #LOGGER.info('ordered_values=%s',values)

    else:
        tele_db.put("ROOT", {'val':1,'name':'sticker','type':'user'})

    loop = asyncio.get_event_loop()
    connection.open()
    bot = BgxTeleBot(loop, connection,tele_db,TOKEN,connects=connects) #Tbot(loop, connection,TOKEN)
    # add handler for intention
    bot.add_intent_handler('smalltalk.greetings.hello',bot.intent_hello)
    bot.add_intent_handler('smalltalk.greetings.bye',bot.intent_bye)
    bot.add_intent_handler('smalltalk.agent.can_you_help',bot.intent_help)
    bot.add_intent_handler('smalltalk.dialog.hold_on',bot.intent_hold_on)
    bot.add_intent_handler('smalltalk.user.needs_advice',bot.intent_needs_advice)
    #bot.add_intent_handler('smalltalk.agent.get_wallet',bot.intent_get_wallet)
    bot.add_intent_handler('smalltalk.agent.check_wallet',bot.intent_check_wallet)
    bot.add_intent_handler('smalltalk.agent.check_wallet_history',bot.intent_check_wallet_history)
    bot.add_intent_handler('smalltalk.agent.create_wallet',bot.intent_create_wallet)
    bot.add_intent_handler('smalltalk.agent.trans_token',bot.intent_trans_token)
    bot.add_intent_handler('smalltalk.agent.inc_wallet',bot.intent_inc_wallet)
    bot.add_intent_handler('smalltalk.agent.dec_wallet',bot.intent_dec_wallet)
    bot.add_intent_handler('smalltalk.agent.buy_stuff',bot.intent_buy_stuff)
    bot.add_intent_handler('smalltalk.agent.sell_stuff',bot.intent_sell_stuff)
    # make stuff
    bot.add_intent_handler('smalltalk.agent.create_stuff',bot.intent_create_stuff)
    bot.add_intent_handler('smalltalk.agent.update_stuff',bot.intent_update_stuff)
    bot.add_intent_handler('smalltalk.agent.show_stuff',bot.intent_show_stuff)
    bot.add_intent_handler("smalltalk.agent.show_stuff_history",bot.intent_show_stuff_history)
    bot.add_intent_handler("smalltalk.agent.show_stuff_list",bot.intent_show_stuff_list)
    #
    bot.add_intent_handler("smalltalk.agent.show_gateway",bot.intent_show_gateway)
    bot.add_intent_handler("smalltalk.agent.show_gateway_list",bot.intent_show_gateway_list)
    bot.add_intent_handler("smalltalk.agent.set_gateway",bot.intent_set_gateway)
    bot.add_intent_handler("smalltalk.agent.peers_down",bot.intent_peers_down)
    bot.add_intent_handler("smalltalk.agent.peers_up",bot.intent_peers_up)
    bot.add_intent_handler("smalltalk.agent.peers_control_list",bot.intent_peers_control_list)
    bot.add_intent_handler("smalltalk.agent.peer_info",bot.intent_peer_info)

    bot.add_intent_handler("smalltalk.agent.pause",bot.intent_pause)
    bot.add_intent_handler("smalltalk.agent.unpause",bot.intent_unpause)
    bot.add_intent_handler('smalltalk.agent.chat_admins',bot.intent_chat_admins)
    bot.add_intent_handler('smalltalk.agent.get_users',bot.intent_get_users)
    LOGGER.info('start_bot_api for=%s', TOKEN)
    bot.start()
    """
    loop = asyncio.get_event_loop()
    connection.open()
    app = web.Application(loop=loop, client_max_size=client_max_size)
    app.on_cleanup.append(lambda app: connection.close())

    # Add routes to the web app
    handler = DgtRouteHandler(loop, connection, timeout, registry)
    LOGGER.info('Creating handlers for validator at %s', connection.url)

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

    # ADD BGX handlers
    app.router.add_get('/dag', handler.list_dag)
    app.router.add_get('/dag/{head_id}', handler.fetch_dag)
    app.router.add_get('/topology', handler.fetch_topology)

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
    LOGGER.info('Starting REST API on %s:%s', host, port)

    web.run_app(
        app,
        host=host,
        port=port,
        access_log=LOGGER,
        access_log_format='%r: %s status, %b size, in %Tf s')
    """

def load_bot_api_config(first_config):
    default_config = load_default_bot_api_config()
    config_dir = get_config_dir()
    conf_file = os.path.join(config_dir, 'rest_api.toml')

    toml_config = load_toml_bot_api_config(conf_file)
    return merge_bot_api_config(
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
        opts_config = BotApiConfig(
            bind=opts.bind,
            connect=opts.connect,
            timeout=opts.timeout,
            opentsdb_url=opts.opentsdb_url,
            opentsdb_db=opts.opentsdb_db,
            opentsdb_username=opts.opentsdb_username,
            opentsdb_password=opts.opentsdb_password,
            client_max_size=opts.client_max_size)
        bot_api_config = load_bot_api_config(opts_config)
        url = None
        if "tcp://" not in bot_api_config.connect[0]:
            url = "tcp://" + bot_api_config.connect[0]
        else:
            url = bot_api_config.connect[0]

        connection = Connection(url)

        log_config = get_log_config(filename="bot_api_log_config.toml")

        # If no toml, try loading yaml
        if log_config is None:
            log_config = get_log_config(filename="bot_api_log_config.yaml")

        if log_config is not None:
            log_configuration(log_config=log_config)
        else:
            log_dir = get_log_dir()
            log_configuration(log_dir=log_dir, name="bgt-bot-api")
        init_console_logging(verbose_level=opts.verbose)

        try:
            host, port = bot_api_config.bind[0].split(":")
            port = int(port)
        except ValueError as e:
            print("Unable to parse binding {}: Must be in the format"
                  " host:port".format(bot_api_config.bind[0]))
            sys.exit(1)

        wrapped_registry = None
        if bot_api_config.opentsdb_url:
            LOGGER.info("Adding metrics reporter: url=%s, db=%s",bot_api_config.opentsdb_url,bot_api_config.opentsdb_db)

            url = urlparse(bot_api_config.opentsdb_url)
            proto, db_server, db_port, = url.scheme, url.hostname, url.port

            registry = MetricsRegistry()
            wrapped_registry = MetricsRegistryWrapper(registry)

            reporter = InfluxReporter(
                registry=registry,
                reporting_interval=10,
                database=bot_api_config.opentsdb_db,
                prefix="bgt_bot_api",
                port=db_port,
                protocol=proto,
                server=db_server,
                username=bot_api_config.opentsdb_username,
                password=bot_api_config.opentsdb_password)
            reporter.start()

        start_bot_api(
            host,
            port,
            connection,
            int(bot_api_config.timeout),
            wrapped_registry,
            connects=bot_api_config.connect,
            client_max_size=bot_api_config.client_max_size)
        # pylint: disable=broad-except
    except Exception as e:
        LOGGER.exception(e)
        sys.exit(1)
    finally:
        if connection is not None:
            try: 
                connection.close()
            except :
                pass
