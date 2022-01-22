# Copyright 2018 NTRlab
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

import sys
import os
import argparse
import logging
import pkg_resources

from dgt_sdk.processor.log import init_console_logging
from dgt_sdk.processor.log import log_configuration
from dgt_sdk.processor.config import get_log_config
from dgt_sdk.processor.config import get_log_dir
from dgt_sdk.processor.config import get_config_dir

from dgt_sdk.consensus.zmq_driver import ZmqDriver
from pbft_engine.engine import PbftEngine

from pbft.config.path import load_path_config
from pbft.exceptions import LocalConfigurationError
from pbft_engine.config.pbft import PbftConfig,load_default_pbft_config,load_toml_pbft_config,merge_pbft_config
from dgt_sdk.messaging.future import FutureTimeoutError
DISTRIBUTION_NAME = 'dgt-pbft'

LOGGER = logging.getLogger(__name__)
MAX_CONNECT_ATTEMPTS=4

def parse_args(args):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        '-C', '--connect',
        default='tcp://localhost:5050',
        help='Endpoint for the validator connection')

    parser.add_argument(
        '--component',
        default='tcp://localhost:4004',
        help='Endpoint for the validator component connection')

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='Increase output sent to stderr')
    parser.add_argument('-sc', '--signed_consensus',                  
                        action='count',                               
                        default=0,                                    
                        help='enable signed consensus mode')          




    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth-DGT) version {}')
        .format(version),
        help='print version information')

    return parser.parse_args(args)

def load_pbft_config(first_config):
    default_pbft_config = load_default_pbft_config()
    conf_file = os.path.join(get_config_dir(), 'pbft.toml')

    toml_config = load_toml_pbft_config(conf_file)

    return merge_pbft_config(configs=[first_config, toml_config, default_pbft_config])

def create_pbft_config(args):
    return PbftConfig(node=args['node'] if args is not None and 'node' in args else None)


def main(args=None):
    try:
        path_config = load_path_config()
    except LocalConfigurationError as local_config_err:
        LOGGER.error(str(local_config_err))
        sys.exit(1)

    if args is None:
        args = sys.argv[1:]
    opts = parse_args(args)

    try:
        arg_config = create_pbft_config(opts)
        pbft_config = load_pbft_config(arg_config)

        log_config = get_log_config('dgt-pbft-engine-log-config.toml')
        if log_config is None:
            log_config = get_log_config('dgt-pbft-engine-log-config.yaml')

        if log_config is not None:
            log_configuration(log_config=log_config)
        else:
            log_dir = get_log_dir()
            log_configuration(
                log_dir=log_dir,
                name='pbft-engine')

        init_console_logging(verbose_level=opts.verbose)

        driver = ZmqDriver(
            PbftEngine(
                path_config=path_config,
                component_endpoint=opts.component,
                pbft_config=pbft_config,
                signed_consensus=opts.signed_consensus>0))
        LOGGER.debug('Start driver=%s endpoint=%s component=%s',driver,opts.connect,opts.component)
        attemps = 0
        while attemps < MAX_CONNECT_ATTEMPTS:
            try:
                driver.start(endpoint=opts.connect)
                break
            except FutureTimeoutError:
                attemps += 1
                LOGGER.debug('Start driver=%s endpoint=%s AGAIN=%s',driver,opts.connect,attemps)

    except KeyboardInterrupt:
        pass
    except Exception:  # pylint: disable=broad-except
        LOGGER.exception("Error starting PBFT Engine")
    finally:
        pass
