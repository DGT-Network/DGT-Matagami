# Copyright 2017 DGT NETWORK INC © Stanislav Parsov 
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
import importlib
import logging
from dgt_validator.exceptions import UnknownConsensusModuleError
from dgt_validator.journal.block_wrapper import NULL_BLOCK_IDENTIFIER
from dgt_validator.state.settings_view import SettingsView
LOGGER = logging.getLogger(__name__)
PROXY = '_proxy_'
class ConsensusFactory(object):
    """ConsensusFactory returns consensus modules by short name.
    """

    @staticmethod
    def get_consensus_module(module_name):
        """Returns a consensus module by name.

        Args:
            module_name (str): The name of the module to load.

        Returns:
            module: The consensus module.

        Raises:
            UnknownConsensusModuleError: Raised if the given module_name does
                not correspond to a consensus implementation.
        """
        module_package = module_name
        if module_name == 'genesis':
            module_package = (
                'dgt_validator.journal.consensus.genesis.'
                'genesis_consensus'
            )
        elif module_name == 'devmode':
            module_package = (
                'dgt_validator.journal.consensus.dev_mode.'
                'dev_mode_consensus'
            )
        elif module_name == PROXY:
            module_package = (
                'dgt_validator.journal.consensus.proxy.'
                'proxy_consensus'
            )
        elif module_name == 'poet':
            module_package = 'sawtooth_poet.poet_consensus'
        elif module_name == 'pbft':
            module_package = 'pbft.bgx_pbft.consensus'

        try:
            return importlib.import_module(module_package)
        except ImportError:
            raise UnknownConsensusModuleError(
                'Consensus module "{}" does not exist.'.format(module_name))

    @staticmethod
    def try_configured_proxy_consensus():
        """Returns the proxy onsensus_module based on the consensus module set by the
        "sawtooth_settings" transaction family.

        Args:
            block_id (str): the block id associated with the current state_view
            state_view (:obj:`StateView`): the current state view to use for
                setting values
        Raises:
            UnknownConsensusModuleError: Thrown when an invalid consensus
                module has been configured.
        """
        LOGGER.debug("ConsensusFactory::try_configured_proxy_consensus")
        try:
            mod = ConsensusFactory.get_consensus_module(PROXY)
            
        except UnknownConsensusModuleError:
            mod = None
        return mod

    @staticmethod
    def try_configured_consensus_module(block_id, state_view):
        """Returns the consensus_module based on the consensus module set by the
        "sawtooth_settings" transaction family.

        Args:
            block_id (str): the block id associated with the current state_view
            state_view (:obj:`StateView`): the current state view to use for
                setting values
        Raises:
            UnknownConsensusModuleError: Thrown when an invalid consensus
                module has been configured.
        """
        settings_view = SettingsView(state_view)

        default_consensus = 'genesis' if block_id == NULL_BLOCK_IDENTIFIER else 'devmode'  
        consensus_module_name = settings_view.get_setting('dgt.consensus.algorithm', default_value=default_consensus)
        consensus_version = settings_view.get_setting('dgt.consensus.version', default_value='0.1')
        LOGGER.debug("ConsensusFactory::try_configured_consensus_module consensus_module_name=%s ver=%s",consensus_module_name,consensus_version)
        try:
            mod = ConsensusFactory.get_consensus_module(consensus_module_name)
        except UnknownConsensusModuleError:
            mod = None
        return mod,(consensus_module_name,consensus_version)

    @staticmethod
    def get_configured_consensus_module(block_id, state_view):
        """Returns the consensus_module based on the consensus module set by the
        "sawtooth_settings" transaction family.

        Args:
            block_id (str): the block id associated with the current state_view
            state_view (:obj:`StateView`): the current state view to use for
                setting values
        Raises:
            UnknownConsensusModuleError: Thrown when an invalid consensus
                module has been configured.
        """
        settings_view = SettingsView(state_view)

        default_consensus = 'genesis' if block_id == NULL_BLOCK_IDENTIFIER else 'devmode'  
        consensus_module_name = settings_view.get_setting('dgt.consensus.algorithm', default_value=default_consensus)
        LOGGER.debug("ConsensusFactory::get_configured_consensus_module consensus_module_name=%s",consensus_module_name)
        return ConsensusFactory.get_consensus_module(consensus_module_name)
