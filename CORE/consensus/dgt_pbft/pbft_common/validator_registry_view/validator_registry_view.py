# Copyright 2018 DGT NETWORK INC © Stanislav Parsov
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
import hashlib
#from sawtooth_validator.protobuf.bgx_validator_registry_pb2 import BgxValidatorInfo
from pbft_common.protobuf.bgx_validator_registry_pb2 import BgxValidatorInfo
import logging

LOGGER = logging.getLogger(__name__)

_NAMESPACE = hashlib.sha256('validator_registry'.encode()).hexdigest()[0:6]


class ValidatorRegistryView:
    """
    A ValidatorRegistryView provides access to the on-chain validator info.

    The ValidatorRegistryView provides access to the validator registry's
    information about validators stored within a particular state view. This
    access is read-only.
    """

    def __init__(self, state_view):
        """
        Constructs a view, on top of the given read-only state view.

        Args:
            state_view (:obj:`StateView`): The read-only state view for the
                current snapshot of chain state.
        """
        self._state_view = state_view

    def get_validators(self):
        """Gets a dict of validator infos for all validators known to the
        registry. The dict is a mapping of validator id to BgxValidatorInfo.

        Returns:
            dict:(str, `BgxValidatorInfo`): A dict of validator id to
                `BgxValidatorInfo` objects.
        """
        validator_map_addr = ValidatorRegistryView._to_address('validator_map')
        leaves = self._state_view.leaves(_NAMESPACE)
        infos = [
            ValidatorRegistryView._parse_validator_info(state_data)
            for address, state_data in leaves
            if address != validator_map_addr
        ]
        #LOGGER.debug("get_validators(%s)",infos)
        return {info.id: info for info in infos}

    def has_validator_info(self, validator_id):
        """Checks to see if it has the validator info for a given validator ID.

        Args:
            validator_id (str): The ID of the validator in question.

        Returns:
            bool: True if the registry has info on the given ID, False if
                otherwise.
        """
        try:
            self._state_view.get(
                ValidatorRegistryView._to_address(validator_id))
            return True
        except KeyError:
            return False

    def get_validator_info(self, validator_id):
        """Get the validator info for a given validator ID.

        Args:
            validator_id (str): The ID of the validator in question.

        Returns:
            :obj:`BgxValidatorInfo`: The validator info.

        Raises:
            KeyError: If no validator info exists for the given ID.
        """
        state_data = self._state_view.get(
            ValidatorRegistryView._to_address(validator_id))

        return ValidatorRegistryView._parse_validator_info(state_data)

    @staticmethod
    def _to_address(addressable_key):
        return _NAMESPACE + hashlib.sha256(
            addressable_key.encode()).hexdigest()

    @staticmethod
    def _parse_validator_info(state_data):
        validator_info = BgxValidatorInfo()
        validator_info.ParseFromString(state_data)
        LOGGER.debug("BgxValidatorInfo(%s)",validator_info)

        return validator_info
