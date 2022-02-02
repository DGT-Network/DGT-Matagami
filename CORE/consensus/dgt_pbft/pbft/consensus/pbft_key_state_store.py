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

import threading
import logging
import os
import base64
import binascii

from collections import namedtuple
# pylint: disable=no-name-in-module
from collections.abc import MutableMapping

from pbft.database.lmdb_nolock_database import LMDBNoLockDatabase

LOGGER = logging.getLogger(__name__)

PbftKeyState = namedtuple(
        'PbftKeyState',
        ['sealed_signup_data', 'has_been_refreshed', 'signup_nonce'])
""" Instead of creating a full-fledged class, let's use a named tuple for
the PBFT key state.  The PBFT key state represents the state for a
validator's key that is stored in the PBFT key state store.  A PBFT key state
object contains:

sealed_signup_data (str): The sealed signup data associated with the
    PBFT key.  This must be a byte string containing the base-64 encoded
    sealed signup data.
has_been_refreshed (bool): If this PBFT has been used to create the key
    block claim limit number of blocks and a new key pair has been created
    to replace it.
signup_nonce (str): Block ID used at signup time. Used as a time indicator
    to check if this registration attempt has been timed out.
"""


class PbftKeyStateStore(MutableMapping):
    """Manages access to the underlying database holding state associated with
    a PBFT public key.  PbftKeyStateStore provides a dict-like interface to
    the PBFT key state, mapping a PBFT public key to its corresponding state.
    """

    _store_dbs = {}
    _lock = threading.Lock()

    @property
    def pbft_public_keys(self):
        """Returns the PBFT public keys in the store

        Returns:
            list: The PBFT public keys in the store
        """
        return self._store_db.keys()

    @property
    def active_key(self):
        return self._store_db.get('active_key')

    @active_key.setter
    def active_key(self, value):
        # If the value is not None, then we are not going to allow an active
        # key that is not in the key state store.  Setting to None is allowed
        # as that is basically clearing out the active key.
        if value is not None and value not in self._store_db:
            raise \
                ValueError(
                    'Cannot make non-existent key [{}...{}] active'.format(
                        value[:8],
                        value[-8:]))
        self._store_db['active_key'] = value

    def __init__(self, data_dir, validator_id):
        """Initialize the store

        Args:
            data_dir (str): The directory where underlying database file will
                be stored
            validator_id (str): A unique ID for the validator for which the
                store is being created

        Returns:
            None
        """
        with PbftKeyStateStore._lock:
            # Create an underlying LMDB database file for the validator if
            # there already isn't one.  We will create the LMDB with the 'c'
            # flag so that it will open if already exists.
            self._store_db = PbftKeyStateStore._store_dbs.get(validator_id)
            if self._store_db is None:
                db_file_name = \
                    os.path.join(
                        data_dir,
                        'pbft-key-state-{}.lmdb'.format(
                            validator_id[:8]))

                LOGGER.debug('Create PBFT key state store: %s', db_file_name)

                self._store_db = \
                    LMDBNoLockDatabase(
                        filename=db_file_name,
                        flag='c')
                PbftKeyStateStore._store_dbs[validator_id] = self._store_db

    @staticmethod
    def _check_pbft_key_state(pbft_key_state):
        try:
            if not isinstance(pbft_key_state.sealed_signup_data, str):
                raise ValueError('sealed_signup_data must be a string')
            elif not pbft_key_state.sealed_signup_data:
                raise ValueError('sealed_signup_data must not be empty')

            # Although this won't catch everything, verify that the sealed
            # signup data at least decodes successfully
            base64.b64decode(pbft_key_state.sealed_signup_data.encode())

            if not isinstance(pbft_key_state.has_been_refreshed, bool):
                raise ValueError('has_been_refreshed must be a bool')
            if not isinstance(pbft_key_state.signup_nonce, str):
                raise ValueError('signup_nonce {} must be a string'.format(
                    pbft_key_state.signup_nonce))
        except (AttributeError, binascii.Error) as error:
            raise ValueError('pbft_key_state is invalid: {}'.format(error))

    def __setitem__(self, pbft_public_key, pbft_key_state):
        """Adds/updates an item in the store

        Args:
            pbft_public_key (str): The PBFT public key for which key state
                will be stored
            pbft_key_state (PbftKeyState): The key state

        Returns:
            None

        Raises:
            ValueError if key state object is not a valid
        """
        PbftKeyStateStore._check_pbft_key_state(pbft_key_state)
        self._store_db[pbft_public_key] = pbft_key_state

    def __getitem__(self, pbft_public_key):
        """Return the key state corresponding to the PBFT public key

        Args:
            pbft_public_key (str): The PBFT public key for which key state
                will be retrieved

        Returns:
            PBFT key state (PbftKeyState)

        Raises:
            KeyError if the PBFT public key is not in the store
            ValueError if the key state object is not valid
        """
        # Get the PBFT key state from the underlying LMDB.  The only catch is
        # that the data was stored using cbor.dumps().  When this happens, it
        # gets stored as a list not a namedtuple.  When re-creating the bgt
        # key state we are going to leverage the namedtuple's _make method.
        try:
            pbft_key_state = \
                PbftKeyState._make(self._store_db[pbft_public_key])
        except TypeError:  # handle keys persisted using sawtooth v1.0.1
            try:
                old_key_state = self._store_db[pbft_public_key]
                old_key_state.append('UNKNOWN_NONCE')
                pbft_key_state = PbftKeyState._make(old_key_state)
            except (AttributeError, TypeError) as error:
                raise ValueError('pbft_key_state is invalid: {}'.format(error))
        except (AttributeError, ValueError) as error:
            raise ValueError('pbft_key_state is invalid: {}'.format(error))

        PbftKeyStateStore._check_pbft_key_state(pbft_key_state)
        return pbft_key_state

    def __delitem__(self, pbft_public_key):
        """Remove key state for PBFT public key

        Args:
            pbft_public_key (str): The PBFT public key for which key state
                will be removed

        Returns:
            None
        """
        try:
            del self._store_db[pbft_public_key]

            # If the key is the active key, then also clear the active key
            if self.active_key == pbft_public_key:
                self.active_key = None
        except KeyError:
            pass

    def __contains__(self, pbft_public_key):
        """Determines if key state exists for PBFT public key

        Args:
            pbft_public_key (str): The PBFT public key for which key state
                will be checked

        Returns:
            True if there is key state for PBFT public key, False otherwise
        """
        return pbft_public_key in self._store_db

    def __iter__(self):
        """Allows for iteration, for example 'for ppk in store:', over PBFT
        public keys in store

        Returns:
            iterator
        """
        return iter(self.bgt_public_keys)

    def __len__(self):
        """Returns number of PBFT public keys in store

        Returns:
            Number of PBFT public keys in store
        """
        return len(self._store_db)

    def __str__(self):
        out = []
        for pbft_public_key in self:
            pbft_key_state = self[pbft_public_key]
            out.append(
                '{}...{}: {{SSD: {}...{}, Refreshed: {} nonce:{}}}'.format(
                    pbft_public_key[:8],
                    pbft_public_key[-8:],
                    pbft_key_state.sealed_signup_data[:8],
                    pbft_key_state.sealed_signup_data[-8:],
                    pbft_key_state.has_been_refreshed,
                    pbft_key_state.signup_nonce))

        return ', '.join(out)
