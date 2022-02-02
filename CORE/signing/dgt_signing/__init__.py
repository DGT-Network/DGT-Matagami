# Copyright 2016, 2017 DGT NETWORK INC © Stanislav Parsov
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
from dgt_signing.core import NoSuchAlgorithmError
from dgt_signing.core import ParseError
from dgt_signing.core import SigningError

from dgt_signing.secp256k1 import Secp256k1Context
from dgt_signing.open_crypto import OpenCryptoContext

DGT_CRYPTO_NM = 'dgt.crypto'
DGT_CRYPTO_ALG_NM = 'dgt.crypto.alg'









CRYPTO_BACK = os.environ.get('CRYPTO_BACK')
class Signer:
    """A convenient wrapper of Context and PrivateKey
    """

    def __init__(self, context, private_key):
        """
        """
        self._context = context
        self._private_key = private_key
        self._public_key = None

    def sign(self, message):
        """Signs the given message

        Args:
            message (bytes): the message bytes

        Returns:
            The signature in a hex-encoded string

        Raises:
            SigningError: if any error occurs during the signing process
        """
        return self._context.sign(message, self._private_key)

    @property
    def private_key(self):
        return self._private_key

    @property
    def context(self):
        return self._context

    def verify(self, signature, message, public):
        return self._context.verify(signature,message,public)

    def get_public_key(self):
        """Return the public key for this Signer instance.
        """
        # Lazy-eval the public key
        if self._public_key is None:
            self._public_key = self._context.get_public_key(self._private_key)
        return self._public_key


class CryptoFactory:
    """Factory for generating Signers.
    """

    def __init__(self, context):
        self._context = context

    @property
    def context(self):
        """Return the context that backs this factory instance
        """
        return self._context

    def new_signer(self, private_key):
        """Create a new signer for the given private key.

        Args:
            private_key (:obj:`PrivateKey`): a private key

        Returns:
            (:obj:`Signer`): a signer instance
        """
        return Signer(self._context, private_key)


def create_context(algorithm_name,backend='bitcoin'):
    """Returns an algorithm instance by name.

    Args:
        algorithm_name (str): the algorithm name

    Returns:
        (:obj:`Context`): a context instance for the given algorithm

    Raises:
        NoSuchAlgorithmError if the algorithm is unknown
    """
    if CRYPTO_BACK != '':
        backend = CRYPTO_BACK
    if backend == 'bitcoin':
        # old version
        if algorithm_name == 'secp256k1':
            return Secp256k1Context()
    elif backend == 'openssl':
        # openssl version
        return OpenCryptoContext(algorithm=algorithm_name)

    raise NoSuchAlgorithmError(f"no such algorithm: {algorithm_name} for backend={backend}")
