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

import binascii
import warnings



from dgt_signing.core import SigningError
from dgt_signing.core import ParseError

from dgt_signing.core import PrivateKey
from dgt_signing.core import PublicKey
from dgt_signing.core import Context
import logging
try:
    import secp256k1
    __CONTEXTBASE__ = secp256k1.Base(ctx=None, flags=secp256k1.ALL_FLAGS)
    __CTX__ = __CONTEXTBASE__.ctx
    __PK__ = secp256k1.PublicKey(ctx=__CTX__)  # Cache object to use as factory
except Exception as ex:
    __CTX__ = None
    __PK__  = None

class Secp256k1PrivateKey(PrivateKey):
    def __init__(self, secp256k1_private_key):
        self._private_key = secp256k1_private_key

    def get_algorithm_name(self):
        return "secp256k1"

    def as_hex(self):
        return binascii.hexlify(self.as_bytes()).decode()

    def as_bytes(self):
        return bytes(self._private_key.private_key)

    @property
    def secp256k1_private_key(self):
        return self._private_key

    @staticmethod
    def from_wif(hex_str):
        raise ParseError(f'Unable to parse hex private key: {hex_str}')

    @staticmethod
    def from_hex(hex_str):
        try:
            priv = binascii.unhexlify(hex_str)
            logging.info(f"Secp256k1PrivateKey.from_hex: hex={hex_str} serialized={priv}")
            return Secp256k1PrivateKey(secp256k1.PrivateKey(priv, ctx=__CTX__))
        except Exception as e:
            raise ParseError(f'Unable to parse hex private key={hex_str}: {e}')

    @staticmethod
    def new_random():
        return Secp256k1PrivateKey(secp256k1.PrivateKey(ctx=__CTX__))


class Secp256k1PublicKey(PublicKey):
    def __init__(self, secp256k1_public_key):
        self._public_key = secp256k1_public_key

    @property
    def secp256k1_public_key(self):
        return self._public_key

    def get_algorithm_name(self):
        return "secp256k1"

    def as_hex(self):
        return binascii.hexlify(self.as_bytes()).decode()

    def as_bytes(self):
        with warnings.catch_warnings():  # squelch secp256k1 warning
            warnings.simplefilter('ignore')
            return self._public_key.serialize()

    @staticmethod
    def from_hex(hex_str):
        try:
            public_key = __PK__.deserialize(binascii.unhexlify(hex_str))

            return Secp256k1PublicKey(
                secp256k1.PublicKey(public_key, ctx=__CTX__))
        except Exception as e:
            raise ParseError('Unable to parse public key: {}'.format(e))


class Secp256k1Context(Context):
    def __init__(self):
        self._ctx = __CTX__

    def get_algorithm_name(self):
        return "secp256k1"

    def sign(self, message, private_key):
        try:
            signature = private_key.secp256k1_private_key.ecdsa_sign(message)
            signature = private_key.secp256k1_private_key.ecdsa_serialize_compact(signature)

            return signature.hex()
        except Exception as e:
            raise SigningError('Unable to sign message: {}'.format(str(e)))

    def verify(self, signature, message, public_key):
        try:
            sig_bytes = bytes.fromhex(signature)

            sig = public_key.secp256k1_public_key.ecdsa_deserialize_compact(sig_bytes)
            return public_key.secp256k1_public_key.ecdsa_verify(message, sig)
        # pylint: disable=broad-except
        except Exception:
            return False

    def new_random_private_key(self):
        return Secp256k1PrivateKey.new_random()

    def new_random(self):           
        return Secp256k1PrivateKey.new_random() 

    def get_public_key(self, private_key):
        return Secp256k1PublicKey(private_key.secp256k1_private_key.pubkey)

    def from_hex(self,hex_str):
        return Secp256k1PrivateKey.from_hex(hex_str)

    def from_wif(self,hex_str):
        return Secp256k1PrivateKey.from_wif(hex_str)

    def pub_from_hex(self,hex_str):
        return Secp256k1PublicKey.from_hex(hex_str)

    def create_x509_certificate(self,subject_info,priv,after=None,before=None):
        return self.sign(b'xxxxxx',priv).encode('utf-8')

    def load_x509_certificate(self,cert_pem):                                            
        xcert = {}
        
        return xcert                                                                     
