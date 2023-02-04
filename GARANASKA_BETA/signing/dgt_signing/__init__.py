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

from sha3 import keccak_256
import hashlib

DGT_CRYPTO_NM = 'dgt.crypto'
DGT_CRYPTO_ALG_NM = 'dgt.crypto.alg'
DGT_ADDR_PREF = "0x"
def key_to_dgt_addr(hex_str,pref=DGT_ADDR_PREF,lng=20):                                        
    a =  keccak_256(hex_str.encode()).digest()[-lng:].hex()                              
    h = hashlib.sha256()                                                                 
    h.update(a.encode())                                                                 
    h.update(h.digest())                                                                 
    crc = h.hexdigest()                                                                  
    addr = "{}{}{}".format(pref,a,crc[0:4])                                              
    return addr                                                                          
                                                                                         
def check_dgt_addr(addr,pref="0x"):                                                      
    a = addr[2:42]                                                                       
    h = hashlib.sha256()                                                                 
    h.update(a.encode())                                                                 
    h.update(h.digest())                                                                 
    crc = h.hexdigest() #_sha256(_sha256(a.encode()).encode()) #h.hexdigest()            
    crc0 = addr[-4:]                                                                     
    #print('a',a,'cr',addr[-4:],crc[0:4] == crc0,addr[0:2])                                         
    return crc[0:4] == crc0  and pref == addr[0:2]                                          

def checksum_encode(addr): # Takes a 20-byte binary address as input
    hex_addr = addr[2:].hex()
    print('addr',addr[2:],hex_addr)
    hashed_address = keccak_256(addr[2:]).digest().hex() #addr.hex()
    print('hashed_address->',hashed_address)
    checksummed_buffer = ""

    # Treat the hex address as ascii/utf-8 for keccak256 hashing
    #hashed_address = keccak_256(text=hex_addr).hex()

    # Iterate over each character in the hex address
    for nibble_index, character in enumerate(hex_addr):

        if character in "0123456789":
            # We can't upper-case the decimal digits
            checksummed_buffer += character
        elif character in "abcdef":
            # Check if the corresponding hex digit (nibble) in the hash is 8 or higher
            try:
                hashed_address_nibble = int(hashed_address[nibble_index], 16)
            except IndexError:
                break
            if hashed_address_nibble > 7:
                checksummed_buffer += character.upper()
            else:
                checksummed_buffer += character
        #else:
        #    raise eth_utils.ValidationError(
        #        f"Unrecognized hex character {character!r} at position {nibble_index}"
        #    )

    return "0x" + checksummed_buffer
def test_eth(addr):
    addr_bytes = addr.encode() #eth_utils.to_bytes(hexstr=addr_str)
    checksum_encoded = checksum_encode(addr_bytes)
    print( checksum_encoded == addr, f"{checksum_encoded} != expected {addr}")

def test_eth_list():
    test_eth("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
    test_eth("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")
    test_eth("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB")
    test_eth("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb")














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
    #print(f">>CREATE_CONTEXT:: backend={backend}")
    if CRYPTO_BACK != '' and CRYPTO_BACK is not None:
        backend = CRYPTO_BACK
    #if backend is None:

    #print(f"CREATE_CONTEXT:: backend={backend}")
    if backend == 'bitcoin':
        # old version
        if algorithm_name == 'secp256k1':
            return Secp256k1Context()
    elif backend == 'openssl':
        # openssl version
        return OpenCryptoContext(algorithm=algorithm_name)

    raise NoSuchAlgorithmError(f"no such algorithm: {algorithm_name} for backend={backend}")
