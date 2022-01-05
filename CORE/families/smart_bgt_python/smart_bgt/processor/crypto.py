from dgt_signing.secp256k1 import Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Context
import binascii
import hashlib

# Namespace for cryptofunction

class BGXCrypto:

    def strHash(str):
        return hashlib.sha256(str.encode('utf-8')).hexdigest()

    def intHash(str):
        return int(BGXCrypto.strHash(str), 16)

    """
    class DigitalSignature:

        def __init__(self, str_signing_key=None):
            if str_signing_key is None:
                self._signing_key = SigningKey.generate(curve=SECP256k1)
                self._verifying_key = self._signing_key.get_verifying_key()
            else:
                hexed_string = str_signing_key.encode()
                signing_key = binascii.a2b_hex(hexed_string)
                self._signing_key = SigningKey.from_string(signing_key, curve=SECP256k1)
                self._verifying_key = self._signing_key.get_verifying_key()

        def sign(self, message):
            if self._signing_key is None:
                # raise something
                return False
            return self._signing_key.sign(str(message).encode('utf-8'))

        def verify(self, sign, message):
            return self._verifying_key.verify(sign, str(message).encode('utf-8'))

        def getVerifyingKey(self):
            verifying_key = self._verifying_key.to_string()
            hexed_string = binascii.b2a_hex(verifying_key)
            return str(hexed_string.decode())

        def getSigningKey(self):
            signing_key = self._signing_key.to_string()
            hexed_string = binascii.b2a_hex(signing_key)
            return str(hexed_string.decode())
    """

    class DigitalSignature:

        def __init__(self, str_signing_key=None):
            if str_signing_key is None:
                self._context = Secp256k1Context()
                self._signing_key = self._context.new_random_private_key()
                self._verifying_key = self._context.get_public_key(self._signing_key)
            else:
                self._context = Secp256k1Context()
                hexed_string = str_signing_key.encode()
                self._signing_key = Secp256k1PrivateKey.from_hex(hexed_string)
                self._verifying_key = self._context.get_public_key(self._signing_key)

        def sign(self, message):
            return self._context.sign(str(message).encode('utf-8'), self._signing_key)

        def verify(self, sign, message):
            return self._context.verify(sign, str(message).encode('utf-8'), self._verifying_key)

        def getVerifyingKey(self):
            return str(self._verifying_key.as_hex())

        def getSigningKey(self):
            return str(self._signing_key.as_hex())
