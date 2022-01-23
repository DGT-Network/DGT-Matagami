# Copyright  2018 DGT NETWORK INC © Stanislav Parsov
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
import datetime

from dgt_signing.core import SigningError
from dgt_signing.core import ParseError

from dgt_signing.core import PrivateKey
from dgt_signing.core import PublicKey
from dgt_signing.core import Context
from dgt_signing.core import X509_COUNTRY_NAME,X509_STATE_OR_PROVINCE_NAME,X509_LOCALITY_NAME,X509_ORGANIZATION_NAME,X509_COMMON_NAME,X509_DNS_NAME, X509_EMAIL_ADDRESS,X509_PSEUDONYM            

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key,load_der_private_key

import logging

# x509
#from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from cryptography.x509.oid import NameOID
# ecdsa-sha2-SECP256K1

x509_attr_map = { X509_COUNTRY_NAME           : NameOID.COUNTRY_NAME,
                  X509_STATE_OR_PROVINCE_NAME : NameOID.STATE_OR_PROVINCE_NAME,
                  X509_LOCALITY_NAME          : NameOID.LOCALITY_NAME,
                  X509_ORGANIZATION_NAME      : NameOID.ORGANIZATION_NAME,
                  X509_COMMON_NAME            : NameOID.COMMON_NAME,
                  X509_EMAIL_ADDRESS          : NameOID.EMAIL_ADDRESS,
                  X509_PSEUDONYM              : NameOID.PSEUDONYM    

                  }




def test_asymmetric(data):                                                           
                                                                                     
    ecr = ec.SECP384R1()                                                             
    eck = ec.SECP256K1()                                                             
    private_key = ec.generate_private_key(eck,backend= default_backend())            
    public_key = private_key.public_key()                                            
    signature = private_key.sign(data,ec.ECDSA(hashes.SHA256()))                     
    ret = public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))              
    print('sign',signature,'ret',ret)                                                
                                                                                     

class OpenCryptoPrivateKey(PrivateKey):
    def __init__(self,ctx, open_private_key=None):
        self._private_key = open_private_key
        self._ctx  = ctx
        self._serialized_private = open_private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
        logging.info(f"OpenCryptoPrivateKey: priv={self._serialized_private} hex={self.as_hex()}")
    def get_algorithm_name(self):
        return self._ctx.algorithm

    def as_hex(self):
        return binascii.hexlify(self.as_bytes()).decode()

    def as_bytes(self):
        return self._serialized_private

    @property
    def private_key(self):
        return self._private_key




class OpenCryptoPublicKey(PublicKey):
    def __init__(self,ctx, open_public_key=None):
        self._public_key = open_public_key
        self._ctx  = ctx
        self._serialized_public = open_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logging.info(f"OpenCryptoPublicKey: pub={self._serialized_public} hex={self.as_hex()}")
    @property
    def public_key(self):
        return self._public_key

    def get_algorithm_name(self):
        return self._ctx.algorithm

    def as_hex(self):
        return binascii.hexlify(self.as_bytes()).decode()

    def as_bytes(self):
        with warnings.catch_warnings():  # squelch secp256k1 warning
            warnings.simplefilter('ignore')
            return self._serialized_public #serialize()



class OpenCryptoContext(Context):
    def __init__(self,algorithm=None,backend=None):
        self._backend = backend if backend is not None else default_backend()
        self._algorithm = algorithm
        if algorithm == "secp256k1":
            self._ctx  = ec.SECP256K1()  
        elif algorithm == "SECP384R1":
            self._ctx  = ec.SECP384R1() 
        else:
            self._algorithm = "secp256k1"
            self._ctx  = ec.SECP256K1()
        logging.info(f"OpenCryptoContext: CRYPTO_BACK={backend} algorithm={self._algorithm}")

    @property
    def algorithm(self):
        self._algorithm

    def get_algorithm_name(self):
        return self._algorithm

    def new_private_key(self):
        return ec.generate_private_key(self._ctx,backend= self._backend)

    def sign(self, message, priv):
        try:
            #signature = private_key.secp256k1_private_key.ecdsa_sign(message)
            #signature = private_key.secp256k1_private_key.ecdsa_serialize_compact(signature)
            signature = priv.private_key.sign(message,ec.ECDSA(hashes.SHA256()))
            return signature.hex()
        except Exception as e:
            raise SigningError(f'Unable to sign message: {e}')

    def verify(self, signature, message, public):
        try:
            sig_bytes = bytes.fromhex(signature)
            public.public_key.verify(sig_bytes, message, ec.ECDSA(hashes.SHA256()))
            return True
            #sig = public_key.secp256k1_public_key.ecdsa_deserialize_compact(sig_bytes)
            #return public_key.secp256k1_public_key.ecdsa_verify(message, sig)
        except Exception:
            return False

    def pub_from_hex(self,hex_str):
        try:                                                                 
            
            serialized_public = binascii.unhexlify(hex_str)   
            public_key = load_der_public_key(serialized_public,backend= self._backend)                                                                 
            return OpenCryptoPublicKey(self,public_key)                                     
        except Exception as e:                                               
            raise ParseError('Unable to parse public key: {}'.format(e))  
           
    def from_hex(self,hex_str):
        try:                                                                    
            serialized_private = binascii.unhexlify(hex_str) 
            logging.info(f"OpenCryptoContext.from_hex: hex={hex_str} serialized={serialized_private}")
            priv_key = load_der_private_key(serialized_private,None,backend= self._backend)                                 
            return OpenCryptoPrivateKey(self,priv_key)                                       
        except Exception as e:                                                  
            raise ParseError(f'Unable to parse hex={hex_str} private key: {e}')  
         
    def from_wif(self,hex_str):
        raise ParseError(f'Unable to parse hex={hex_str} private key')

    def new_random_private_key(self):
        return OpenCryptoPrivateKey(self,self.new_private_key())

    def new_random(self):              
        return OpenCryptoPrivateKey(self,self.new_private_key())   

    def get_public_key(self, priv):
        return OpenCryptoPublicKey(self,priv.private_key.public_key())

    def create_x509_certificate(self,subject_info,priv,after=None,before=None):
        attribures = []
        key = priv.private_key
        for attr,val in subject_info.items():
            if attr in x509_attr_map:
                rattr = x509_attr_map[attr]
                attribures.append(x509.NameAttribute(rattr,val))

        subject = issuer = x509.Name(attribures)  
        tmnow = datetime.datetime.utcnow()
        valid_before = tmnow if before is None else tmnow + datetime.timedelta(days=before)
        
        cert = x509.CertificateBuilder().subject_name(
                subject
                ).issuer_name(
                    issuer
                ).public_key(
                   key.public_key()
                ).serial_number(
                  x509.random_serial_number()
                ).not_valid_before(
                   valid_before
                )

        if after is not None:
            cert = cert.not_valid_after(
                   # Our certificate will be valid for 10 days
                     valid_before + datetime.timedelta(days=after)
                  )

        if X509_DNS_NAME in subject_info:
            cert = cert.add_extension(
                        x509.SubjectAlternativeName([x509.DNSName(subject_info[X509_DNS_NAME])]),
                        critical=False,
                        )

        # Sign our certificate with our private key
        cert = cert.sign(key, hashes.SHA256(), backend= self._backend)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        logging.info(f"create_x509_certificate: CERT={cert_pem}")
        print(f"create_x509_certificate: CERT={cert_pem}")
        public_key = cert.public_key()                                            
        if isinstance(public_key, ec.EllipticCurvePublicKey):                   
            # Do something EC specific                                            
            logging.info(f"create_x509_certificate: KEY=EllipticCurvePublicKey") 
            print("create_x509_certificate: KEY=EllipticCurvePublicKey") 
        
        return cert_pem 
    
    def load_x509_certificate(self,cert_pem):
        xcert = x509.load_pem_x509_certificate(cert_pem,backend= self._backend)
        #print(f"load_x509_certificate: SERIAL={xcert.serial_number} cert={xcert}")
        return xcert

