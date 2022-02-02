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

import hashlib
import base64
import time
import random
import requests
import yaml
import cbor
import json

from dgt_signing import create_context
from dgt_signing import CryptoFactory
from dgt_signing import ParseError

from dgt_sdk.protobuf.transaction_pb2 import TransactionHeader
from dgt_sdk.protobuf.transaction_pb2 import Transaction
from dgt_sdk.protobuf.batch_pb2 import BatchList
from dgt_sdk.protobuf.batch_pb2 import BatchHeader
from dgt_sdk.protobuf.batch_pb2 import Batch
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo

from x509_cert.client_cli.exceptions import XcertClientException

FAMILY_NAME ="xcert"
FAMILY_VERSION ="1.0"

def _sha512(data):
    return hashlib.sha512(data).hexdigest()

def _get_prefix():                                             
    return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]                     
                                                                   
def _get_address(name):                                      
    prefix = _get_prefix()                                    
    game_address = _sha512(name.encode('utf-8'))[64:]              
    return prefix + game_address  
                                 
def _token_info(val):
    token = X509CertInfo()
    token.ParseFromString(val)
    return token

class XcertClient:
    def __init__(self, url, keyfile=None,backend=None):
        self.url = url
        self._context = create_context('secp256k1',backend=backend)
        if keyfile is not None:
            self._signer = self.get_signer(keyfile)
            

    def get_signer(self,keyfile):
        try:                                                                                          
            with open(keyfile) as fd:                                                                 
                private_key_str = fd.read().strip()                                                   
                fd.close()                                                                            
        except OSError as err:                                                                        
            raise XcertClientException('Failed to read private key: {}'.format(str(err)))                                    
                                                                                                      
        try:                                                                                          
            private_key = self._context.from_hex(private_key_str)                                           
        except ParseError as e:                                                                       
            raise XcertClientException('Unable to load private key: {}'.format(str(e)))               
                                                                                                      
        return CryptoFactory(self._context).new_signer(private_key)                                 


    def load_xcert(self,xcert_pem):
        xcert = self._signer.context.load_x509_certificate(xcert_pem)
        return xcert

    def set_or_upd(self,value,user,before,after):
        with open(value,"r") as cert_file:                                               
            try:                                                                         
                info =  json.load(cert_file)                                             
                                                                                         
            except Exception as ex:                                                      
                info = {}                                                                
        signer = self.get_signer(user)                                                   
        cert = signer.context.create_x509_certificate(info,signer.private_key,after=after,before=before)        
        pubkey = signer.get_public_key().as_hex()                                        
        return pubkey,cert


    def set(self,value,user,before,after,wait=None):

        pubkey,cert = self.set_or_upd(value,user,before,after)
        print(f'SET cert={cert} pub={pubkey} valid={before}/{after}')
        return self._send_transaction('set',pubkey, cert, to=None, wait=wait,user=user)

    def upd(self,value,user,before,after, wait=None):
        pubkey,cert = self.set_or_upd(value,user,before,after)      
        print(f'UPD cert={cert} pub={pubkey} valid={before}/{after}') 
        return self._send_transaction('upd',pubkey, cert, to=None, wait=wait,user=user)
        

    def list(self):
        result = self._send_request("state?address={}".format(self._get_prefix()))

        try:
            encoded_entries = yaml.safe_load(result)["data"]

            return [
                cbor.loads(base64.b64decode(entry["data"]))
                for entry in encoded_entries
            ]

        except BaseException:
            return None

    def show(self, name):
        address = self._get_address(name)

        result = self._send_request("state/{}".format(address), name=name,)

        try:
            return cbor.loads(base64.b64decode(yaml.safe_load(result)["data"]))[name]

        except BaseException:
            return None

    def _get_status(self, batch_id, wait):
        try:
            result = self._send_request('batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise XcertClientException(err)

    def _get_prefix(self):
        return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]

    def _get_address(self, name):
        prefix = self._get_prefix()
        game_address = _sha512(name.encode('utf-8'))[64:]
        return prefix + game_address

    def _send_request(self, suffix, data=None, content_type=None, name=None):
        if self.url.startswith("http://"):
            url = "{}/{}".format(self.url, suffix)
        else:
            url = "http://{}/{}".format(self.url, suffix)

        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if result.status_code == 404:
                raise XcertClientException("No such key: {}".format(name))

            elif not result.ok:
                raise XcertClientException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise XcertClientException(
                'Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise XcertClientException(err)

        return result.text

    def _send_transaction(self, verb, name, value, to=None, wait=None,user='anybody'):
        val = {
            'Verb': verb,
            'Owner': name,
            'Value': value,
        }
        if to is not None:
            val['To'] = to

        payload = cbor.dumps(val)

        # Construct the address
        address = self._get_address(name)
        inputs = [address]
        outputs = [address]
        if to is not None:
            address_to = self._get_address(to)
            inputs.append(address_to)
            outputs.append(address_to)

        header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name=FAMILY_NAME,
            family_version=FAMILY_VERSION,
            inputs=inputs,
            outputs=outputs,
            dependencies=[],
            payload_sha512=_sha512(payload),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            nonce=hex(random.randint(0, 2**64))
        ).SerializeToString()

        signature = self._signer.sign(header)

        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=signature
        )

        batch_list = self._create_batch_list([transaction])
        batch_id = batch_list.batches[0].header_signature

        if wait and wait > 0:
            wait_time = 0
            start_time = time.time()
            response = self._send_request(
                "batches", batch_list.SerializeToString(),
                'application/octet-stream',
            )
            while wait_time < wait:
                status = self._get_status(
                    batch_id,
                    wait - int(wait_time),
                )
                wait_time = time.time() - start_time

                if status != 'PENDING':
                    return response

            return response

        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
        )

    def _create_batch_list(self, transactions):
        transaction_signatures = [t.header_signature for t in transactions]

        header = BatchHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            transaction_ids=transaction_signatures
        ).SerializeToString()

        signature = self._signer.sign(header)

        batch = Batch(
            header=header,
            transactions=transactions,
            header_signature=signature,
            timestamp=int(time.time()))
        return BatchList(batches=[batch])
