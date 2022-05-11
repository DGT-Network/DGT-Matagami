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

import hashlib
import base64
import time
import random
import requests
import yaml
import cbor

from dgt_signing import create_context
from dgt_signing import CryptoFactory
from dgt_signing import ParseError
from dgt_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch
from smart_bgt.client_cli.exceptions import SmartBgtClientException
from smart_bgt.processor.utils import FAMILY_NAME,FAMILY_VER
from smart_bgt.processor.crypto import BGXCrypto


def _sha512(data):
    return hashlib.sha512(data).hexdigest()


class SmartBgtClient:
    def __init__(self, url, keyfile=None):
        self.url = url

        if keyfile is not None:
            try:
                with open(keyfile) as fd:
                    private_key_str = fd.read().strip()
                    fd.close()
            except OSError as err:
                raise SmartBgtClientException(
                    'Failed to read private key: {}'.format(str(err)))

            try:
                private_key = Secp256k1PrivateKey.from_hex(private_key_str)
            except ParseError as e:
                raise SmartBgtClientException(
                    'Unable to load private key: {}'.format(str(e)))

            self._signer = CryptoFactory(
                create_context('secp256k1')).new_signer(private_key)


    def init(self, full_name, private_key, ethereum_address,num_bgt,bgt_price,dec_price, wait=None):
        args = {
            'Name': full_name,
            'private_key': private_key,
            'ethereum_address': ethereum_address,
            'num_bgt': num_bgt,
            'bgt_price': bgt_price,
            'dec_price':dec_price,
        }
        return self._send_transaction('init', args, wait=wait)


    def transfer(self, from_addr, to_addr, num_bgt, group_id='None', wait=None):
        args = {
            'Name': from_addr,
            'to_addr': to_addr,
            'num_bgt': num_bgt,
            'group_id': group_id,
        }
        return self._send_transaction('transfer', args, wait=wait)


    def allowance(self, from_addr, num_bgt, group_id='None', wait=None):
        args = {
            'Name': from_addr,
            'num_bgt': num_bgt,
            'group_id': group_id,
        }
        return self._send_transaction('allowance', args, wait=wait)


    def balance_of(self, addr, wait=None):
        args = {
            'addr': addr,
        }
        return self._send_transaction('balance_of', args, wait=wait)


    def total_supply(self, token_name, wait=None):
        args = {
            'token_name': token_name,
        }
        return self._send_transaction('total_supply', args, wait=wait)


    def generate_key(self, wait=None):
        return self._send_transaction('generate_key',{}, wait=wait)


    def list(self):
        result = self._send_request(
            "state?address={}".format(
                self._get_prefix()))

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
            return cbor.loads(
                base64.b64decode(
                    yaml.safe_load(result)["data"]))[name]

        except BaseException:
            return None


    def _get_status(self, batch_id, wait):
        try:
            result = self._send_request(
                'batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise SmartBgtClientException(err)


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
                raise SmartBgtClientException("No such key: {}".format(name))

            elif not result.ok:
                raise SmartBgtClientException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise SmartBgtClientException(
                'Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise SmartBgtClientException(err)

        return result.text

    def _send_transaction(self, verb, args, wait=None):
        args['Verb'] = verb
        payload = cbor.dumps(args)
        inputs = []
        outputs= []

        # Construct the address 0281e398fc978e8d36d6b2244c71e140f3ee464cb4c0371a193bb0a5c6574810ba
        if verb != 'generate_key' and verb != 'balance_of' and verb != 'total_supply':
            address = self._get_address(args['Name'])
            inputs = [address]
            outputs= [address]

        if verb == 'init':
            private_key = args['private_key']
            digital_signature = BGXCrypto.DigitalSignature(private_key)
            open_key = digital_signature.getVerifyingKey()
            address2 = self._get_address(open_key)
            inputs.append(address2)
            outputs.append(address2)
        elif verb == 'transfer':
            address1 = self._get_address(args['to_addr'])
            inputs.append(address1)
            outputs.append(address1)
        elif verb == 'balance_of':
            address = self._get_address(args['addr'])
            inputs = [address]
            outputs = [address]
        elif verb == 'total_supply':
            address = self._get_address(args['token_name'])
            inputs = [address]
            outputs = [address]
  
        header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name=FAMILY_NAME,
            family_version=FAMILY_VER,
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
            header_signature=signature)
        return BatchList(batches=[batch])
