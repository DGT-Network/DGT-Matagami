#!/usr/bin/python
#
# Copyright 2016 DGT NETWORK INC © Stanislav Parsov
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

import argparse
import hashlib
import os
import logging
import random
import string
import time
import base64
import cbor
import yaml
from dgt_signing import create_context
from dgt_signing import CryptoFactory

from dgt_sdk.protobuf import transaction_pb2
from dgt_sdk.protobuf import batch_pb2
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo
#from x509_cert.processor.handler import make_xcert_address
from x509_cert.xcert_addr_util import make_xcert_address

LOGGER = logging.getLogger(__name__)

def loads_bgt_token(data,name):
    value = cbor.loads(base64.b64decode(data))[name]
    token = X509CertInfo()
    token.ParseFromString(value)
    LOGGER.debug("BGT:%s %s=%s",name,token.group_code,token.decimals)
    return {'bgt':name,'group':token.group_code,'value':token.decimals,'sign':token.sign}

class BgtPayload:
    def __init__(self, verb, name, value,to = None):
        self._verb = verb
        self._name = name
        self._value = value
        self._to    = to
        self._cbor = None
        self._sha512 = None

    def to_hash(self):

        ret = {
            'Verb': self._verb,
            'Name': self._name,
            'Value': self._value

        }
        if self._to is not None :
            ret['To'] = self._to
        return ret

    def to_cbor(self):
        if self._cbor is None:
            self._cbor = cbor.dumps(self.to_hash(), sort_keys=True)
        return self._cbor

    def sha512(self):
        if self._sha512 is None:
            self._sha512 = hashlib.sha512(self.to_cbor()).hexdigest()
        return self._sha512


def create_xcert_transaction(verb, name, value, signer,to = None):
    payload = BgtPayload(verb=verb, name=name, value=value, to = to)

    # The prefix should eventually be looked up from the
    # validator's namespace registry.
    addr = make_xcert_address(name)
    inputs  = [addr]
    outputs = [addr]
    if to is not None:
        addr_to = make_xcert_address(to)
        inputs.append(addr_to)
        outputs.append(addr_to)
    
    header = transaction_pb2.TransactionHeader(
        signer_public_key=signer.get_public_key().as_hex(),
        family_name='bgt',
        family_version='1.0',
        inputs=inputs,
        outputs=outputs,
        dependencies=[],
        payload_sha512=payload.sha512(),
        batcher_public_key=signer.get_public_key().as_hex(),
        nonce=hex(random.randint(0, 2**64)))

    header_bytes = header.SerializeToString()

    signature = signer.sign(header_bytes)

    transaction = transaction_pb2.Transaction(
        header=header_bytes,
        payload=payload.to_cbor(),
        header_signature=signature)

    return transaction


def create_batch(transactions, signer):
    transaction_signatures = [t.header_signature for t in transactions]

    header = batch_pb2.BatchHeader(
        signer_public_key=signer.get_public_key().as_hex(),
        transaction_ids=transaction_signatures)

    header_bytes = header.SerializeToString()

    signature = signer.sign(header_bytes)

    batch = batch_pb2.Batch(
        header=header_bytes,
        transactions=transactions,
        header_signature=signature,
        timestamp=int(time.time()))

    return batch


def generate_word():
    return ''.join([random.choice(string.ascii_letters) for _ in range(0, 6)])


def generate_word_list(count):
    if os.path.isfile('/usr/share/dict/words'):
        with open('/usr/share/dict/words', 'r') as fd:
            return [x.strip() for x in fd.readlines()[0:count]]
    else:
        return [generate_word() for _ in range(0, count)]


def do_generate(args):
    context = create_context('secp256k1')
    signer = CryptoFactory(context).new_signer(context.new_random_private_key())

    words = generate_word_list(args.pool_size)

    batches = []
    start = time.time()
    total_txn_count = 0
    for i in range(0, args.count):
        txns = []
        for _ in range(0, random.randint(1, args.batch_max_size)):
            txn = create_xcert_transaction(
                verb=random.choice(['inc', 'dec']),
                name=random.choice(words),
                value=1,
                signer=signer)
            total_txn_count += 1
            txns.append(txn)

        batch = create_batch(
            transactions=txns,
            signer=signer)

        batches.append(batch)

        if i % 100 == 0 and i != 0:
            stop = time.time()

            txn_count = 0
            for batch in batches[-100:]:
                txn_count += len(batch.transactions)

            fmt = 'batches {}, batch/sec: {:.2f}, txns: {}, txns/sec: {:.2f}'
            print(fmt.format(
                str(i),
                100 / (stop - start),
                str(total_txn_count),
                txn_count / (stop - start)))
            start = stop

    batch_list = batch_pb2.BatchList(batches=batches)

    print("Writing to {}...".format(args.output))
    with open(args.output, "wb") as fd:
        fd.write(batch_list.SerializeToString())


def add_generate_parser(subparsers, parent_parser):

    epilog = '''
    deprecated:
     use create_batch, which combines
     the populate and generate commands.
    '''

    parser = subparsers.add_parser(
        'generate',
        parents=[parent_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog)

    parser.add_argument(
        '-o', '--output',
        type=str,
        help='location of output file',
        default='batches.bgt')

    parser.add_argument(
        '-c', '--count',
        type=int,
        help='number of batches',
        default=1000)

    parser.add_argument(
        '-B', '--batch-max-size',
        type=int,
        help='max size of the batch',
        default=20)

    parser.add_argument(
        '-P', '--pool-size',
        type=int,
        help='size of the word pool',
        default=100)
