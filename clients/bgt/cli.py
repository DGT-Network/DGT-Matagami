import socket
import sys
import os
import os.path

from dgt_signing import create_context
from dgt_signing import CryptoFactory
from dgt_sdk.protobuf.transaction_pb2 import TransactionHeader
from dgt_sdk.protobuf.transaction_pb2 import Transaction
from dgt_sdk.protobuf.transaction_pb2 import TransactionList
from dgt_sdk.protobuf.batch_pb2 import BatchList
from dgt_sdk.protobuf.batch_pb2 import BatchHeader
from dgt_sdk.protobuf.batch_pb2 import Batch

import json
import cbor
from hashlib import sha512
import random
import time
import requests



def send_request(url, suffix, data = None , content_type = None, name = None):
    headers={}
    try:
        headers['Content-Type'] = content_type
        result = requests.post(url, headers= headers , data=data)
    except Exception as e:
        print("Something went wrong: "+ str(e)) 
    return result.text

def _sha512(data):
    return sha512(data).hexdigest()

def get_prefix():
    return _sha512('bgt'.encode('utf-8'))[0:6]

def get_address(name):
    prefix = get_prefix()
    game_address=_sha512(name.encode('utf-8'))[64:]
    return prefix + game_address


def connect(host:str,port:int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        res = s.connect_ex((host,port))
        return res

def send(IP,verb,wal,to,value,PK) -> str:
    value=int(value)
    URL = f"http://{IP}/batches"

    context=create_context('secp256k1',backend='openssl')
    PK = context.from_hex(PK)
    signer = CryptoFactory(context).new_signer(PK)


    payload = {'Name' : wal , 'Value' : value , 'Verb' : verb }

    address= get_address(wal)
    inputs = [address]
    outputs = [address]

    if to is not None:      
        payload["To"] = to
        inputs.append(get_address(to))
        outputs.append(get_address(to))

    payload_bytes = cbor.dumps(payload)
    transaction_header_bytes=TransactionHeader(
            batcher_public_key = signer.get_public_key().as_hex(),
            dependencies=[],
            family_name = "bgt" ,
            family_version = "1.0" ,
            inputs = inputs,
            outputs = outputs,
            nonce = hex(random.randint(0,2**64)),
            payload_sha512=_sha512(payload_bytes),
            signer_public_key=signer.get_public_key().as_hex()
            ).SerializeToString()

    signature = signer.sign(transaction_header_bytes)
    txn = Transaction(
            header = transaction_header_bytes,
            payload=payload_bytes,
            header_signature = signature
            )
    txns = [txn]
    batch_header_bytes = BatchHeader(
            signer_public_key=signer.get_public_key().as_hex(),
            transaction_ids = [txn.header_signature for txn in txns]
            ).SerializeToString()

    batch_signature = signer.sign(batch_header_bytes)

    batch = Batch(
            header = batch_header_bytes,
            header_signature = batch_signature,
            transactions = txns,
            timestamp = int(time.time())
            )
    batch_list_bytes= BatchList(batches=[batch]).SerializeToString()
    #Probably better if send_resquest prints in main.py
    print(send_request(URL,"batches",batch_list_bytes,"application/octet-stream"))

def show(ip : str, wal: str) -> None:
    params = {
        'family' : 'bgt',
        'cmd' : 'show',
        'wallet' : wal
            }
    response = requests.get(f"http://{ip}/run",params=params)
    print(response.text)

def List(ip:str, val_ip : str) -> None:
    params ={
        'family' : 'bgt',
        'url' : val_ip,
        'cmd' : 'list'
            }
    response = requests.get(f"http://{ip}/run",params=params)
    return response.text

