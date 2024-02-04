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
import os
import hashlib
import base64
import time
import random
import requests
import yaml
import cbor
from eth_keys import keys
from eth_utils import decode_hex,to_bytes
from eth_abi import encode as  encode_abi,decode as decode_abi,is_encodable_type,is_encodable
from web3._utils.abi import get_abi_input_types
from eth_utils import combine_argument_formatters,apply_formatters_to_sequence
from eth_abi.codec import ABICodec
from eth_abi.registry import registry
from eth_abi.grammar import parse
#from web3._utils.abi import (
#    abi_bytes_type,
#    abi_string_type,
#    uint256_abi_type,
#)
from eth_abi.exceptions import EncodingError, DecodingError
from dgt_signing import create_context
from dgt_signing import CryptoFactory,key_to_dgt_addr
from dgt_signing import ParseError

from dgt_sdk.protobuf.transaction_pb2 import TransactionHeader
from dgt_sdk.protobuf.transaction_pb2 import Transaction
from dgt_sdk.protobuf.batch_pb2 import BatchList
from dgt_sdk.protobuf.batch_pb2 import BatchHeader
from dgt_sdk.protobuf.batch_pb2 import Batch
from deth_common.protobuf.deth_pb2 import DethTransaction as BgtTokenInfo,CreateExternalAccountTxn,EvmEntry
from dgt_sdk.oauth.requests import OAuth2Session
from deth.client_cli.exceptions import DethClientException
from deth.client_cli.deth_attr import * 
from deth.client_cli.compile import compile_contract,get_compiled_contract
from eth_utils import (
    decode_hex,
    encode_hex,
)
from web3 import (
    Web3,
)
#from eth_utils import is_address, is_boolean, is_bytes, is_integer, is_string


   
   
   
   

def conv_bytes(address_string):
    return to_bytes(hexstr=address_string)

        
abi_mapping = {
    "address": conv_bytes,
    "bool": bool,
    "string": str,
    "bytes": bytes,
    "uint8": int,
    "uint256": int,
    "int8": int,
    "int256": int,
}

abi_codec = ABICodec(registry)
#abi_registry = registry
#type_codec = abi_registry.get_encoder("uint256")
#print('type_codec',type_codec)
def convert_abi_arguments(inputs, arguments):
    converted_arguments = []
    types = []
    for i, arg_type in enumerate(inputs):
        try:
            argument = arguments[i]
            type_codec = abi_mapping.get(arg_type)#abi_registry.get_encoder(arg_type)
            types.append(type_codec)
            #print(arg_type,dir(type_codec),str(type_codec))
            #val = decode_abi([arg_type],bytes(argument,'utf-8'))
            #print('val',val)

        except (IndexError, EncodingError, TypeError):
            raise ValueError("Invalid argument or type mismatch")
    formaters = combine_argument_formatters(*types)
    
    return formaters(arguments)

def get_formatter(abi_type):
    try:
        type_declaration = parse(abi_type)
        codec = abi_codec.get_type_codec(type_declaration)
        return codec
        #type_codec = abi_codec.get_type_encoder(abi_type)
        #return type_codec.encode_single
    except KeyError:
        raise ValueError(f"Unsupported argument type: {abi_type}")

def get_argument_types(abi_spec):
    return [input_param["type"] for input_param in abi_spec.get("inputs", [])]


def _sha512(data):
    return hashlib.sha512(data).hexdigest()

def _get_prefix():                                             
    return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]                     
                                                                   
def _get_address(name):                                      
    prefix = _get_prefix()                                    
    game_address = _sha512(name.encode('utf-8'))[64:]              
    return prefix + game_address  
                                 
def _token_info(val):
    token = BgtTokenInfo()
    token.ParseFromString(val)
    return token

class DethClient:
    def __init__(self, url, keyfile=None,token=None):
        self.url = url
        self._requests = OAuth2Session(token = {'access_token': token} if token is not None else None)
        #my_provider = Web3.HTTPProvider("http://127.0.0.1:8545");
        self._w3 = Web3()#Web3.EthereumTesterProvider())#my_provider)
        if keyfile is not None:
            try:
                with open(keyfile) as fd:
                    private_key_str = fd.read().strip()
                    fd.close()
            except OSError as err:
                raise DethClientException('Failed to read private key: {}'.format(str(err)))

            context = create_context('secp256k1')
            try:
                private_key = context.from_hex(private_key_str)
            except ParseError as e:
                raise DethClientException('Unable to load private key: {}'.format(str(e)))

            self._signer = CryptoFactory(context).new_signer(private_key)
            self._context = context
        else:
            self._context = create_context('secp256k1') 
        

    def get_random_addr(self):                                        
        priv_key = self._context.new_random_private_key()             
        pub_key = self._context.get_public_key(priv_key).as_hex()     
        addr = key_to_dgt_addr(pub_key,lng=30)                               
        print("PUB",addr,type(addr))                                            
        return addr  
                                                     
    def get_pub_key(self,vkey):                                                                                   
        # try first open file with private key                                                                    
        try:                                                                                                      
            with open(vkey) as fd:                                                                                
                private_key_str = fd.read().strip()                                                               
                fd.close()                                                                                        
            if vkey.endswith('.pub') or vkey.endswith('.PUB'):                                                    
                #print('PUB',private_key_str)                                                                     
                return private_key_str                                                                            
        except OSError as err:                                                                                    
            # use value as pub key                                                                                
            return vkey                                                                                           
        try:                                                                                                      
            private_key = self._context.from_hex(private_key_str)                                                 
            signer = CryptoFactory(self._context).new_signer(private_key)                                         
            pubkey = signer.get_public_key().as_hex()                                                             
            #print('pub',pubkey)                                                                                  
            return pubkey                                                                                         
        except ParseError as e:                                                                                   
            print('Unable to load private key: {} use param is key'.format(str(e)))                               
            return vkey                                                                                           

    def get_smart_api(self,deployed_contract_address,abi):                                     
        smart = self._w3.eth.contract(                                                    
            address=Web3.to_checksum_address(encode_hex(deployed_contract_address)),      
            abi=abi,                                                     
        )  
        return smart                                                                               
                                                                                          


    def crt(self, opts, wait=None):
        #key = self.get_pub_key(name)
        pubkey = self._signer.get_public_key().as_hex()
        waddr = key_to_dgt_addr(pubkey,lng=30)
        print("crt",waddr)
        #return
        #addr = key_to_dgt_addr(key,lng=30)
        #sender_private_key = keys.PrivateKey(to_bytes(hexstr=addr)) #to_bytes(hexstr='0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8'))
        #sender_address = sender_private_key.public_key.to_canonical_address()
        #print("set",sender_address.hex())

        return self._send_transaction(DETH_CRT_OP, waddr, 0, to=None, wait=wait)

    def call(self, opts, wait=None):
        #contract_interface = get_compiled_contract(opts.out_path,opts.path,opts.name)           
        #if contract_interface is None:                                                                       
        #    print("Undefined smart contract {}".format(opts.name))
        #    return


        real_name = self.get_real_name(opts.name)
        data = self.show(real_name)
        if data is None:
            print("Unloaded smart contract",opts.name)
            return
        token = EvmEntry()
        token.ParseFromString(data)
        deployed_contract_address = token.account.address
        code = cbor.loads(token.account.code)
        #print('contr {}: smart={}'.format(real_name,code[DETH_SMART_NAME]))


        smart = self.get_smart_api(deployed_contract_address,code[DETH_SMART_ABI])
        #print('all',dir(smart)) 
        w3_tx = smart.functions  
        try:
            # [f['name'] for f in w3_tx._functions if f["type"] == 'function']
            func = smart.get_function_by_name(opts.func)
        except ValueError as ex:
            print("Smart contract '{}' has no such function '{}' use={} - ({})".format(opts.name,opts.func,smart.all_functions(),ex))
            return
        #print("func",dir(func),func.abi)
        
        if opts.args:
            vals = opts.args.split(',')
            itypes = get_argument_types(func.abi)
            #itypes = [ 'uint8','int256',"address"]
            #values = ['11','444','0x123abc']
            #print('form',get_formatter('uint256'))
            #fs = [int,str,bool]
            #formaters = apply_formatters_to_sequence(*fs)
            #formaters = combine_argument_formatters(*fs)
            #print('abi',formaters(['111','jjj','false']))
            converted_arguments = convert_abi_arguments(itypes, vals)
            #print("converted_arguments",converted_arguments)

        else:
            converted_arguments =  []
        #print('args',args)
        call = smart.encodeABI(fn_name=opts.func, args=converted_arguments)
        #print("smart func:",call) 
        
        #tx = func(
        #    10
        #)#.build_transaction(W3_TX_DEFAULTS)
        #print(tx,type(tx),dir(tx)) 
        #print(tx.abi) 
        #nhash = key_to_dgt_addr(opts.name,lng=30)
        pubkey = self._signer.get_public_key().as_hex()        
        creater_addr = key_to_dgt_addr(pubkey,lng=30)          
        val = {
                DETH_CALL_FUNC : call,
                DETH_CREATER : creater_addr
                }
        #try:
        #    print("estimate_gas",tx.estimate_gas()) 
        #except Exception as ex:
        #    print("cant estimate smart contract",ex)
        
        return self._send_transaction(DETH_CALL_OP, real_name, val, to=None, wait=wait)

    def perm(self, args, wait=None):
        return self._send_transaction(DETH_PERM_OP, args.name, args.value, to=None, wait=wait)

    def send(self, opts, wait=None):
        pubkey = self._signer.get_public_key().as_hex()
        from_addr = key_to_dgt_addr(pubkey,lng=30)

        to_pub = self.get_pub_key(opts.to)
        to_addr = key_to_dgt_addr(to_pub,lng=30)
        print("FROM={} TO={}".format(from_addr,to_addr))
        #return
        
        
                                                
        return self._send_transaction(DETH_SEND_OP, from_addr, opts.value, to=to_addr, wait=wait)    


    def smart(self, opts, wait=None):
        # load 
        pubkey = self._signer.get_public_key().as_hex()
        creater_addr = key_to_dgt_addr(pubkey,lng=30)

        if opts.compile >  0:
            ret = compile_contract(opts.path,opts.out_path)
            #print("COMP,ret",ret,ret.returncode)
            if ret.returncode != 0:
                return
        data = get_compiled_contract(opts.out_path,opts.path,opts.name)
        smart_name = self.get_real_name(opts.smart_keyfile)
        #nhash = key_to_dgt_addr(opts.name,lng=30)
        val = {
                DETH_SMART_CODE : {
                                    DETH_BIN        : data["bin"],
                                    DETH_SMART_ABI  : data["abi"],
                                    DETH_SMART_PATH : opts.path, # "opts.path:opts.name" -  this is key for contract
                                    DETH_SMART_NAME : opts.name
                                },
                DETH_CREATER    : creater_addr,
                DETH_UPDATE_MODE: opts.update > 0
            }
        #print("hash",nhash)
        # we should use creater_addr as name of smart 
        return self._send_transaction(DETH_SMART_OP, smart_name, val, to=None, wait=wait)

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

    def get_real_name(self, name):
        if name.startswith("0x"):           
            real_name = name                                         
        else:                                                        
            pub_key = self.get_pub_key(name)                         
            real_name = key_to_dgt_addr(pub_key,lng=30)              
        return real_name

    def show(self, name):
        real_name = self.get_real_name(name)
        
        address = self._get_address(real_name)
        #print('name:addr',address,real_name)
        result = self._send_request("state/{}".format(address), name=real_name,)

        try:
            return cbor.loads(base64.b64decode(yaml.safe_load(result)["data"]))[real_name]

        except BaseException:
            return None

    def _get_status(self, batch_id, wait):
        try:
            result = self._send_request('batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            yres = yaml.safe_load(result)['data'][0]
            #print("yres",yres)
            return (yres['status'],yres['invalid_transactions'])
        except BaseException as err:
            raise DethClientException(err)

    def _get_prefix(self):
        return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]

    def _get_address(self, name):
        prefix = self._get_prefix()
        game_address = _sha512(name.encode('utf-8'))[64:]
        return prefix + game_address

    def _send_request(self, suffix, data=None, content_type=None, name=None):
        if self.url.startswith("http"):
            url = "{}/{}".format(self.url, suffix)
        else:
            url = "{}://{}/{}".format('https' if os.environ.get('HTTPS_MODE') == '--http_ssl' else 'http',self.url, suffix)

        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = self._requests.post(url, headers=headers, data=data,verify=False)
            else:
                result = self._requests.get(url, headers=headers,verify=False)

            if result.status_code == 404:
                raise DethClientException("No such key: {}".format(name))

            elif not result.ok:
                raise DethClientException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise DethClientException(
                'Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise DethClientException(err)

        return result.text

    def _send_transaction(self, verb, name, value, to=None, wait=10):
        val = {
            DETH_VERB: verb,
            DETH_NAME: name,
            DETH_VAL: value,
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
        #print("inputs={} outputs={}".format(inputs,outputs))
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
            #print("RESPONSE={}".format(response))                
            status = ('PENDING','ok')                                    
            while wait_time < wait:                               
                status = self._get_status(                        
                    batch_id,                                     
                    wait - int(wait_time),                        
                )                                                 
                wait_time = time.time() - start_time              
                #print("STATUS={}".format(status))                
                if status[0] != 'PENDING':                           
                    return (*status,batch_id) #response            
                                                                  
            return (*status,batch_id) # response                   


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
