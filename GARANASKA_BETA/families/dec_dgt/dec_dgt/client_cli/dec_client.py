# Copyright 2022 DGT NETWORK INC © Stanislav Parsov
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
from dec_common.protobuf.dec_dgt_token_pb2 import DecTokenInfo

from dec_dgt.client_cli.exceptions import DecClientException
from dec_dgt.client_cli.dec_attr import *


def _sha512(data):
    return hashlib.sha512(data).hexdigest()

def _get_prefix():                                             
    return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]                     
                                                                   
def _get_address(name):                                      
    prefix = _get_prefix()                                    
    game_address = _sha512(name.encode('utf-8'))[64:]              
    return prefix + game_address  
                                 
def _token_info(val):
    token = DecTokenInfo()
    token.ParseFromString(val)
    return token

class DecClient:
    def __init__(self, url, keyfile=None):
        self.url = url

        if keyfile is not None:
            try:
                with open(keyfile) as fd:
                    private_key_str = fd.read().strip()
                    fd.close()
            except OSError as err:
                raise DecClientException(
                    'Failed to read private key: {}'.format(str(err)))
            context = create_context('secp256k1')
            try:
                private_key = context.from_hex(private_key_str)
            except ParseError as e:
                raise DecClientException(
                    'Unable to load private key: {}'.format(str(e)))

            self._signer = CryptoFactory(context).new_signer(private_key)

    def load_json_proto(self,value):
        if isinstance(value,dict):                        
            info = value                                  
        else:                                             
            with open(value,"r",encoding='utf8') as cert_file:            
                try:                                      
                    info =  json.load(cert_file)          
                                                          
                except Exception as ex: 
                    print('Cant load file {} - {}'.format(value,ex))                  
                    info = {}  
        return info                           

    # emission cmd parts
    def emission(self,args,wait=None):
        info = self.load_json_proto(args.proto)
        if args.total_sum :
            info[DEC_TOTAL_SUM][DATTR_VAL] = args.total_sum
        if args.name :                                 
            info[DEC_NAME][DATTR_VAL] = args.name
        if args.fee :                             
            info[DEC_FEE][DATTR_VAL] = args.fee 

        print('PROTO',info)
        self._send_transaction(DEC_EMISSION_OP, DEC_EMISSION_KEY, info, to=None, wait=wait)

    def birth(self,args,wait=None):
        token = self.show(DEC_EMISSION_KEY)
        dec = cbor.loads(token.dec) if token.group_code == DEC_NAME_DEF else {}   
        tmstamp = dec[DEC_TMSTAMP] if DEC_TMSTAMP in dec else 0
        return tmstamp


    def total_supply(self,args,wait=None):  
        token = self.show(DEC_EMISSION_KEY)                                     
        dec = cbor.loads(token.dec) if token.group_code == DEC_NAME_DEF else {} 
        return dec[DEC_TOTAL_SUM] if DEC_TOTAL_SUM in dec else 0
    
       
           
    def token_info(self,args,wait=None):    
        token = self.show(DEC_EMISSION_KEY)
        info = {}    
        if token.group_code == DEC_NAME_DEF :
            dec = cbor.loads(token.dec)
            for attr,aval in dec.items():
                if attr not in [DEC_PASSKEY,DEC_MINTING_TOTAL,DEC_СORPORATE_TOTAL,DEC_SALE_TOTAL,DEC_TMSTAMP]:
                    info[attr] = aval[DATTR_VAL]
                
            
        return info
        
    def burn(self,args,wait=None):   
        info = {}
        if args.passkey and args.sum:
            info[DEC_PASSKEY] = args.passkey
            info[DEC_TOTAL_SUM] = args.sum
            print('PROTO',info)                                                                 
            self._send_transaction(DEC_BURN_OP, DEC_EMISSION_KEY, info, to=None, wait=wait)
        else:
            print('Set  passkey and burn_sum argument')

    def change_mint(self,args,wait=None):
        info = {}                                                                                    
        if args.passkey and args.mint:                                                                
            info[DEC_PASSKEY] = args.passkey  
            try:
                info[DEC_MINT_PARAM] = json.loads(args.mint) 
            except Exception as ex :
                print('Cant load ({}) - {}'.format(args.mint,ex))
                return
            print('PROTO',info)                                                                      
            self._send_transaction(DEC_CHANGE_MINT_OP, DEC_EMISSION_KEY, info, to=None, wait=wait)          
        else:                                                                                        
            print('Set  passkey and mint_param argument')                                              


    def distribute(self,args,wait=None):    
        token = self.show(DEC_EMISSION_KEY)               
        info = {}                                         
        if token.group_code == DEC_NAME_DEF :             
            dec = cbor.loads(token.dec)                        
            for attr in [DEC_MINTING_TOTAL,DEC_СORPORATE_TOTAL,DEC_SALE_TOTAL]:
                info[attr] = dec[attr]
        return info                                       



    def faucet(self,args,wait=None):  
        if args.passkey:  
            info = {}                                                              
            info[DEC_PASSKEY] = args.passkey                                                        
            info[DATTR_VAL]   = args.value                                       
            print('PROTO',info)                                                                     
            self._send_transaction(DEC_FAUCET_OP, args.pubkey, info, to=DEC_EMISSION_KEY, wait=wait)  
        else:                                                                                       
            print('Set  passkey argument')                                           


    #                            
    # emission cmd parts End
    #  
    # minting cmd parts 
    def mint(self,args,wait=None): 
        pass 

    def heart_beat(self,args,wait=None):      
        pass 
    
    def seal_count(self,args,wait=None):                            
        pass  
                                                    
    #
    # banking cmd parts  
    #                              
    def balance_of(self,args,wait=None):  
        token = self.show(args.pubkey)  
        return token

    def send(self,args,wait=None): 
        info = {DATTR_VAL : args.amount}
        if args.asset_type:
            info[DEC_ASSET_TYPE] = args.asset_type             
        if args.did:                                
            info[DEC_DID_VAL] = args.did

        return self._send_transaction(DEC_SEND_OP, args.name, info, to=args.to, wait=wait,din=DEC_EMISSION_KEY)  

    def pay(self,args,wait=None):      
        info = {DATTR_VAL : args.amount}                                                                         
        if args.asset_type:                                                                                      
            info[DEC_ASSET_TYPE] = args.asset_type                                                               
        if args.did:                                                                                             
            info[DEC_DID_VAL] = args.did                                                                         
        if args.target:
            info[DEC_TARGET] = args.target
        din = [DEC_EMISSION_KEY]
        if args.provement_key:                        
            info[DEC_PROVEMENT_KEY] = args.provement_key 
            din.append(args.provement_key)

        return self._send_transaction(DEC_PAY_OP, args.name, info, to=args.to, wait=wait,din=din)  
    
     
    def invoice(self,args,wait=None):   
        info = {DATTR_VAL : args.amount}                                                                         
        if args.target:                                                                                          
            info[DEC_TARGET] = args.target                                                                       
        if args.available_till:                                                                                   
            info[AVAILABLE_TILL] = args.available_till                                                         
                                                                                                                 
        return self._send_transaction(DEC_INVOICE_OP, args.prove_key, info, to=None, wait=wait,din=[DEC_EMISSION_KEY,args.pub_key])   
        
    
    def bank_list(self,args,wait=None):                                                
        pass   
    #  Banking cmd parts END
    #                                                                 
    def set(self, name, value, wait=None):
        return self._send_transaction(DEC_SET_OP, name, value, to=None, wait=wait)

    def inc(self, name, value, wait=None):
        return self._send_transaction(DEC_INC_OP, name, value, to=None, wait=wait)

    def dec(self, name, value, wait=None):
        return self._send_transaction(DEC_DEC_OP, name, value, to=None, wait=wait)

    def trans(self, name, value, to, wait=None):
        return self._send_transaction(DEC_TRANS_OP, name, value, to=to, wait=wait)

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
            val = cbor.loads(base64.b64decode(yaml.safe_load(result)["data"]))[name]
            token = DecTokenInfo()       
            token.ParseFromString(val)
            return token 
        except BaseException:
            return None

    def _get_status(self, batch_id, wait):
        try:
            result = self._send_request(
                'batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise DecClientException(err)

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
                raise DecClientException("No such key: {}".format(name))

            elif not result.ok:
                raise DecClientException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise DecClientException(
                'Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise DecClientException(err)

        return result.text

    def _send_transaction(self, verb, name, value, to=None, wait=None,din=None):
        val = {
            'Verb': verb,
            'Name': name,
            'Value': value,
        }
        if to is not None:
            val['To'] = to
        
        

        # Construct the address
        address = self._get_address(name)
        inputs = [address]
        outputs = [address]
        if to is not None:
            address_to = self._get_address(to)
            inputs.append(address_to)
            outputs.append(address_to)
        if din is not None:
            dinputs = din if isinstance(din,list) else [din]
            val[DATTR_INPUTS] = dinputs
            for ain in dinputs:
                address_in = self._get_address(ain)
                inputs.append(address_in)

        print("in={} out={}".format(inputs,outputs))
        payload = cbor.dumps(val)
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
