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

import asyncio
import re
import logging
import json
import base64
import hashlib
import random
import time
import os
from datetime import datetime

from aiohttp import web

# pylint: disable=no-name-in-module,import-error
# needed for the google.protobuf imports to pass pylint
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError



import bgt_bot_api.exceptions as errors
from bgt_bot_api import error_handlers
from bgt_bot_api.messaging import DisconnectError
from bgt_bot_api.messaging import SendBackoffTimeoutError

from dgt_sdk.protobuf.validator_pb2 import Message
from dgt_sdk.protobuf import client_transaction_pb2
from dgt_sdk.protobuf import client_list_control_pb2
from dgt_sdk.protobuf import client_batch_submit_pb2
from dgt_sdk.protobuf import client_state_pb2
from dgt_sdk.protobuf import client_block_pb2
from dgt_sdk.protobuf import client_batch_pb2
from dgt_sdk.protobuf import client_topology_pb2

from dgt_sdk.protobuf.client_receipt_pb2 import  ClientReceiptGetRequest
from dgt_sdk.protobuf.client_receipt_pb2 import  ClientReceiptGetResponse
from dgt_sdk.protobuf import client_peers_pb2
from dgt_sdk.protobuf import client_status_pb2
from dgt_sdk.protobuf.client_peers_pb2 import  ClientPeersControlRequest,ClientPeersControlResponse

from dgt_sdk.protobuf.block_pb2 import BlockHeader
from dgt_sdk.protobuf.batch_pb2 import Batch,BatchHeader,BatchList
from dgt_sdk.protobuf.transaction_pb2 import Transaction,TransactionHeader

from bgt_bot_api.route_handlers import RouteHandler,DEFAULT_TIMEOUT
from bgt_bot_api.bot_handlers import Tbot
import cbor
import yaml

from dgt_signing import CryptoFactory,create_context

from smart_bgt.processor.utils import FAMILY_NAME as SMART_BGX_FAMILY
from smart_bgt.processor.utils import FAMILY_VER as SMART_BGX_VER
from smart_bgt.processor.utils import SMART_BGT_META,SMART_BGT_CREATOR_KEY,SMART_BGT_PRESENT_AMOUNT
from smart_bgt.processor.utils import make_smart_bgt_address
# bgt tokens utils

from dgt_bgt.client_cli.bgt_client import FAMILY_VERSION as BGT_FAMILY_VERSION
from dgt_bgt.client_cli.bgt_client import FAMILY_NAME as BGT_FAMILY_NAME
from dgt_bgt.client_cli.bgt_client import _get_address as bgt_get_address
from dgt_bgt.client_cli.bgt_client import _token_info as bgt_token_info
# stuff tokens  utils
from dgt_stuff.client_cli.stuff_client import FAMILY_VERSION as STUFF_FAMILY_VERSION
from dgt_stuff.client_cli.stuff_client import FAMILY_NAME as STUFF_FAMILY_NAME
from dgt_stuff.client_cli.stuff_client import _get_prefix as stuff_get_prefix
from dgt_stuff.client_cli.stuff_client import _get_address as stuff_get_address
from dgt_stuff.client_cli.stuff_client import _token_info as stuff_token_info

# XCERT
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo
from x509_cert.client_cli.xcert_client import _get_prefix as xcert_get_prefix
from x509_cert.client_cli.xcert_client import _get_address as xcert_get_address
from x509_cert.client_cli.xcert_client import FAMILY_VERSION as XCERT_FAMILY_VERSION 
from x509_cert.client_cli.xcert_client import FAMILY_NAME as XCERT_FAMILY_NAME 

import time
LOGGER = logging.getLogger(__name__)

TRANSACTION_FEE = 0.1
STICKERS_ID = ['CAACAgIAAxkBAAIF9F6kUJ5Lw5OiQqid_RPttTSTvyImAAJKAAMNttIZMbmooT7Bxh4ZBA','CAACAgIAAxkBAAIG616lU-vcYirYCwwrLrKX73-uepyZAALCAQACVp29Cpl4SIBCOG2QGQQ','CAACAgIAAxkBAAIG7V6lVKbCn5BTkYWohNhS5Vj_R9KCAAIwAAMoD2oU-59-sQY3MgUZBA','CAACAgIAAxkBAAIG716lVPjDYPkfXtomRWoPLTBOYTjSAAIaAQACMNSdEfnuBojG8jcjGQQ']

XCERT_PROTO = {
    "COUNTRY_NAME"              : "CA",      
    "STATE_OR_PROVINCE_NAME"    : "ONTARIO", 
    "LOCALITY_NAME"             : "BARRIE", 
    "ORGANIZATION_NAME"         : "YOUR ORGANIZATION NAME" ,
    "COMMON_NAME"               : "NODE SAMPLE", 
    "DNS_NAME"                  : "dgt.world", 
    "EMAIL_ADDRESS"             : "adminmail@mail.com",
    "PSEUDONYM"                 : "dgt00000000000000000",
    "JURISDICTION_COUNTRY_NAME" : "CA",
    "BUSINESS_CATEGORY"         : "YOUR BUSINESS CATEGORY",
    "USER_ID"                   : "000000000000000001"
}
DID_ATTR = 'did'
UID_ATTR = 'uid'
CID_ATTR = 'chat_id'
UFN_ATTR = 'user_first_name'
OPR_ATTR = 'oper'
EMAIL_ATTR = 'email'
ADDRESS_ATTR = 'address'
XCERT_ATTR = 'xcert'
COUNTRY_ATTR = 'country'

def _sha512(data):
    return hashlib.sha512(data).hexdigest()

def _base64url2public(addr):
    try:
        return base64.urlsafe_b64decode(addr).decode("utf-8") 
    except :
        raise errors.BadWalletAddress()
        

def _public2base64url(key):
    return base64.urlsafe_b64encode(key.encode()).decode('utf-8')

def user_wallet_name(user_id):
    return 'wallet_{}'.format(user_id)

def user_stuff_name(val):
    return '{}'.format(int(val))

class BgxTeleBot(Tbot):
    """Contains a number of aiohttp handlers for endpoints in the Rest Api.

    Each handler takes an aiohttp Request object, and uses the data in
    that request to send Protobuf message to a validator. The Protobuf response
    is then parsed, and finally an aiohttp Response object is sent back
    to the client with JSON formatted data and metadata.

    If something goes wrong, an aiohttp HTTP exception is raised or returned
    instead.

    Args:
        connection (:obj: messaging.Connection): The object that communicates
            with the validator.
        timeout (int, optional): The time in seconds before the Api should
            cancel a request and report that the validator is unavailable.
    """

    def __init__(self,loop, connection,tdb,token=None,project_id=None,session_id=None,proxy=None,connects=None,vault=None,conf=None):

        super().__init__(loop,connection,tdb,token,project_id,session_id,proxy,connects)
        # DGT init
        
        self._vault = vault

        home_dir = os.environ['PEER_HOME'] if 'PEER_HOME' in os.environ else "/project/peer"
        kdir = f'{home_dir}/keys'
        self._signer = self._load_identity_signer(kdir,'notary') 
        self._user_notary = conf.user_notary
        self._approve_q = {}
        LOGGER.debug(f'DgtTeleBot: from={kdir} _signer PUBLIC_KEY={self._public_key.as_hex()[:8]} NOTARY={self._user_notary}')
        #self.make_xcert(XCERT_PROTO,{})

    def _load_identity_signer(self,key_dir, key_name):                                                                
        """Loads a private key from the key directory, based on a validator's                                    
        identity.                                                                                                
                                                                                                                 
        Args:                                                                                                    
            key_dir (str): The path to the key directory.                                                        
            key_name (str): The name of the key to load.                                                         
                                                                                                                 
        Returns:                                                                                                 
            Signer: the cryptographic signer for the key                                                         
        """                                                                                                      
        key_path = os.path.join(key_dir, '{}.priv'.format(key_name))                                             
                                                                                                                 
        if not os.path.exists(key_path):                                                                         
            raise Exception("No such signing key file: {}".format(key_path))                                     
        if not os.access(key_path, os.R_OK):                                                                     
            raise Exception(                                                                                     
                "Key file is not readable: {}".format(key_path))                                                 
                                                                                                                 
        LOGGER.info('Loading signing key: %s', key_path)                                                         
        try:                                                                                                     
            with open(key_path, 'r') as key_file:                                                                
                private_key_str = key_file.read().strip()                                                        
        except IOError as e:                                                                                     
            raise Exception(                                                                                     
                "Could not load key file: {}".format(str(e)))                                                    
                                                                                                                 
        context = create_context('secp256k1')                                                            
        try:                                                                                                     
            private_key = context.from_hex(private_key_str)                                                      
        except signing.ParseError as e:                                                                          
            raise Exception(                                                                                     
                "Invalid key in file {}: {}".format(key_path, str(e)))  
                                                 
        self._private_key = private_key                      
        self._public_key = context.get_public_key(self._private_key)
        self._context =  context                                                                                                        
        crypto_factory = CryptoFactory(context)                                                                  
        return crypto_factory.new_signer(private_key)                                                            

    def get_user_did(self,uid):
        did = f"did:notary:{self._public_key.as_hex()[:8]}:{uid}"
        return did

    def make_xcert_prof(self,proto_xcert,info):
        proto = proto_xcert.copy()     
        if EMAIL_ATTR in info:                                
            proto["EMAIL_ADDRESS"] = info[EMAIL_ATTR]         
        if DID_ATTR in info:                                  
            proto["USER_ID"] = str(info[DID_ATTR])            
                                                              
        if ADDRESS_ATTR  in info:                             
            proto["LOCALITY_NAME"] = info[ADDRESS_ATTR]       
        if COUNTRY_ATTR in info:                              
            proto["COUNTRY_NAME"] = info[COUNTRY_ATTR]        
        return proto



    def make_xcert(self,proto,info,after=10,before=0):

        proto = self.make_xcert_prof(proto,info)
        cert = self._signer.context.create_x509_certificate(proto,self._signer.private_key,after=after,before=before)        
        pubkey = self._signer.get_public_key().as_hex() 
        token = X509CertInfo(                      
                         owner_key = pubkey,        
                         xcert = cert             
            )                                      
        ser_cert = token.SerializeToString().hex() 

        info[XCERT_ATTR] = cert.hex()                                      
        LOGGER.info(f'XCERT {cert} PUB={pubkey}') 
        return cert,pubkey



    def _create_batch(self, transactions):
        """
        Create batch for transactions
        """
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
            timestamp=int(time.time())
            )
        return batch
        #return BatchList(batches=[batch])

    def _create_transaction(self,payload,inputs,outputs,dependencies=[],family=SMART_BGX_FAMILY,ver=SMART_BGX_VER):
        """
        make transaction
        """
        LOGGER.debug('DgtTeleBot: _create_transaction make Transaction')
        txn_header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name=family,
            family_version=ver,
            inputs=inputs,
            outputs=outputs,
            dependencies=dependencies,
            payload_sha512=_sha512(payload),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            nonce=hex(random.randint(0, 2**64))
        ).SerializeToString()

        signature = self._signer.sign(txn_header)
        transaction = Transaction(
            header=txn_header,
            payload=payload,
            header_signature=signature
        )
        return transaction

    async def _get_state_by_addr(self,request,address):
        LOGGER.debug('DgtTeleBot:_get_state_by_addr %s',address)
        state_address = make_smart_bgt_address(address)

        error_traps = [error_handlers.InvalidAddressTrap] #,error_handlers.StateNotFoundTrap]

        head = request.url.query.get('head', None)

        head, root = await self._head_to_root(head)
        response = await self._query_validator(
            Message.CLIENT_STATE_GET_REQUEST,
            client_state_pb2.ClientStateGetResponse,
            client_state_pb2.ClientStateGetRequest(
                state_root=root, address=state_address),
            error_traps)
        LOGGER.debug('DgtRouteHandler:_get_state_by_addr %s',address)
        try:
            result = cbor.loads(base64.b64decode(response['value']))
            LOGGER.debug('DgtRouteHandler: _get_state_by_addr result=%s',type(result))
        except BaseException:
            LOGGER.debug('DgtRouteHandler: Cant get state FOR=%s',address)
            return None
        return result

    async def make_bgt_transaction(self,verb, name, value=None, to=None,minfo=None):
        """
        make bgt transaction
        """
        val = {                                                               
            'Verb': verb,                                                     
            'Name': name,                                                     
        }   
        if value is not None:                                                    
            val['Value'] = value                                                                  
        if to is not None:                                                    
            val['To'] = to                                                    
                                                                              
        payload = cbor.dumps(val)                                             
                                                                              
        # Construct the address                                               
        address = bgt_get_address(name)                                     
        inputs = [address]                                                    
        outputs = [address]                                                   
        if to is not None:                                                    
            address_to = bgt_get_address(to)                                
            inputs.append(address_to)                                         
            outputs.append(address_to)                                        
        transaction = self._create_transaction(payload,inputs,outputs,family=BGT_FAMILY_NAME,ver=BGT_FAMILY_VERSION)
        batch = self._create_batch([transaction])
        batch_id = batch.header_signature #batch_list.batches[0].header_signature

        # Query validator
        error_traps = [error_handlers.BatchInvalidTrap,error_handlers.BatchQueueFullTrap]
        validator_query = client_batch_submit_pb2.ClientBatchSubmitRequest(batches=[batch])
        LOGGER.debug('make_bgt_transaction: _make_token_transfer send batch_id=%s',batch_id)

        #with self._post_batches_validator_time.time():
        resp = await self._query_validator(
            Message.CLIENT_BATCH_SUBMIT_REQUEST,
            client_batch_submit_pb2.ClientBatchSubmitResponse,
            validator_query,
            error_traps)
        if minfo and resp is not None and ('status' in resp) and resp['status'] == 'OK':
            LOGGER.debug('make_bgt_transaction: check result')
            self.intent_handler(minfo._replace(batch_id=batch_id))
        else:
            return None
        LOGGER.debug('make_bgt_transaction: done=%s',resp)
        return batch_id

    async def list_state(self,address):
            """Fetches list of data entries, optionally filtered by address prefix.

            Request:
                query:
                    - head: The id of the block to use as the head of the chain
                    - address: Return entries whose addresses begin with this
                    prefix

            Response:
                data: An array of leaf objects with address and data keys
                head: The head used for this query (most recent if unspecified)
                link: The link to this exact query, including head block
                paging: Paging info and nav, like total resources and a next link
            """
            #paging_controls = self._get_paging_controls(request)
            # for DAG ask head of chain for getting merkle root is incorrect way 
            # FIXME - add special method for asking real merkle root
            #head, root = await self._head_to_root(request.url.query.get('head', None))
            LOGGER.debug('LIST_STATE STATE=%s',address)
            error_traps = [error_handlers.InvalidAddressTrap]       
            validator_query = client_state_pb2.ClientStateListRequest(
                state_root=None,#root,
                address=address,
                #sorting="default",
                #paging=self._make_paging_message(paging_controls)
                )

            response = await self._query_validator(
                Message.CLIENT_STATE_LIST_REQUEST,
                client_state_pb2.ClientStateListResponse,
                validator_query,
                error_traps)
            return response.get('entries', [])

    async def _get_state(self,address,state_address):
        LOGGER.debug('DgtTeleBot:_get_state_by_addr %s',address)
        #state_address = make_smart_bgt_address(address)

        error_traps = [error_handlers.InvalidAddressTrap] #,error_handlers.StateNotFoundTrap]

        #head = request.url.query.get('head', None)

        #head, root = await self._head_to_root(head)
        response = await self._query_validator(
            Message.CLIENT_STATE_GET_REQUEST,
            client_state_pb2.ClientStateGetResponse,
            client_state_pb2.ClientStateGetRequest(
                state_root=None, address=state_address),
            error_traps)
        LOGGER.debug('DgtRouteHandler:_get_state_by_addr %s',address)
        try:
            result = cbor.loads(base64.b64decode(response['value']))
            LOGGER.debug('DgtRouteHandler: _get_state_by_addr RESULT=%s',result)
        except BaseException:
            LOGGER.debug('DgtRouteHandler: Cant get state FOR=%s',address)
            result = None
        return result

    def unfold_stuff_history(self):
        pass
    async def _get_state_history(self,address,state_address,family='stuff'):                                              
        LOGGER.debug('DgtTeleBot:_get_state_history %s',address) 
        def byTime_key(receipt):
            return receipt['timestamp']

        error_traps = [error_handlers.InvalidAddressTrap]                                                           #     
        validator_query = ClientReceiptGetRequest(ind=ClientReceiptGetRequest.INDEX_ADDR,transaction_ids=[state_address])
        
        response = await self._query_validator(
            Message.CLIENT_RECEIPT_GET_REQUEST,
            ClientReceiptGetResponse,
            validator_query,
            error_traps)   
                                                                               
                                    
        try:   
            #value = base64.b64decode(response['value']) 
            value = self._drop_id_prefixes(self._drop_empty_props(response['receipts']))                                                                                   
            LOGGER.debug('DgtRouteHandler:_get_state_history %s=%s',address,value) 
            result = {}
            n = 0
            prev = None
            svalue = sorted(value, key = byTime_key)
            for receipt in svalue:
                timestamp = receipt['timestamp']
                dtm = datetime.fromtimestamp(timestamp)
                for changes in receipt['state_changes']:
                    val = base64.b64decode(changes['value'])
                    content = cbor.loads(val)
                    LOGGER.debug('DgtRouteHandler:timestamp=%s receipt=%s\n content=%s',dtm,val,content)
                    
                    for key,v in content.items():  
                        if family == 'stuff':
                            try:                                                                                                   
                                token = stuff_token_info(v)                                                                        
                                stuff = cbor.loads(token.stuff) 
                                if prev:
                                    # compare with pevious
                                    fstuff = {}
                                    #LOGGER.debug('PREV: stuff=%s',prev)
                                    for nm,nval in stuff.items():
                                        if nm in prev and nval != prev[nm]:
                                            fstuff[nm] = nval
                                else:
                                    fstuff = stuff.copy()
                                    #LOGGER.debug('FIRST: stuff=%s',fstuff)
                                fstuff['user'] = token.user                                                                         
                            except Exception as ex1:                                                                               
                                fstuff = {}                
                                stuff = {}
                            result[dtm] = fstuff
                            prev = stuff.copy()
                        elif family == 'bgt':
                            token = bgt_token_info(v)
                            result[dtm] = {'amount':token.decimals}

                        n += 1
            LOGGER.debug('DgtRouteHandler:n=%s content=%s',n,result)
            
            
        except BaseException:                                                                      
            LOGGER.debug('DgtRouteHandler: Cant get state FOR=%s',address)                         
            result = None                                                                          
        return result                                                                              

    async def _peers_control(self,cname,pname,mode):
        error_traps = [error_handlers.InvalidAddressTrap]                                                                
        vquery = ClientPeersControlRequest(mode=mode,cluster=cname,peer=pname)
        try:
            response = await self._query_validator(
                Message.CLIENT_PEERS_CONTROL_REQUEST,
                ClientPeersControlResponse,
                vquery,
                error_traps)
            LOGGER.debug('DgtRouteHandler:_peers_control response %s',response)
            return response['info'] if response is not None else 'Service Unavailable - try again' 

        except errors.ValidatorTimedOut:
            return 'Service Unavailable'

    
    def get_args_from_request(self,parameters):
        args = {}                                         
        for param,val in parameters.items(): 
            if val != '' :                                
                args[param] = val
                LOGGER.debug('ARG: %s=%s(%s)',param,val,type(val))
        return args     
                            
    async def bgt_get_state(self,wallet):
        # get BGT state
        state_address = bgt_get_address(wallet)              
        val = await self._get_state(wallet,state_address)    
        return bgt_token_info(val[wallet]) if val else None

    async def bgt_get_state_history(self,wallet):                        
        # get BGT state                                          
        state_address = bgt_get_address(wallet) 
        LOGGER.debug('get_state_history: %s=>%s',wallet,state_address)                
        val = await self._get_state_history(wallet,state_address,family='bgt')        
        return val 

    async def stuff_get_state(self,num_stuff):                        
        # get BGT state                                          
        state_address = stuff_get_address(num_stuff)                  
        val = await self._get_state(num_stuff,state_address)        
        return stuff_token_info(val[num_stuff]) if val else None
        
    async def stuff_get_state_history(self,num_stuff):                        
        # get BGT state                                          
        state_address = stuff_get_address(num_stuff)  
        LOGGER.debug('get_state_history: %s=>%s',num_stuff,state_address)                
        val = await self._get_state_history(num_stuff,state_address)        
        return val 

    async def make_stuff_transaction(self,verb, name, value=None,minfo=None):
        """
        make bgt transaction
        """
        val = {                                                               
            'Verb': verb,                                                     
            'Name': name, 
            'User': minfo.user_first_name,                                                    
        }   
        if value is not None:                                                    
            val['Value'] = value                                                                  
                                                            

        payload = cbor.dumps(val)                                             

        # Construct the address                                               
        address = stuff_get_address(name)                                     
        inputs = [address]                                                    
        outputs = [address]                                                   
                                                
        transaction = self._create_transaction(payload,inputs,outputs,family=STUFF_FAMILY_NAME,ver=STUFF_FAMILY_VERSION)
        batch = self._create_batch([transaction])
        batch_id = batch.header_signature #batch_list.batches[0].header_signature

        # Query validator
        error_traps = [error_handlers.BatchInvalidTrap,error_handlers.BatchQueueFullTrap]
        validator_query = client_batch_submit_pb2.ClientBatchSubmitRequest(batches=[batch])
        LOGGER.debug('make_stuff_transaction: _make_token_transfer send batch_id=%s',batch_id)

        #with self._post_batches_validator_time.time():
        resp = await self._query_validator(
            Message.CLIENT_BATCH_SUBMIT_REQUEST,
            client_batch_submit_pb2.ClientBatchSubmitResponse,
            validator_query,
            error_traps)
        if minfo and resp is not None and ('status' in resp) and resp['status'] == 'OK':
            LOGGER.debug('make_stuff_transaction: check result')
            self.intent_handler(minfo._replace(batch_id=batch_id))
        else:
            return None
        LOGGER.debug('make_stuff_transaction: done=%s',resp)
        return batch_id


    async def intent_get_wallet(self,minfo):
        """
        Get or create wallet for user who send this message
        """
        LOGGER.debug('DgtTeleBot: create wallet FOR=%s',minfo)
        await self.make_bgt_transaction('set','wallet_'+str(minfo.user_id),5)
        minfo = minfo._replace(intent='smalltalk.agent.check_wallet')
        LOGGER.debug('DgtTeleBot: check wallet FOR=%s',minfo)
        self.intent_handler(minfo)

    async def intent_create_wallet(self,minfo):
        """
        Get or create wallet for user who send this message
        """
        LOGGER.debug('DgtTeleBot: create wallet FOR=%s',minfo)
        if minfo.batch_id:                                                       
            LOGGER.debug('DgtTeleBot: CHECK=%s CREATE wallet',minfo.batch_id) 
            batch = await self.check_batch_status(minfo.batch_id,minfo)          
            return
        args = self.get_args_from_request(minfo.result.parameters) if minfo.result else {'name' : minfo.user_first_name}
        if 'name' in args:
            if self.is_user_with_name(args['name']):
                new_user = self._tdb.get_multi([args['name']],index='name')[0]
                new_wallet = user_wallet_name(new_user[0])
                await self.make_bgt_transaction('set',new_wallet,5 if 'amount' not in args else round(args['amount']),minfo=minfo)
                self.send_message(minfo.chat_id, '{},делаю кошелек для {} {}.'.format(minfo.user_first_name,args['name'],new_user[1]['last_name']))
            else:
                self.send_message(minfo.chat_id, "Однако, персона '{}' мне неизвестена.".format(args['name']))

    def get_wallet_param(self,minfo):
        args = self.get_args_from_request(minfo.result.parameters)                                           
        if 'name' in args :                                                                                  
            if self.is_user_with_name(args['name']):                                                         
                user = self._tdb.get_multi([args['name']],index='name')[0]                                   
                wallet = user_wallet_name(user[0])                                                           
                uname = args['name']                                                                         
            else:                                                                                            
                self.send_message(minfo.chat_id, "К сожалению я не знаю персону '{}'.".format(args['name'])) 
                return None,None                                                                                      
        else:                                                                                                
            uname = minfo.user_first_name                                                                    
            wallet = user_wallet_name(minfo.user_id)                                                         
        return uname,wallet

    async def intent_check_wallet(self,minfo):
        """
        Get or create wallet check
        """
        LOGGER.debug('DgtTeleBot: check wallet FOR=%s',minfo)
        uname,wallet = self.get_wallet_param(minfo)
        if uname is None:
            return 
           
        try:
            token = await self.bgt_get_state(wallet)
            LOGGER.debug('DgtTeleBot: %s=%s',wallet,token)
            repl = 'В кошельке {}: {} {}.'.format(uname,token.decimals,token.group_code) if token else "К сожалению у {} нет кошелька".format(uname)
            self.send_message(minfo.chat_id, repl)
        except Exception as ex:
            LOGGER.debug('DgtTeleBot: cant check token into=%s (%s)',wallet,ex)
            
    async def intent_check_wallet_history(self,minfo):
        """
        Get wallet history
        """
        LOGGER.debug('DgtTeleBot: check_wallet_history FOR=%s',minfo)
        uname,wallet = self.get_wallet_param(minfo)
        if uname is None:
            return 

        try:
            token = await self.bgt_get_state_history(wallet)
            LOGGER.debug('DgtTeleBot: %s=%s',wallet,token)
            
            repl = 'История кошелька {}:\n{}.'.format(uname,yaml.dump(token, default_flow_style=False)[0:-1]) if token else "К сожалению у {} нет кошелька".format(uname)
            self.send_message(minfo.chat_id, repl)
        except Exception as ex:
            LOGGER.debug('DgtTeleBot: cant check token into=%s (%s)',wallet,ex)

    async def intent_trans_token(self,minfo):
        if minfo.batch_id:                                                       
            LOGGER.debug('DgtTeleBot: CHECK=%s TRANS to wallet',minfo.batch_id) 
            batch = await self.check_batch_status(minfo.batch_id,minfo)          
            return
        args = self.get_args_from_request(minfo.result.parameters)
        if 'amount' in args and 'name' in args :
            if self.is_user_with_name(args['name']):
                to_user = self._tdb.get_multi([args['name']],index='name')[0]
                # check wallet TO 
                to_wallet = user_wallet_name(to_user[0])
                token = await self.bgt_get_state(to_wallet)
                if token:
                    await self.make_bgt_transaction('trans',user_wallet_name(minfo.user_id),round(args['amount']),to_wallet,minfo=minfo)
                    self.send_message(minfo.chat_id, 'Хорошо {}. Пытаюсь перевести {} BGT : {} {}.'.format(minfo.user_first_name,args['amount'],args['name'],to_user[1]['last_name']))   
                    LOGGER.debug('DgtTeleBot: TRANS TOKEN %s TO %s(%s=%s)',str(args['amount']),args['name'],to_user[0],to_user[1])

                else:
                    self.send_message(minfo.chat_id, '{},а у {} {} нет кошелька.'.format(minfo.user_first_name,args['name'],to_user[1]['last_name']))

            else:
                self.send_message(minfo.chat_id, "Однако, участник '{}' мне неизвестен.".format(args['name']))

    async def intent_inc_wallet(self,minfo):
        """
        add token into wallet
        """
        if minfo.batch_id:                                                       
            LOGGER.debug('DgtTeleBot: INC wallet CHECK=%s',minfo.batch_id) 
            batch = await self.check_batch_status(minfo.batch_id,minfo)          
            return                                                               

        args = self.get_args_from_request(minfo.result.parameters)
        if 'amount' in args:
            token = round(args['amount'])
            LOGGER.debug('DgtTeleBot: inc wallet %s',token)
            await self.make_bgt_transaction('inc','wallet_'+str(minfo.user_id),token,minfo=minfo)
            self.send_message(minfo.chat_id, 'Хорошо {}. Добавляю {} BGT.'.format(minfo.user_first_name,args['amount']))
            

    async def intent_dec_wallet(self,minfo):
        """
        dec token into wallet
        """
        if minfo.batch_id:
            LOGGER.debug('DgtTeleBot: DEC wallet CHECK TRANS=%s',minfo.batch_id)
            batch = await self.check_batch_status(minfo.batch_id,minfo)
            return
        args = self.get_args_from_request(minfo.result.parameters)
        if 'amount' in args:
            token = round(args['amount'])
            LOGGER.debug('DgtTeleBot: DEC wallet %s',token)
            await self.make_bgt_transaction('dec','wallet_'+str(minfo.user_id),token,minfo=minfo)
            self.send_message(minfo.chat_id, 'Хорошо {}. Скинул {} BGT.'.format(minfo.user_first_name,args['amount']))
            

    async def intent_buy_stuff(self,minfo):
        """
        buy something
        """
        if minfo.batch_id:
            LOGGER.debug('DgtTeleBot: BUY STUFF CHECK TRANS=%s',minfo.batch_id)
            batch = await self.check_batch_status(minfo.batch_id,minfo)
            if batch['status'] == 'COMMITTED':
                # send sticker
                self.send_sticker(minfo.chat_id,STICKERS_ID[1]) 
                
            return
        args = self.get_args_from_request(minfo.result.parameters)
        if 'stuff' in args:
            LOGGER.debug('DgtTeleBot: BUY %s',args['stuff'])
            await self.make_bgt_transaction('dec','wallet_'+str(minfo.user_id),2,minfo=minfo)
            

    async def intent_sell_stuff(self,minfo):
        """
        sell something
        """
        if minfo.batch_id:
            LOGGER.debug('DgtTeleBot: SELL STUFF CHECK TRANS=%s',minfo.batch_id)
            batch = await self.check_batch_status(minfo.batch_id,minfo)
            if batch['status'] == 'COMMITTED':
                # send sticker
                self.send_message(minfo.chat_id, 'Ну вот, немного подзаработали.'.format(minfo.user_first_name)) 
            return
        args = self.get_args_from_request(minfo.result.parameters)
        if 'stuff' in args:
            LOGGER.debug('DgtTeleBot: SELL %s',args['stuff'])
            await self.make_bgt_transaction('inc','wallet_'+str(minfo.user_id),3,minfo=minfo)
            

    async def intent_create_stuff(self,minfo):
        """
        Get or create stuff for user who send this message
        """
        LOGGER.debug('DgtTeleBot: create stuff FOR=%s',minfo)
        if minfo.batch_id:                                                       
            LOGGER.debug('DgtTeleBot: CHECK=%s CREATE stuff',minfo.batch_id) 
            batch = await self.check_batch_status(minfo.batch_id,minfo)          
            return
        args = self.get_args_from_request(minfo.result.parameters) if minfo.result else {'name' : minfo.user_first_name}
        LOGGER.debug('DgtTeleBot: create stuff args=%s',args)
        if 'number' in args:
            new_stuff = user_stuff_name(args['number'])
            bid = await self.make_stuff_transaction('set',new_stuff,{'weight':100,'carbon':3,'type':'stuff','param1':'undef','param2':'undef','param3':'undef'},minfo=minfo)
            if bid is None:
                self.send_message(minfo.chat_id, f'Не смог выполнить запрос создания детали {new_stuff}.')
            else:
                self.send_message(minfo.chat_id, f'Создаю описание детали {new_stuff} от имени {minfo.user_first_name}.')
            
        #else:
            #self.send_message(minfo.chat_id, "Однако, номер детали не определен.")

    async def intent_update_stuff(self,minfo):                                                                                       
        """                                                                                                                          
        Get or create stuff for user who send this message                                                                           
        """                                                                                                                          
        LOGGER.debug('DgtTeleBot: update stuff FOR=%s',minfo)                                                                        
        if minfo.batch_id:                                                                                                           
            LOGGER.debug('DgtTeleBot: CHECK=%s CREATE stuff',minfo.batch_id)                                                         
            batch = await self.check_batch_status(minfo.batch_id,minfo)                                                              
            return                                                                                                                   
        args = self.get_args_from_request(minfo.result.parameters) if minfo.result else {'name' : minfo.user_first_name}             
        LOGGER.debug('DgtTeleBot: update stuff args=%s',args)                                                                        
        if 'number' in args:                                                                                                         
            new_stuff = user_stuff_name(args['number']) 
            upd = {}
            for nm,val in args.items():
                if nm == 'number':
                    continue
                if nm[:4] == 'name':
                    nnum = 'number'+nm[4:]
                    LOGGER.debug('upd : %s=%s',val,args[nnum] if nnum in args else 'undef')
                    if nnum in args:
                        upd[val] = args[nnum]
            if upd != {}:
                await self.make_stuff_transaction('upd',new_stuff,upd,minfo=minfo)                              
                self.send_message(minfo.chat_id, 'Изменяю описание детали {} от имени {}.'.format(new_stuff,minfo.user_first_name))  
            else:
                self.send_message(minfo.chat_id, 'Не заданы новые параметры детали {}.'.format(new_stuff)) 
   
    async def intent_show_stuff(self,minfo):                                                                                                            
        """                                                                                                                                                      
        Get or create wallet check                                                                                                                               
        """                                                                                                                                                      
        LOGGER.debug('DgtTeleBot: show  stuff FOR=%s',minfo)                                                                                                    
        args = self.get_args_from_request(minfo.result.parameters)                                                                                               
        if 'number' in args : 
            num_stuff = user_stuff_name(args['number'])                                                                                                                                     
            try:                                                                                                                                                     
                token = await self.stuff_get_state(num_stuff)                                                                                                             
                LOGGER.debug('DgtTeleBot: %s=%s',num_stuff,token) 
                if token :
                    user  = token.user
                    token = cbor.loads(token.stuff)

                repl = 'Деталь={} создано={} :\n{}.'.format(num_stuff,user,yaml.dump(token, default_flow_style=False)[0:-1]) if token else "К сожалению деталь {} не существует".format(num_stuff) 
                self.send_message(minfo.chat_id,repl)
            except Exception as ex:                                                                                                                                  
                LOGGER.debug('DgtTeleBot: cant check token into=%s (%s)',num_stuff,ex)                                                                                                                                        
                                                                                         
    
    async def intent_show_stuff_history(self,minfo):                                                                                                                                                                               
        """                                                                                                                                                                                                                
        Get  history stuff                                                                                                                                                                                        
        """                                                                                                                                                                                                                
        LOGGER.debug('DgtTeleBot: show  stuff history FOR=%s',minfo)                                                                                                                                                               
        args = self.get_args_from_request(minfo.result.parameters)                                                                                                                                                         
        if 'number' in args :                                                                                                                                                                                              
            num_stuff = user_stuff_name(args['number'])                                                                                                                                                                    
            try:                                                                                                                                                                                                           
                token = await self.stuff_get_state_history(num_stuff)                                                                                                                                                              
                LOGGER.debug('DgtTeleBot: %s=%s',num_stuff,token)                                                                                                                                                          
                                                                                                                                                                                                                                           
                repl = 'История детали {}:\n{}.'.format(num_stuff,yaml.dump(token, default_flow_style=False)[0:-1]) if token else "К сожалению деталь {} не существует".format(num_stuff)                         
                self.send_message(minfo.chat_id,repl)                                                                                                                                                                      
            except Exception as ex:                                                                                                                                                                                        
                LOGGER.debug('DgtTeleBot: cant check token into=%s (%s)',num_stuff,ex)                                                                                                                                     
                
    #                    
    async def intent_show_stuff_list(self,minfo):       
        LOGGER.debug('intent_show_stuff_list: %s',minfo)
        try:                                                                                                                                                                                                           
            list = await self.list_state("{}".format(stuff_get_prefix()))                                                                                                                                                              
            #LOGGER.debug('STUFF LIST: %s',list)  

            stuff_list = {}
            for val  in list:
                data = base64.b64decode(val['data'])
                content = cbor.loads(data) 
                #LOGGER.debug('STUFF : %s',content)
                for key,v in content.items():                                                                              
                    try:                                                                                                   
                        token = stuff_token_info(v)                                                                        
                        stuff = cbor.loads(token.stuff)
                        stuff_list[key] = {'user':token.user}
                        #LOGGER.debug('STUFF=%s : %s user=%s',key,stuff,token.user)
                    except:
                        pass
            repl = 'Список деталей:\n{}.'.format(yaml.dump(stuff_list, default_flow_style=False)[0:-1])                                                                                                                                                                                                                               
            
            self.send_message(minfo.chat_id,repl)                                                                                                                                                                      
        except Exception as ex:                                                                                                                                                                                        
            LOGGER.debug('DgtTeleBot: cant list stuff(%s)',ex) 


    async def make_xcert_transaction(self,verb, name, value=None,minfo=None):                                            
        """                                                                                                              
        make xcert transaction                                                                                             
        """                                                                                                              
        val = {                                                                                             
            'Verb': verb,     #  'set' 'upd'                                                                             
            'Owner': name,                                                                                  
            'Value': value,                                                                                 
        }                                                                                                   
        payload = cbor.dumps(val)                                                                                        
                                                                                                                         
        # Construct the address                                                                                          
        address = xcert_get_address(name)    # pubkey                                                                             
        inputs = [address]                                                                                               
        outputs = [address]                                                                                              
                                                                                                                         
        transaction = self._create_transaction(payload,inputs,outputs,family=XCERT_FAMILY_NAME,ver=XCERT_FAMILY_VERSION) 
        batch = self._create_batch([transaction])                                                                        
        batch_id = batch.header_signature #batch_list.batches[0].header_signature                                        

        # Query validator                                                                                     
        error_traps = [error_handlers.BatchInvalidTrap,error_handlers.BatchQueueFullTrap]                     
        validator_query = client_batch_submit_pb2.ClientBatchSubmitRequest(batches=[batch])                   
        LOGGER.debug('make_xcert_transaction:  send batch_id=%s',batch_id)                
                                                                                                              
        #with self._post_batches_validator_time.time():                                                       
        resp = await self._query_validator(                                                                   
            Message.CLIENT_BATCH_SUBMIT_REQUEST,                                                              
            client_batch_submit_pb2.ClientBatchSubmitResponse,                                                
            validator_query,                                                                                  
            error_traps)                                                                                      
        if minfo and resp is not None and ('status' in resp) and resp['status'] == 'OK':                      
            LOGGER.debug('make_xcert_transaction: check result')                                              
            
        else:                                                                                                 
            return None                                                                                       




    def intent_create_xcert(self,minfo):                                                                                                                                        
        """                                                                                                                                                                           
        Get or create xcert for user who send this message                                                                                                                            
        """   
        self.create_xcert(minfo,force=False)    
                                                                                                                                                                            
    def intent_update_xcert(self,minfo):                        
        """                                                           
        Get or update xcert for user who send this message            
        """                                                           
        self.create_xcert(minfo,force=True)                     


    def create_xcert(self,minfo,force=False):                                                                                                          
        """                                                                                                                                             
        Get or create/update xcert for user who send this message                                                                                                                            
        """                                                                                                                                                                           
        LOGGER.debug(f'DgtTeleBot: create/update xcert FOR={minfo}')                                                                                                                         
        if minfo.batch_id:                                                                                                                                                            
            LOGGER.debug('DgtTeleBot: CHECK=%s CREATE/UPDATE xcert',minfo.batch_id)                                                                                                          
            #batch = await self.check_batch_status(minfo.batch_id,minfo)                                                                                                               
            return                                                                                                                                                                    
        args = self.get_args_from_request(minfo.result.parameters) if minfo.result else {EMAIL_ATTR : f"{minfo.user_first_name}@mail.ru"}                                                              
        LOGGER.debug(f'DgtTeleBot: char={minfo.chat_id} notary={self._user_notary} create xcert args={args}')                                                                                                                         
        if EMAIL_ATTR in args and ADDRESS_ATTR in args : # and COUNTRY_ATTR in args:                                                                                 
            email = args[EMAIL_ATTR]                                                                                                                       
            if self._vault is not None:      
                did = self.get_user_did(minfo.user_id)                                                                                                           
                 
                try:
                    data = self._vault.get_xcert(uid=minfo.user_id)
                    if data and not force :    
                        if XCERT_ATTR in data['data']:       
                            del data['data'][XCERT_ATTR] 
                                                                                                                                               
                        self.send_message(minfo.chat_id, f'Сертификат существует KYC={did} XCERT={data} ')                                        
                        return                                                                                                                              
                    else:                                                                                                                                   
                        # create cert  
                        #self.send_message(minfo.chat_id, f'СUFN_ATTRертификат не существует')
                        args[DID_ATTR] = did
                        args[UID_ATTR] = minfo.user_id
                        args[CID_ATTR] = minfo.chat_id
                        args[UFN_ATTR] = minfo.user_first_name
                        args[OPR_ATTR] = 'set' if not force else 'upd'
                        #cert,_ = self.make_xcert(XCERT_PROTO,args)  
                        if self._user_notary is not None:
                            # ask real notary about this cert 
                            self.send_message(minfo.chat_id, f'Требуется проверка сертификата для {minfo.user_first_name} uid={minfo.user_id} info={args}.') 
                            self._approve_q[minfo.user_id] = args.copy()
                        else: 
                            # do it right now
                            #cert,_ = self.make_xcert(XCERT_PROTO,args)
                            proto = self.make_xcert_prof(XCERT_PROTO,args)
                            kyc = self._vault.create_xcert(proto,uid=minfo.user_id)                                                                              
                            if kyc is not None:                                                                                                                 
                                self.send_message(minfo.chat_id, f'Успешно {"изменен" if data else "создан"} сертификат доступа для {minfo.user_first_name} KYC={kyc}.')  
                                #await self.make_xcert_transaction('crt',str(minfo.user_id),cert,minfo)                 
                            else:                                                                                                                               
                                self.send_message(minfo.chat_id, f'Не смог выполнить запрос создания сертификата для {minfo.user_first_name}.')  
                except errors.VaultNotReady  :
                    self.send_message(minfo.chat_id, f'Нет доступа к хранилищу секретов.')
                                                                                                                                                        
            else:                                                                                                                                       
                self.send_message(minfo.chat_id, f'Нет доступа к BD секретов')                                                                                  
                return                                                                                                                                      

    def intent_show_xcert(self,minfo):                                                                                                                          
        """                                                                                                                                                             
        Get or show xcert for user who send this message                                                                                                              
        """                                                                                                                                                             
        LOGGER.debug(f'DgtTeleBot: show xcert FOR={minfo}')                                                                                                           
        if self._vault is not None:   
            try:
                data = self._vault.get_xcert(uid=minfo.user_id)                                                                                                         
                if data :  
                    kyc = data['data'][DID_ATTR] if DID_ATTR in data['data'] else minfo.user_id   
                    if XCERT_ATTR in data['data']:
                        del data['data'][XCERT_ATTR]
                    self.send_message(minfo.chat_id, f'Ваш сертификат KYC={kyc} XCERT={data} ')                                                                            
                else:                                                                                                                                                   
                    # create cert
                    self.send_message(minfo.chat_id, f'Ваш сертификат еще не существует') 
            except errors.VaultNotReady  :                                              
                self.send_message(minfo.chat_id, f'Нет доступа к хранилищу секретов.')  


        else:
            self.send_message(minfo.chat_id, f'Нет доступа к хранилищу секретов.') 
                
    def intent_approve_xcert(self,minfo):
        args = self.get_args_from_request(minfo.result.parameters) if minfo.result else {}       
        LOGGER.debug(f'DgtTeleBot: approve xcert args={args} {self._approve_q}')                                                                                   
                                                                                                                                                
        if UID_ATTR in args: 
            uid = int(args[UID_ATTR])                                                            
            
            if uid in self._approve_q:
                req = self._approve_q.pop(uid)
                chat_id = req[CID_ATTR]
                user_first_name = req[UFN_ATTR]
                self.send_message(chat_id, f'{user_first_name} Ваш запрос на сертификат одобрен')

                oper = req[OPR_ATTR]
                did = req[DID_ATTR]
                #cert,_ = self.make_xcert(XCERT_PROTO,req)
                proto = self.make_xcert_prof(XCERT_PROTO,req)                                                                                                           
                kyc = self._vault.create_xcert(proto,uid=req[UID_ATTR])                                                                                               
                if kyc is not None:                                                                                                                                  
                    self.send_message(chat_id, f'Успешно создан сертификат доступа для {user_first_name} KYC={kyc}.')         
                    #await self.make_xcert_transaction(oper,str(did),cert)                                                             
                else:                                                                                                                                                
                    self.send_message(chat_id, f'Не смог выполнить запрос создания сертификата для {user_first_name}.') 
            else:
                self.send_message(minfo.chat_id, f'Отсутствует запрос  сертификата от={uid}')


    async def _get_topology(self,minfo):
        """Fetches the topology from the validator.
        Request:

        Response:
            data: JSON array of net topology
            link: The link to this exact query
        """
        error_traps = [error_handlers.InvalidAddressTrap]
        response = await self._query_validator(
            Message.CLIENT_TOPOLOGY_GET_REQUEST,
            client_topology_pb2.ClientTopologyGetResponse,
            client_topology_pb2.ClientTopologyGetRequest(),
            error_traps)
        try:
            topology = json.loads(base64.b64decode(response['topology']))
            return topology
        except Exception as ex:                                                                                                                                                                                        
            LOGGER.debug('DgtTeleBot: cant load topology(%s)',ex)
            self.send_message(minfo.chat_id,'Что то пошло не так')
            return None

    async def intent_show_gateway(self,minfo):
        """Fetches the topology from the validator.
        Request:

        Response:
            data: JSON array of net topology
            link: The link to this exact query
        """
        topology = await self._get_topology(minfo)
        if topology:
            LOGGER.debug('Request fetch_topology=%s',topology['Identity'])
            repl = 'Работаю с узлом:\n{}.'.format(yaml.dump(topology['Identity'], default_flow_style=False)[0:-1])
            self.send_message(minfo.chat_id,repl)
        
        
    async def intent_show_gateway_list(self,minfo):
        try:
            repl = 'Доступные шлюзы:\n{}.'.format(yaml.dump(self._connects, default_flow_style=False)[0:-1])
            self.send_message(minfo.chat_id,repl)
        except Exception as ex:                                                                                                                                                                                        
            LOGGER.debug('DgtTeleBot: cant show list gate way(%s)',ex)
    
    async def intent_set_gateway(self,minfo):
        LOGGER.debug('DgtTeleBot: intent_set_gateway FOR=%s',minfo)                                                                                                    
        args = self.get_args_from_request(minfo.result.parameters)                                                                                               
        if 'number' in args : 
            num = int(user_stuff_name(args['number']))
            if self._connects and len(self._connects) >= num:
                LOGGER.debug('DgtTeleBot: gateway(%s)',self._connects[num-1])
                if self.change_gateway(num-1) :
                    self.send_message(minfo.chat_id,'Переключились на {}'.format(self._connects[num-1]))
                else:
                    self.send_message(minfo.chat_id,'Не удачное переключение на {}'.format(self._connects[num-1]))
            else:
                self.send_message(minfo.chat_id,'Нет такого шлюза')

    async def intent_peers_down(self,minfo):
        """
        send request for starting peer
        """
        LOGGER.debug('DgtTeleBot: intent_peers_down FOR=%s',minfo)                                                                                                    
        args = self.get_args_from_request(minfo.result.parameters)                                                                                               
        if 'number' in args and 'name' in args:
            cname,pname = args['name'],str(int(args['number']))
            LOGGER.debug('DgtTeleBot: STOP PEER (%s %s)',cname,pname)
            repl = await self._peers_control(args['name'],str(int(args['number'])),ClientPeersControlRequest.DOWN)
            self.send_message(minfo.chat_id,'Стоп узла:{} {} - {}'.format(cname,pname,repl))

    async def intent_peers_up(self,minfo):
        LOGGER.debug('DgtTeleBot: intent_peers_up FOR=%s',minfo)                                                                                                    
        args = self.get_args_from_request(minfo.result.parameters)                                                                                               
        if 'number' in args and 'name' in args:
            cname,pname = args['name'],str(int(args['number']))
            LOGGER.debug('DgtTeleBot: START PEER (%s %s)',cname,pname)
            repl = await self._peers_control(args['name'],str(int(args['number'])),ClientPeersControlRequest.UP)
            self.send_message(minfo.chat_id,'Запуск узла:{} {} - {}'.format(cname,pname,repl))

    async def intent_peers_control_list(self,minfo):
        LOGGER.debug('DgtTeleBot: intent_peers_control_list FOR=%s',minfo)
        topology = await self._get_topology(minfo)
        if topology:
            repl = 'Могу контролировать:\n{}.'.format(yaml.dump(topology['Control'], default_flow_style=False)[0:-1])
            self.send_message(minfo.chat_id,repl)

    async def intent_peer_info(self,minfo):
        LOGGER.debug('DgtTeleBot: intent_peer_info FOR=%s',minfo)                                                                                                    
        args = self.get_args_from_request(minfo.result.parameters)
        if 'cluster' in args and 'name' in args:
            cname,pname = args['cluster'],args['name']
            LOGGER.debug('DgtTeleBot: intent_peer_info FOR=%s.%s',cname,pname)
            repl = await self._peers_control(cname,pname,ClientPeersControlRequest.INFO)
            self.send_message(minfo.chat_id,'Состояние узла:{} {} - {}'.format(cname,pname,repl))

    async def check_batch_status(self,batch_id,minfo):
        error_traps = [error_handlers.StatusResponseMissing]                             
        validator_query =  client_batch_submit_pb2.ClientBatchStatusRequest(batch_ids=[batch_id])                                                    
        
        response = await self._query_validator(                                          
            Message.CLIENT_BATCH_STATUS_REQUEST,                                         
            client_batch_submit_pb2.ClientBatchStatusResponse,                           
            validator_query,                                                             
            error_traps)                                                                 
        
        data = self._drop_id_prefixes(self._drop_empty_props(response['batch_statuses']))                          
        batch = data[0]  
        LOGGER.debug('CLIENT_BATCH_STATUS_REQUEST:batch:%s', batch) 
        if batch['status'] == 'INVALID':
            self.send_message(minfo.chat_id, 'Сожалею {} не вышло ({}).'.format(minfo.user_first_name,batch['invalid_transactions'][0]['message']))
        elif batch['status'] == 'COMMITTED':
            self.send_message(minfo.chat_id, 'Ура {}, все получилось.'.format(minfo.user_first_name))
        elif batch['status'] == 'PENDING':
            self.send_message(minfo.chat_id, 'Придется немного подождать {}.'.format(minfo.user_first_name))
            self.intent_handler(minfo) # check again

        return batch                                                               

    def _get_token(self,wallet,key):
        def coin(token):
            balance = int(token['balance']  if 'balance' in token else 0)
            decimals = int(token['decimals']  if 'decimals' in token else 18)
            return round(balance * pow(10, decimals - 18),5)
         
        tokens = json.loads(wallet[key])
        amount = 0
        coin_code = ''
        for key in tokens:
            LOGGER.debug('DgtRouteHandler:_get_token group (%s)',key)
            token = json.loads(tokens[key])
            coin_code = coin_code + ',' + (token['group_code'] if 'group_code' in token else 'white')
            amount    = amount + coin(token)
        return coin_code,amount

    async def get_meta_token(self,request,coin_code = 'bgt'):
        """
        get meta token with label coin_code and corresponding wallet
        now use SMART_BGT_META as coin_code - FIX IT 
        """
        meta_token = await self._get_state_by_addr(request,SMART_BGT_META)
        if meta_token is None:
            return meta_token,''
        # create wallet and present some few token
        meta = json.loads(meta_token[SMART_BGT_META])
        LOGGER.debug('DgtRouteHandler:get_meta_token=%s key=%s',meta,meta[SMART_BGT_CREATOR_KEY])
        return meta_token,meta[SMART_BGT_CREATOR_KEY]
         

    def _wrap_error(self,request,code,mesg,title = 'Error'):
        return self._wrap_response(
                        request,
                        metadata={
                            'code': code,
                            'title' : title,
                            'message' : mesg
                        },
                        status=code
                        )

    async def _make_token_transfer(self,request,address_from,address_to,num_bgt,coin_code='bgt'):
        """
        Make transfer from wallet to wallet
        """
        
        payload_bytes = cbor.dumps({
            'Verb'   : 'transfer',
            'Name'   : address_from,
            'to_addr': address_to,
            'num_bgt': num_bgt,
            'group_id' : coin_code
        })
        LOGGER.debug('DgtRouteHandler: _make_token_transfer make payload=%s',payload_bytes)
        in_address = make_smart_bgt_address(address_from)
        out_address = make_smart_bgt_address(address_to)
        inputs =[in_address, out_address]   
        outputs=[in_address, out_address]
        transaction = self._create_transaction(payload_bytes,inputs,outputs)
        batch = self._create_batch([transaction])
        batch_id = batch.header_signature #batch_list.batches[0].header_signature

        # Query validator
        error_traps = [error_handlers.BatchInvalidTrap,error_handlers.BatchQueueFullTrap]
        validator_query = client_batch_submit_pb2.ClientBatchSubmitRequest(batches=[batch])
        LOGGER.debug('DgtRouteHandler: _make_token_transfer send batch_id=%s',batch_id)

        with self._post_batches_validator_time.time():
            await self._query_validator(
                Message.CLIENT_BATCH_SUBMIT_REQUEST,
                client_batch_submit_pb2.ClientBatchSubmitResponse,
                validator_query,
                error_traps)


        # Ask validator for batch status while it changes from PENDING
        pending_status = 'PENDING'
        status = ''
        while True:
            error_traps = [error_handlers.StatusResponseMissing]
            validator_query = \
                client_batch_submit_pb2.ClientBatchStatusRequest(
                    batch_ids=[batch_id])
            self._set_wait(request, validator_query)
            response = await self._query_validator(
                Message.CLIENT_BATCH_STATUS_REQUEST,
                client_batch_submit_pb2.ClientBatchStatusResponse,
                validator_query,
                error_traps)
            metadata = self._get_metadata(request, response)
            data = self._drop_id_prefixes(
                self._drop_empty_props(response['batch_statuses']))

            LOGGER.debug(f'CLIENT_BATCH_STATUS_REQUEST:metadata:{metadata} data={data}')
            
            batch = data[0]
            if batch['status'] != pending_status:
                status = batch['status']
                break
            time.sleep(2)


        # Build response envelope
        # link = self._build_url(request, path='/batch_statuses', id=batch_id)
        return status

    async def post_transfer(self, request):
        """
        make transfer from wallet to wallet
        """
        LOGGER.debug('DgtRouteHandler: post_transfer !!!')
        timer_ctx = self._post_batches_total_time.time()
        self._post_batches_count.inc()
        body = await request.json()

        LOGGER.debug('DgtRouteHandler: post_transfer body=(%s)',body)
        if 'data' not in body:
            raise errors.NoTransactionPayload()

        data = body['data']
        try:
            signed_payload = data['signed_payload']
            payload = data['payload']
            address_from = payload['address_from']
            address_to = payload['address_to']
            num_bgt    = payload['tx_payload']

        except KeyError:
            raise errors.BadTransactionPayload()
        coin_code    = payload['coin_code'] if 'coin_code' in payload else None
        # Verification of signed hashes
        """
        result = rest_api_utils.verify_signature(public_key_from, signed_payload, payload)
        if result != 1:
            raise errors.InvalidSignature()
        """

        address_from =  _base64url2public(address_from)
        try:
            address_to   =  _base64url2public(address_to)
        except errors.BadWalletAddress:
            LOGGER.debug('DgtRouteHandler: post_transfer  BadWalletAddress= %s',address_to)
            meta_token,meta_wallet = await self.get_meta_token(request,coin_code)
            if meta_token is None:
                raise errors.BadWalletAddress()
            LOGGER.debug('DgtRouteHandler: post_transfer to META WALLET=%s',meta_wallet)
            address_to = meta_wallet

        LOGGER.debug('DgtRouteHandler: post_transaction make payload=%s',payload)
        tx_status = await self._make_token_transfer(request,address_from,address_to,num_bgt,coin_code)
        # status = 202

        if tx_status != 'COMMITTED':
            raise errors.NotEnoughFunds()

        tx = {
            'timestamp': datetime.now().__str__(),
            'status': tx_status == 'COMMITTED',
            'tx_payload': num_bgt,
            'currency': payload['coin_code'],
            'address_from': address_from,
            'address_to': address_to,
            'fee': TRANSACTION_FEE,
            'tx_status': tx_status,
            'extra': 'post_transfer'
        }

        retval = self._wrap_response(
            request,
            # metadata={'link': link},
            metadata=tx,
            status=200)
        LOGGER.debug('DgtRouteHandler: post_transfer retval=%s',retval)
        timer_ctx.stop()
        return retval


    async def get_wallet(self, request):
        """
        get wallet balance
        """
        address = request.match_info.get(ADDRESS_ATTR, '')
        LOGGER.debug('DgtRouteHandler: get_wallet address=%s type=%s',address,type(address))
        address =  _base64url2public(address)

        LOGGER.debug('DgtRouteHandler: get_wallet public=(%s) type=%s',address,type(address))
        result = await self._get_state_by_addr(request,address)
        if result is None :
            return self._wrap_error(request,400,'There is no wallet for this public key.')
        status = 'Ok'
        coin_code,amount = self._get_token(result,address)
        """
            data={
                    'status': status,
                    'balance': {
                        'coin_code' : coin_code,
                        'amount'    : amount
                    }
                }
        """
        return self._wrap_response(
            request,
            metadata={
                'wallet': {
                        'coin_code' : coin_code,
                        'amount'    : amount,
                        'bgt'       : amount
                    }
            }
            )
            
            

    # First iteration of implementation
    async def post_wallet(self, request):
        """
        create new wallet for public_key
        """
        if 'public_key' not in request.headers:
            LOGGER.debug('Submission header public_key is mandatory')
            raise errors.NoMandatoryHeader()
        public_key = request.headers['public_key']

        # convert  public_key to base64url for using it into url /wallets/addr
        user_address = _public2base64url(public_key)
        wallet = await self._get_state_by_addr(request,public_key)
        if wallet is None:
            LOGGER.debug('DgtRouteHandler:post_wallet CREATE NEW WALLET') 
            meta_token,meta_wallet = await self.get_meta_token(request)
            if meta_token is not None:
                # create wallet and present some few 'bgt' token as default 
                # make transfer to new wallet
                tx_status = await self._make_token_transfer(request,meta_wallet,public_key,SMART_BGT_PRESENT_AMOUNT)
                LOGGER.debug('DgtRouteHandler:post_wallet tx_status=%s',tx_status)
                # SHOULD DO waiting until wallet was created
                #wallet = await self._get_state_by_addr(request,public_key)
                status = "Wallet WAS CREATED"
                coin_code = 'white'
                amount    = 0

            else: # we must do emmission before
                return self._wrap_error(request,400,'Emmission must be done before')
        else:
            LOGGER.debug('DgtRouteHandler:post_wallet ALREADY CREATED wallet(%s)',wallet)
            status = "Wallet ALREADY CREATED"
            coin_code,amount = self._get_token(wallet,public_key)
            


        return self._wrap_response(
            request,
            metadata={
                user_address: {
                    'status': status,
                    'wallet': {
                        'coin_code' : coin_code,
                        'amount'    : amount,
                        'bgt'       : amount
                    }
                }
            },
            status=200)

    async def get_fee(self, request):
        body = await request.json()

        if 'data' not in body or 'payload' not in body['data']:
            raise errors.NoTransactionPayload()

        payload = body['data']['payload']

        return self._wrap_response(
            request,
            metadata={
                'fee': TRANSACTION_FEE,
                'payload': payload
            },
            status=200)

    async def get_global_transactions(self, request):
        """
        DONT USE now instead list_transactions handler
        """
        LOGGER.debug('list_transactions for validator')

        paging_controls = self._get_paging_controls(request)
        validator_query = client_transaction_pb2.ClientTransactionListRequest(
            head_id=self._get_head_id(request),
            transaction_ids=self._get_filter_ids(request),
            sorting=self._get_sorting_message(request, "default"),
            paging=self._make_paging_message(paging_controls))

        response = await self._query_validator(
            Message.CLIENT_TRANSACTION_LIST_REQUEST,
            client_transaction_pb2.ClientTransactionListResponse,
            validator_query)

        data = [self._expand_transaction(t) for t in response['transactions']]

        transactions = [cbor.loads(base64.b64decode(tx['payload'])) for tx in data]
        # transactions = list(filter(lambda tx: 'Verb' in tx and tx['Verb'] == 'transfer',
        #                            [cbor.loads(base64.b64decode(tx['payload'])) for tx in data]))

        result_list = []
        for tx in transactions:
            if not isinstance(tx, dict) or \
                    'Verb' not in tx or \
                    tx['Verb'] != 'transfer':
                continue
            result_tx = {
                    'timestamp': datetime.now().__str__(),
                    'status': True,
                    'tx_payload': tx['num_bgt'],
                    'currency': tx['group_id'],
                    'address_from': tx['Name'],
                    'address_to': tx['to_addr'],
                    'fee': 0.1,
                    'extra': 'extra information'
                }
            try:
                result_tx['address_from'] = _public2base64url(result_tx['address_from'])
            except:
                pass

            try:
                result_tx['address_to'] = _public2base64url(result_tx['address_to'])
            except:
                pass

            result_list.append(result_tx)

        LOGGER.debug('get_global_transactions result_list=%s',result_list)
        return self._wrap_response(
            request,
            metadata={
                'transactions': result_list
            },
            status=200)

    async def post_add_funds(self, request):
        body = await request.json()

        if 'data' not in body:
            raise errors.NoTransactionPayload()

        data = body['data']
        try:
            signed_payload = data['signed_payload']
            payload = data['payload']
            address_to = payload['address_to']
            reason = payload['reason']
            bgt_num = payload['tx_payload']
            coin_code = payload['coin_code']


        except KeyError:
            raise errors.BadTransactionPayload()

        
        LOGGER.debug('DgtRouteHandler:post_add_funds payload(%s)',payload)    
        public_key_to =  _base64url2public(address_to)
        wallet = await self._get_state_by_addr(request,public_key_to)
        if wallet is None:
            LOGGER.debug('DgtRouteHandler:post_add_funds wallet(%s) not found',address_to)
            raise errors.WalletNotFound()
        # check emmission
        meta_token,meta_wallet = await self.get_meta_token(request,coin_code)
        if meta_token is not None:
            LOGGER.debug('DgtRouteHandler:post_add_funds key=%s bgt_num=%s reason=%s',meta_wallet,bgt_num,reason) 
            # make transfer to  public_key_to wallet
            tx_status = await self._make_token_transfer(request,meta_wallet,public_key_to,bgt_num,coin_code)
        else:
            return self._wrap_error(request,400,'Emmission must be done before')
        # Verification of signed hashes
        #result = rest_api_utils.verify_signature(public_key_to, signed_payload, payload)
        #if result != 1:
        #    raise errors.InvalidSignature()

        tx = {
            'timestamp': datetime.now().__str__(),
            'status': True,
            'tx_payload': bgt_num,
            'currency': coin_code,
            'address_to': address_to,
            'fee': TRANSACTION_FEE,
            'tx_status': tx_status,
            'extra': 'post_transfer'
        }

        return self._wrap_response(
            request,
            metadata=tx,
            status=200)

        # return self._wrap_response(
        #     request,
        #     metadata=link,
        #     status=200)

