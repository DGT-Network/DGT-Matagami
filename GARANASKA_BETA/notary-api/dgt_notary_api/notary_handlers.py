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
from datetime import datetime
import uuid
from aiohttp import web
import traceback
# pylint: disable=no-name-in-module,import-error
# needed for the google.protobuf imports to pass pylint
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError



import dgt_notary_api.exceptions as errors
from dgt_notary_api import error_handlers
from dgt_notary_api.messaging import DisconnectError
from dgt_notary_api.messaging import SendBackoffTimeoutError

from dgt_sdk.protobuf.validator_pb2 import Message
from dgt_sdk.protobuf import client_transaction_pb2
from dgt_sdk.protobuf import client_list_control_pb2
from dgt_sdk.protobuf import client_batch_submit_pb2
from dgt_sdk.protobuf import client_state_pb2
from dgt_sdk.protobuf import client_block_pb2
from dgt_sdk.protobuf import client_batch_pb2
from dgt_sdk.protobuf import client_receipt_pb2
from dgt_sdk.protobuf import client_peers_pb2
from dgt_sdk.protobuf import client_status_pb2
from dgt_sdk.protobuf.block_pb2 import BlockHeader
from dgt_sdk.protobuf.batch_pb2 import Batch,BatchHeader,BatchList
from dgt_sdk.protobuf.transaction_pb2 import Transaction,TransactionHeader
"""
from dgt_sdk.protobuf.notary_pb2 import NotaryRequest
"""
from dgt_notary_api.route_handlers import RouteHandler,DEFAULT_TIMEOUT
import cbor


from dgt_signing import CryptoFactory,create_context

from smart_bgt.processor.utils import FAMILY_NAME as SMART_BGX_FAMILY
from smart_bgt.processor.utils import FAMILY_VER as SMART_BGX_VER
from smart_bgt.processor.utils import SMART_BGT_META,SMART_BGT_CREATOR_KEY,SMART_BGT_PRESENT_AMOUNT
from smart_bgt.processor.utils import make_smart_bgt_address
# bgt families                                                                               
from dgt_bgt.client_cli.generate import BgtPayload,create_bgt_transaction,loads_bgt_token    
from dgt_bgt.processor.handler import make_bgt_address, make_bgt_prefix 
from cert_common.protobuf.x509_cert_pb2 import X509CertInfo  
from x509_cert.client_cli.xcert_attr import *
from x509_cert.client_cli.exceptions import VaultNotReady
from dec_dgt.client_cli.dec_attr import (DEC_HEADER_PAYLOAD,DEC_PAYLOAD,DEC_HEADER_SIGN,DEC_CMD_OPTS,DEC_TRANS_OPTS,DEC_EMITTER,DEC_NOTARY_REQ_SIGN) 
                                                                                                                        
                                                                                                                        
                                   
import time
LOGGER = logging.getLogger(__name__)

TRANSACTION_FEE = 0.1
APPROVAL_KEY = "akey"
APPROVE_MODE = "approve"
STATUS_MODE = "status"
DELETE_MODE = "delete"
REQ_PAYLOAD = 'payload'
REQ_STATUS =  'req_status'
REQ_DGT_LINK      =  'dgt_link'
REQ_STATUS_QUEUE  = 'QUEUE'
REQ_STATUS_DEL  = 'DROPPED'
REQ_STATUS_PENDING  = 'PENDING'
REQ_STATUS_DGT_PENDING  = 'DGT_PENDING'
DGT_COMMIT = 'COMMITTED'
DGT_ERROR  = 'ERROR'

def _sha512(data):
    return hashlib.sha512(data).hexdigest()

def _base64url2public(addr):
    try:
        return base64.urlsafe_b64decode(addr).decode("utf-8") 
    except :
        raise errors.BadWalletAddress()
        

def _public2base64url(key):
    return base64.urlsafe_b64encode(key.encode()).decode('utf-8')

class NotaryRouteHandler(RouteHandler):
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

    def __init__(self, loop, connection,timeout=DEFAULT_TIMEOUT, metrics_registry=None,vault=None,db=None):

        super().__init__(loop,connection,timeout,metrics_registry)
        # BGX init
        self._context = create_context('secp256k1') 
        self._private_key = self._context.new_random_private_key()
        self._public_key = self._context.get_public_key(self._private_key)
        self._crypto_factory = CryptoFactory(self._context)
        self._signer = self._crypto_factory.new_signer(self._private_key)
        self._vault = vault
        self._db = db
        """
        keep user request for notary
        """
        LOGGER.debug('NotaryRouteHandler: _signer PUBLIC_KEY={} DB={}'.format(self._public_key.as_hex()[:8],self._db))

    async def show_xcert(self, request):                                                                
        """                                    
        """                                                                                              
                                                                                                         
        #address = request.match_info.get('id', '')                                                  
        name = request.url.query.get(UID_ATTR, None)                                                       
        LOGGER.debug('show xcert name={}'.format(name))                       
        #FIXME for DAG we should ask real merkle root  
        try:
            data = self._vault.get_xcert(uid=name) 
        except  VaultNotReady:
            return self._wrap_response(request,data="Notary not ready")

        if data:
            data = data['data']
            if XCERT_ATTR in data:
                del data[XCERT_ATTR]
        return self._wrap_response(                                                                      
            request,                                                                                     
            data=data if data else "undefined secret {}".format(name),                                                                      
            metadata=None)                                   

    async def list_xcert(self, request):                    
        """                                                 
        """                                                 
        #address = request.match_info.get('id', '')         
        #name = request.url.query.get('name', None)          
        LOGGER.debug('list xcert')     
        #FIXME for DAG we should ask real merkle root   
        results = self._vault.list() 
        token = X509CertInfo()
        res = {}                                                                  
        for pair in results:                                                                      
            for name, value in pair.items():                                                      
                token.ParseFromString(value)                                                      
                xcert = self._vault.load_xcert(token.xcert)   
                res[name] = {'valid' : {'before' : xcert.not_valid_before.strftime("%m/%d/%Y, %H:%M:%S"),
                                        'after' : xcert.not_valid_after.strftime("%m/%d/%Y, %H:%M:%S")
                                        }
                            }                                         
                

        return self._wrap_response(                         
            request,                                        
            data=res,                   
            metadata=None)                                  
                                                            
    async def crt_xcert(self, request):                                                         
        """                                                                                      
        """                                                                                      
                                                                                                 
        #address = request.match_info.get('id', '')                                              
        email = request.url.query.get(EMAIL_ATTR, "your@mail")
        addr = request.url.query.get(ADDRESS_ATTR, "your address")
        uid = request.url.query.get(UID_ATTR, uuid.uuid4())                                               
        LOGGER.debug('crt xcert email={}'.format(email))                                          
        #FIXME for DAG we should ask real merkle root                                            
        #data = self._vault.get_xcert(uid=name)    
        proto = self._vault.make_xcert_prof({EMAIL_ATTR:email,ADDRESS_ATTR:addr,UID_ATTR:uid})                                               
        kyc = self._vault.create_xcert(proto,uid=uid)
        return self._wrap_response(                                                              
            request,                                                                             
            data="Create secret KYC={} UID={}".format(kyc,uid) if kyc else "Cant create xcert ",                           
            metadata=None)  
                                                                         
    async def upd_xcert(self, request):                                                                                       
        """                                                                                                                   
        """                                                                                                                   
                                                                                                                              
        #address = request.match_info.get('id', '') 
        email = request.url.query.get(EMAIL_ATTR,None)                                                                
        addr = request.url.query.get(ADDRESS_ATTR,None)                                                            
        uid = request.url.query.get(UID_ATTR,None) 
        country = request.url.query.get(COUNTRY_ATTR,None) 
        kyc = None                                                                
        LOGGER.debug('update xcert UID={}'.format(uid)) 
        if uid:
            try:                                                             
                data = self._vault.get_xcert(uid=uid)                       
            except  VaultNotReady:                                           
                return self._wrap_response(request,data="Notary not ready")  

            if data :               
                if XCERT_ATTR in data['data']:    
                    del data['data'][XCERT_ATTR] 
                proto = self._vault.make_xcert_prof({EMAIL_ATTR:email,ADDRESS_ATTR:addr,UID_ATTR:uid,COUNTRY_ATTR:country},proto_xcert=data['data'])   
                kyc = self._vault.create_xcert(proto,uid=uid)                                            


        return self._wrap_response(                                                                                           
            request,                                                                                                          
            data="Update secret KYC={} UID={}".format(kyc,uid) if kyc else "Cant update xcert for {}".format(uid),                              
            metadata=None)                                                                                                    

    async def wallets(self, request):                                                                                                                                         
        """  
        show wallets list                                                                                                                                                                   
        """                                                                                                                                                                     
        did = request.url.query.get(DID_ATTR,None)                                                                                                                              
        LOGGER.debug('print wallets  for DID={}'.format(did))                                                                                                                         
        if did:                                                                                                                                                                 
            try:                                                                                                                                                                
                wallets = self._vault.get_wallets(did)  
                return self._wrap_response(                                                                   
                    request,                                                                                  
                    data="Wallets={} for DID={}".format(wallets,did), 
                    metadata=None)                                                                            
                                                                                                              
                                                                                                                                         
            except  VaultNotReady:                                                                                                                                              
                return self._wrap_response(request,data="Notary not ready")                                                                                                     
            
        else:
                                                                                                                                                                                
            return self._wrap_response(                                                                                                                                             
                request,                                                                                                                                                            
                data="Cant show wallets for DID={}".format(did),                                                              
                metadata=None)                                                                                                                                                      

    async def roles(self, request):                                                        
        """                                                                                  
        show role list                                                                    
        """                                                                                  
        did = request.url.query.get(DID_ATTR,None)                                           
        LOGGER.debug('print roles  for DID={}'.format(did))                                
        if did:                                                                              
            try:                                                                             
                roles = self._vault.get_roles(did)                                       
                return self._wrap_response(                                                  
                    request,                                                                 
                    data="Roles={} for DID={}".format(roles,did),                        
                    metadata=None)                                                           
                                                                                             
                                                                                             
            except  VaultNotReady:                                                           
                return self._wrap_response(request,data="Notary not ready")                  
                                                                                             
        else:                                                                                
                                                                                             
            return self._wrap_response(                                                      
                request,                                                                     
                data="Cant show roles for DID={}".format(did),                             
                metadata=None)                                                               
                                                                                             
    async def goods(self, request):                                                               
        """                                                                                       
        show role list                                                                            
        """                                                                                       
        did = request.url.query.get(DID_ATTR,None)                                                
        LOGGER.debug('print goods  for DID={}'.format(did))                                       
        if did:                                                                                   
            try:                                                                                  
                goods = self._vault.get_goods(did)                                                
                return self._wrap_response(                                                       
                    request,                                                                      
                    data="Goods={} for DID={}".format(goods,did),                                 
                    metadata=None)                                                                
                                                                                                  
                                                                                                  
            except  VaultNotReady:                                                                
                return self._wrap_response(request,data="Notary not ready")                       
                                                                                                  
        else:                                                                                     
                                                                                                  
            return self._wrap_response(                                                           
                request,                                                                          
                data="Cant show goods for DID={}".format(did),                                    
                metadata=None)                                                                    
                                                                                                  
    async def approvals(self, request):
        """                           
        show list for  approvals                
        """ 
        LOGGER.debug('print APPROVALS INFO')
        alist = self._db.keys() 
        """                         
        with self._db.cursor() as curs:            
            for val in curs.iter():                 
                alist.append(val)
        """
        return self._wrap_response(                                  
                  request,                                                 
                  data=alist,            
                  metadata=None
            )    
                                           
    async def approval(self, request):                                                             
        """                                                                                     
        show approval info                                                                          
        """                                                                                     
        akey = request.url.query.get(APPROVAL_KEY,None) 
        is_approve = request.url.query.get(APPROVE_MODE,"0") != "0"  
        is_status = request.url.query.get(STATUS_MODE,"0") != "0"
        is_delete = request.url.query.get(DELETE_MODE,"0") != "0"
                                                  
        LOGGER.debug('APPROVAL INFO  for {} approve={} status={} delete={}'.format(akey,is_approve,is_status,is_delete))                                     
        if akey:   
            aval = self._db.get(akey)
             
            if aval :
                if akey == 'ROOT':
                    data_val = aval
                elif REQ_PAYLOAD in aval:
                    if is_approve:
                        status = aval[REQ_STATUS]
                        if status not in [REQ_STATUS_QUEUE,DGT_ERROR]:
                            raise errors.BadRequestStatus()

                        data_val = aval[REQ_PAYLOAD].hex() 
                        LOGGER.debug('approve={}'.format(data_val)) 
                    elif is_delete :
                        self._db.update([],[akey])
                        data_val = {REQ_STATUS: REQ_STATUS_DEL }
                    else:
                        # check status or send info 
                        freq = cbor.loads(aval[REQ_PAYLOAD])
                        nreq = cbor.loads(freq[DEC_CMD_OPTS][DEC_PAYLOAD])
                        dgt_link = aval[REQ_DGT_LINK] if REQ_DGT_LINK in aval else None
                        curr_status = aval[REQ_STATUS]
                        LOGGER.debug('Curr status={}'.format(curr_status))
                        #self._vault.notary_approve_vault(freq,nreq)

                        if dgt_link is not None and is_status:
                            if curr_status == REQ_STATUS_PENDING:
                                # check DGT transaction status
                                status = self._vault._get_status(dgt_link,1)
                                LOGGER.debug('check transaction url={} status={}'.format(dgt_link,status))
                                if aval[REQ_STATUS] != status:
                                    aval[REQ_STATUS] = status
                                    if status == DGT_COMMIT:
                                        self._vault.notary_approve_vault(aval[REQ_PAYLOAD])

                                    self._db.update([(akey, {'qid' : akey,REQ_PAYLOAD : aval[REQ_PAYLOAD], REQ_STATUS : status,REQ_DGT_LINK:dgt_link})],[])
                            elif curr_status in [ DGT_ERROR,"{"]:
                                # send again into DGT 
                                LOGGER.debug('Send request again into DGT={}'.format(akey))
                                res = self.ask_dgt_approve(akey,aval[REQ_PAYLOAD])
                                aval[REQ_STATUS] = res[0]
                                dgt_link = res[1]

                                    # update info 
                        data_val = {REQ_STATUS: aval[REQ_STATUS],REQ_PAYLOAD: nreq,REQ_DGT_LINK: dgt_link }

                else:
                    data_val = "No {} approval for={}".format(REQ_PAYLOAD,akey)

            else :
                data_val = "No such approval for={}".format(akey) 
                                                                                       
                                                                                                
        else:
            data_val = "Set argument 'akey'"                                                                                   
                                                                                                
        return self._wrap_response(                                                         
            request,                                                                        
            data=data_val,                                  
            metadata=None)                                                                  
    
    async def balanceof(self, request):                                        
        """                                                                  
        show wallet balance                                                    
        """                                                                  
        pkey = request.url.query.get(WALLET_PKEY,None)                           
        LOGGER.debug('print wallet ballance  for PUB KEY={}'.format(pkey))                
        if pkey:                                                              
            try:                                                             
                balance = self._vault.get_balance_of(pkey)                       
                return self._wrap_response(                                  
                    request,                                                 
                    data="Wallet balance={}".format(balance.decimals),        
                    metadata=None)                                           
                                                                             
                                                                             
            except  VaultNotReady:                                           
                return self._wrap_response(request,data="Notary not ready")  
                                                                             
        else:                                                                
                                                                             
            return self._wrap_response(                                      
                request,                                                     
                data="Cant show wallet balance for KEY={}".format(pkey),             
                metadata=None)                                               







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

    def _create_transaction(self,payload,inputs,outputs,dependencies=[]):
        """
        make transaction
        """
        LOGGER.debug('NotaryRouteHandler: _create_transaction make Transaction')
        txn_header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name=SMART_BGX_FAMILY,
            family_version=SMART_BGX_VER,
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
        LOGGER.debug('NotaryRouteHandler:_get_state_by_addr %s',address)
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
        LOGGER.debug('NotaryRouteHandler:_get_state_by_addr %s',address)
        try:
            result = cbor.loads(base64.b64decode(response['value']))
            LOGGER.debug('NotaryRouteHandler: _get_state_by_addr result=%s',type(result))
        except BaseException:
            LOGGER.debug('NotaryRouteHandler: Cant get state FOR=%s',address)
            return None
        return result

    async def run_transaction(self, request):                                                                                                      
        """                                                                                                                                        
        make transfer from wallet to wallet                                                                                                        
        """                                                                                                                                        
        family = request.url.query.get('family', None)                                                                                             
        if family == 'bgt' :                                                                                                                       
            cmd = request.url.query.get('cmd', None)                                                                                               
            arg1 = request.url.query.get('wallet', None)                                                                                           
            if cmd == 'show':                                                                                                                      
                address = make_bgt_address(arg1)                                                                                                   
                error_traps = [error_handlers.InvalidAddressTrap,error_handlers.StateNotFoundTrap]                                                 
                response = await self._query_validator(                                                                                            
                    Message.CLIENT_STATE_GET_REQUEST,                                                                                              
                    client_state_pb2.ClientStateGetResponse,                                                                                       
                    client_state_pb2.ClientStateGetRequest(                                                                                        
                        state_root='',                                                                                                             
                        address=address),                                                                                                          
                    error_traps)                                                                                                                   
                LOGGER.debug('run_transaction: BGT show=%s (%s)!',arg1,response)                                                                   
                if response['status'] == 'OK':                                                                                                     
                    bgt = loads_bgt_token(response['value'],arg1)                                                                                  
                    LOGGER.debug('run_transaction: BGT[%s]=%s!',arg1,bgt)                                                                          
                else:                                                                                                                              
                    bgt = response['value']                                                                                                        
                return self._wrap_response(                                                                                                        
                    request,                                                                                                                       
                    data=bgt,                                                                                                                      
                    metadata=self._get_metadata(request, response))                                                                                
            elif  cmd == 'list' :
                paging_controls = self._get_paging_controls(request)                           
                # for DAG ask head of chain for getting merkle root is incorrect way           
                # FIXME - add special method for asking real merkle root                       
                head, root = await self._head_to_root(request.url.query.get('head', None))     
                LOGGER.debug('LIST_STATE STATE=%s',root[:10])                                  
                                                                                               
                validator_query = client_state_pb2.ClientStateListRequest(                     
                    state_root='',
                    address=make_bgt_prefix(),                            
                    sorting=self._get_sorting_message(request, "default"),                     
                    paging=self._make_paging_message(paging_controls))                         
                                                                                               
                response = await self._query_validator(                                        
                    Message.CLIENT_STATE_LIST_REQUEST,                                         
                    client_state_pb2.ClientStateListResponse,                                  
                    validator_query)                                                           
                 
                if response['status'] == 'OK':
                    decoded = []
                    for entry in response['entries']:
                        bgt = loads_bgt_token(entry["data"])      
                        LOGGER.debug(f'BGT LIST DATA={bgt}')
                        decoded.append(bgt)
                    response['entries'] = decoded

                return self._wrap_paginated_response(                                          
                    request=request,                                                           
                    response=response,                                                         
                    controls=paging_controls,                                                  
                    data=response.get('entries', []),                                          
                    head=head)                                                                 

                                                                                                                                                   
            arg2 = request.url.query.get('amount', None)                                                                                           
            arg3 = request.url.query.get('to', None)                                                                                               
            LOGGER.debug('run_transaction family=%s cmd=%s(%s,%s) query=%s!!!',family,cmd,arg1,arg2,request.url.query)                             
            transaction = create_bgt_transaction(verb=cmd,name=arg1,value=int(arg2),signer=self._signer,to=arg3)                                   
            batch = self._create_batch([transaction])                                                                                              
            batch_id = batch.header_signature                                                                                                      
        else:                                                                                                                                      
            # undefined families                                                                                                                   
            batch_id = None                                                                                                                        
            link = ''                                                                                                                              
                                                                                                                                                   
        if batch_id is not None:                                                                                                                   
            error_traps = [error_handlers.BatchInvalidTrap,error_handlers.BatchQueueFullTrap]                                                      
            validator_query = client_batch_submit_pb2.ClientBatchSubmitRequest(batches=[batch])                                                    
            LOGGER.debug('run_transaction send batch_id=%s',batch_id)                                                                              
                                                                                                                                                   
            with self._post_batches_validator_time.time():                                                                                         
                await self._query_validator(                                                                                                       
                    Message.CLIENT_BATCH_SUBMIT_REQUEST,                                                                                           
                    client_batch_submit_pb2.ClientBatchSubmitResponse,                                                                             
                    validator_query,                                                                                                               
                    error_traps)                                                                                                                   
            link = self._build_url(request, path='/batch_statuses', id=batch_id)                                                                   
        return self._wrap_response(                                                                                                                
            request,                                                                                                                               
            data=None,                                                                                                                             
            metadata={                                                                                                                             
              'link': link,                                                                                                                        
            }                                                                                                                                      
            )                                                                                                                                      



    def _get_token(self,wallet,key):
        def coin(token):
            balance = int(token['balance']  if 'balance' in token else 0)
            decimals = int(token['decimals']  if 'decimals' in token else 18)
            return round(balance * pow(10, decimals - 18),5)
         
        tokens = json.loads(wallet[key])
        amount = 0
        coin_code = ''
        for key in tokens:
            LOGGER.debug('NotaryRouteHandler:_get_token group (%s)',key)
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
        LOGGER.debug('NotaryRouteHandler:get_meta_token=%s key=%s',meta,meta[SMART_BGT_CREATOR_KEY])
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
        LOGGER.debug('NotaryRouteHandler: _make_token_transfer make payload=%s',payload_bytes)
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
        LOGGER.debug('NotaryRouteHandler: _make_token_transfer send batch_id=%s',batch_id)

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

            LOGGER.debug('CLIENT_BATCH_STATUS_REQUEST:metadata:%s', metadata)
            LOGGER.debug('CLIENT_BATCH_STATUS_REQUEST:data:%s', data)
            batch = data[0]
            if batch['status'] != pending_status:
                status = batch['status']
                break
            time.sleep(5)


        # Build response envelope
        # link = self._build_url(request, path='/batch_statuses', id=batch_id)
        return status

    async def post_transfer(self, request):
        """
        make transfer from wallet to wallet
        """
        LOGGER.debug('NotaryRouteHandler: post_transfer !!!')
        timer_ctx = self._post_batches_total_time.time()
        self._post_batches_count.inc()
        body = await request.json()

        LOGGER.debug('NotaryRouteHandler: post_transfer body=(%s)',body)
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
            LOGGER.debug('NotaryRouteHandler: post_transfer  BadWalletAddress= %s',address_to)
            meta_token,meta_wallet = await self.get_meta_token(request,coin_code)
            if meta_token is None:
                raise errors.BadWalletAddress()
            LOGGER.debug('NotaryRouteHandler: post_transfer to META WALLET=%s',meta_wallet)
            address_to = meta_wallet

        LOGGER.debug('NotaryRouteHandler: post_transaction make payload=%s',payload)
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
        LOGGER.debug('NotaryRouteHandler: post_transfer retval=%s',retval)
        timer_ctx.stop()
        return retval


    async def get_wallet(self, request):
        """
        get wallet balance
        """
        address = request.match_info.get('address', '')
        LOGGER.debug('NotaryRouteHandler: get_wallet address=%s type=%s',address,type(address))
        address =  _base64url2public(address)

        LOGGER.debug('NotaryRouteHandler: get_wallet public=(%s) type=%s',address,type(address))
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
            LOGGER.debug('NotaryRouteHandler:post_wallet CREATE NEW WALLET') 
            meta_token,meta_wallet = await self.get_meta_token(request)
            if meta_token is not None:
                # create wallet and present some few 'bgt' token as default 
                # make transfer to new wallet
                tx_status = await self._make_token_transfer(request,meta_wallet,public_key,SMART_BGT_PRESENT_AMOUNT)
                LOGGER.debug('NotaryRouteHandler:post_wallet tx_status=%s',tx_status)
                # SHOULD DO waiting until wallet was created
                #wallet = await self._get_state_by_addr(request,public_key)
                status = "Wallet WAS CREATED"
                coin_code = 'white'
                amount    = 0

            else: # we must do emmission before
                return self._wrap_error(request,400,'Emmission must be done before')
        else:
            LOGGER.debug('NotaryRouteHandler:post_wallet ALREADY CREATED wallet(%s)',wallet)
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

        
        LOGGER.debug('NotaryRouteHandler:post_add_funds payload(%s)',payload)    
        public_key_to =  _base64url2public(address_to)
        wallet = await self._get_state_by_addr(request,public_key_to)
        if wallet is None:
            LOGGER.debug('NotaryRouteHandler:post_add_funds wallet(%s) not found',address_to)
            raise errors.WalletNotFound()
        # check emmission
        meta_token,meta_wallet = await self.get_meta_token(request,coin_code)
        if meta_token is not None:
            LOGGER.debug('NotaryRouteHandler:post_add_funds key=%s bgt_num=%s reason=%s',meta_wallet,bgt_num,reason) 
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

    async def notary_req(self, request):  
        """
        User ask notary sign
        """                                                                                                                  
        if request.headers['Content-Type'] != 'application/octet-stream':                                           
            LOGGER.debug('Submission headers had wrong Content-Type: %s',request.headers['Content-Type'])                                                                    
            raise errors.SubmissionWrongContentType()                                                               
                                                                                                                    
        body = await request.read()                                                                                 
        if not body:                                                                                                
            LOGGER.debug('Submission contained an empty body')                                                      
            raise errors.NoBatchesSubmitted()                                                                       
                                                                                                                    
        try:                                                                                                        
            nreq = cbor.loads(body)
            if not isinstance(nreq,dict) or DEC_CMD_OPTS not in nreq:
                LOGGER.debug('Wrong payload  request={}'.format(nreq))      
                raise errors.BadRequestPayload()                               

            opts = nreq[DEC_CMD_OPTS]
            ret = self._signer.verify(opts[DEC_NOTARY_REQ_SIGN], opts[DEC_PAYLOAD],self._context.pub_from_hex(opts[DEC_EMITTER]) )
            if not ret:
                LOGGER.debug('Wrong sign for request={}'.format(opts))        
                raise errors.BadRequestSign()                                   


            tstamp = datetime.now().__str__() 

            LOGGER.debug('{} : CHECK={} Request {}'.format(tstamp,ret,nreq)) 
            data = {'key' : tstamp,REQ_STATUS : REQ_STATUS_QUEUE}
            self._db.put(tstamp, {'qid' : tstamp,REQ_PAYLOAD : body,REQ_STATUS : REQ_STATUS_QUEUE}) 
                                                                                
        except DecodeError:                                                                                         
            LOGGER.debug('Submission body could not be decoded: %s', body)                                          
            raise errors.BadProtobufSubmitted()                                                                     


                                                                                                                                                             
        return self._wrap_response(                                                                                                                             
            request,
            data=data,                                                                                                                                            
            metadata=None,                                                                                                                                        
            status=200)   
    
    async def notary_approve(self, request): 
        
        akey = request.url.query.get(APPROVAL_KEY,None) 

        LOGGER.debug('APPROVE  for {}'.format(akey))
        if akey:                                                                          
            aval = self._db.get(akey)                                                     
            data_val = "Request status {} incorrect for={}".format(aval[REQ_STATUS],akey) if aval and aval[REQ_STATUS] != REQ_STATUS_QUEUE else "No such approval request for={}".format(akey)           
                                                                                          
        else:                                                                             
            data_val = "Set argument 'akey'" 
            aval = None                                             

        if aval is None:
            # error
            return self._wrap_response(           
                request,                          
                data=data_val,                    
                metadata=None)                    

        # take request from queue

        if request.headers['Content-Type'] != 'application/octet-stream':        
            LOGGER.debug('Submission headers had wrong Content-Type: %s',request.headers['Content-Type'])                                 
            raise errors.SubmissionWrongContentType()                            
                                                                                 
        body = await request.read()                                              
        if not body:                                                             
            LOGGER.debug('Submission contained an empty body')                   
            raise errors.NoBatchesSubmitted()                                    
                                                                                 
        try:                                                                     
            res = self.ask_dgt_approve(akey,body)
            
        except DecodeError:                                                      
            LOGGER.debug('Submission body could not be decoded: %s', body)       
            raise errors.BadProtobufSubmitted()                                  
                                                                                 
                                                                                 
                                                                                 
        return self._wrap_response(                                              
            request,  
            data=res,                                                           
            metadata=None,                                                       
            status=200)        
    
    def ask_dgt_approve(self,akey,body):
        #LOGGER.debug('ask_dgt_approve: body={}'.format(type(body)))
        try:
            areq_val = cbor.loads(body)
            res = self._vault.notary_approve(areq_val)                                                                                            
            LOGGER.debug('{} : Approve Request RES={}'.format(akey,res))                                                          
            if res[0] == DGT_COMMIT:                                                                                                              
                # was commited                                                                                                                    
                self._vault.notary_approve_vault(areq_val)                                                                                        
            elif res[0] == DGT_ERROR:                                                                                                             
                # already signed but not accepted DGT net                                                                                         
                LOGGER.debug('{} : Approve Request ERROR'.format(akey))                                                                           
            self._db.update([(akey, {'qid' : akey,REQ_PAYLOAD : body, REQ_STATUS : res[0],REQ_DGT_LINK:res[1]})],[])   # REQ_STATUS_DGT_PENDING 
            return res
        except Exception as ex:
            LOGGER.debug('ask_dgt_approve: body={} - error={} TB={}'.format(type(body),ex,traceback.format_exc()))
            return (DGT_ERROR,'')
