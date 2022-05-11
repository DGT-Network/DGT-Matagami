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
import yaml
import base64
import hashlib
import random
import os
from aiohttp import web
import cbor
import time
# pylint: disable=no-name-in-module,import-error
# needed for the google.protobuf imports to pass pylint
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError


#from dgt_sdk.protobuf.validator_pb2 import Message
import dgt_rest_api.exceptions as errors
from dgt_rest_api import error_handlers
from dgt_rest_api.messaging import DisconnectError
from dgt_rest_api.messaging import SendBackoffTimeoutError

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
#from dgt_sdk.protobuf.transaction_pb2 import  Transaction,TransactionHeader
#from dgt_sdk.protobuf.batch_pb2 import  Batch,BatchHeader,BatchList

from dgt_rest_api.route_handlers import RouteHandler,DEFAULT_TIMEOUT
# bgt families
from dgt_bgt.client_cli.generate import BgtPayload,create_bgt_transaction,loads_bgt_token
from dgt_bgt.processor.handler import make_bgt_address

from dgt_signing import CryptoFactory,create_context


LOGGER = logging.getLogger(__name__)
ROOT = os.path.dirname(__file__)

class DashboardRouteHandler(RouteHandler):
    """Contains a number of aiohttp handlers for endpoints in the Rest Api.

    Args:
        connection (:obj: messaging.Connection): The object that communicates
            with the validator.
        timeout (int, optional): The time in seconds before the Api should
            cancel a request and report that the validator is unavailable.
    """

    def __init__(self, loop, connection,timeout=DEFAULT_TIMEOUT, metrics_registry=None):

        super().__init__(loop,connection,timeout,metrics_registry)
        # Dashboard init
        self._context = create_context('secp256k1') 
        self._private_key = self._context.new_random()
        self._public_key = self._context.get_public_key(self._private_key)
        self._crypto_factory = CryptoFactory(self._context)
        self._signer = self._crypto_factory.new_signer(self._private_key)
        self._public_key_id = self._public_key.as_hex()
        LOGGER.debug('DashboardRouteHandler: _signer PUBLIC_KEY=%s',self._public_key_id[:8])
        self._network = {}
        try:
            with open('./network.json') as file:
                self._network = json.load(file)
        except Exception as err:
            LOGGER.debug('DashboardRouteHandler: err=%s',err)

        
        #LOGGER.debug('DashboardRouteHandler: network=%s',self._network)
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

    def _create_transaction(self,family,ver,payload,inputs,outputs,dependencies=[]):
        """
        make transaction
        """
        LOGGER.debug('DgtRouteHandler: _create_transaction make Transaction')
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

    async def index(self,request):
        html = request.match_info.get('html', '/')
        LOGGER.debug('DashboardRouteHandler: index=%s html=%s',request.path,html)
        full_path = 'app/html/' +  ('index' if html == '/' else html) + '.html' 
        try:
            content = open(os.path.join(ROOT, full_path), 'r').read()
        except:
            raise errors.FileNotFound()

        return web.Response(content_type='text/html', text=content)

    async def javascript(self,request):
        LOGGER.debug('DashboardRouteHandler: javascript=%s',request.path)
        content = open(os.path.join(ROOT,'app/js/'+request.path[1:]), 'r', encoding='utf-8').read()
        return web.Response(content_type='application/javascript', text=content)

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
        


    async def fetch_peers(self, request):
        """Fetches the peers from the validator.
        Request:

        Response:
            data: JSON array of peer endpoints
            link: The link to this exact query
        """
        LOGGER.debug('DashboardRouteHandler: fetch_peers')
        response = await self._query_validator(
            Message.CLIENT_PEERS_GET_REQUEST,
            client_peers_pb2.ClientPeersGetResponse,
            client_peers_pb2.ClientPeersGetRequest())

        return self._wrap_response(
            request,
            data=self._network, #response['peers'],
            metadata=self._get_metadata(request, response))

    async def fetch_state(self, request):
        """Fetches data from a specific address in the validator's state tree.

        Request:
            query:
                - head: The id of the block to use as the head of the chain
                - address: The 70 character address of the data to be fetched

        Response:
            data: The base64 encoded binary data stored at that address
            head: The head used for this query (most recent if unspecified)
            link: The link to this exact query, including head block
        """
        error_traps = [
            error_handlers.InvalidAddressTrap,
            error_handlers.StateNotFoundTrap]

        address = request.match_info.get('address', '')
        head = request.url.query.get('head', None)

        head, root = await self._head_to_root(head)
        response = await self._query_validator(
            Message.CLIENT_STATE_GET_REQUEST,
            client_state_pb2.ClientStateGetResponse,
            client_state_pb2.ClientStateGetRequest(
                state_root=root, address=address),
            error_traps)
        content = cbor.loads(base64.b64decode(response['value']))
        if isinstance(content, dict) :
            for key in content:
                LOGGER.debug('DashboardRouteHandler:_get_token GROUP (%s)',key)
                token = json.loads(content[key])
                content[key] = token
        LOGGER.debug('DashboardRouteHandler: fetch_state=(%s)',content)
        return self._wrap_response(
            request,
            data=content,
            metadata=self._get_metadata(request, response, head=head))


