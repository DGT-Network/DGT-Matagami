# Copyright 2017 DGT NETWORK INC 
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
from dgt_validator.protobuf.transaction_receipt_pb2 import \
    TransactionReceipt
from dgt_validator.protobuf.client_receipt_pb2 import \
    ClientReceiptGetRequest
from dgt_validator.protobuf.client_receipt_pb2 import \
    ClientReceiptGetResponse

from dgt_validator.networking.dispatch import Handler
from dgt_validator.networking.dispatch import HandlerResult
from dgt_validator.networking.dispatch import HandlerStatus
from dgt_validator.protobuf import validator_pb2

from dgt_validator.journal.chain import ChainObserver
import logging
LOGGER = logging.getLogger(__name__)

class TransactionReceiptStore(ChainObserver):
    """A TransactionReceiptStore persists TransactionReceipt records to a
    provided database implementation.
    """

    def __init__(self, receipt_db):
        """Constructs a TransactionReceiptStore, backed by a given database
        implementation.

        Args:
            receipt_db (:obj:dgt_validator.database.database.Database): A
                database implementation that backs this store.
        """
        self._receipt_db = receipt_db

    def put(self, txn_id, txn_receipt):
        """Add the given transaction receipt to the store. Does not guarantee
           it has been written to the backing store.

        Args:
            txn_id (str): the id of the transaction being stored.
            receipt (TransactionReceipt): the receipt object to store.
        """
        LOGGER.debug('PUT: receipt=%s', txn_receipt)
        self._receipt_db[txn_id] = txn_receipt.SerializeToString()

    def get(self, txn_id):
        """Returns the TransactionReceipt

        Args:
            txn_id (str): the id of the transaction for which the receipt
                should be retrieved.

        Returns:
            TransactionReceipt: The receipt for the given transaction id.

        Raises:
            KeyError: if the transaction id is unknown.
        """
        if txn_id not in self._receipt_db:
            raise KeyError('Unknown transaction id {}'.format(txn_id))

        txn_receipt_bytes = self._receipt_db[txn_id]
        txn_receipt = TransactionReceiptStore._deserialize(txn_receipt_bytes)
        return txn_receipt

    def chain_update(self, block, receipts):
        LOGGER.debug('chain_update:block=%s receipts=%s',block, receipts)
        for receipt in receipts:
            self.put(receipt.transaction_id, receipt)

    def get_receipt_by_address(self, address):
        """Returns the receipt that contains the given state address .

        Args:
            address (str): a state addr

        Returns:
            a receipt

        Raises:
            ValueError if no block containing the transaction is found
        """
        receipt_bytes = self._receipt_db.get(address, index='states')
        if not receipt_bytes:
            raise ValueError('Receipt "{}" not in receiptStore'.format(address))

        txn_receipt = TransactionReceiptStore._deserialize(receipt_bytes) 
        return txn_receipt

    def get_receipts_by_address(self, address):
        receipts = []
        with self._receipt_db.cursor(index='states') as curs:
            try:
                curs.seek(address)
                for val in curs.iternext_dup():
                    receipt = TransactionReceiptStore._deserialize(val)
                    receipts.append(receipt)
                    LOGGER.debug('get_receipts_by_address: receipt=%s',receipt)
                #ordered_values = list(curs.iternext_dup())
            except Exception as ex:
                LOGGER.debug('CURS: error(%s)',ex)
        #for val  in ordered_values:
        #    LOGGER.debug('get_receipts_by_address: receipt=%s',TransactionReceiptStore._deserialize(val))
        return receipts

    @staticmethod
    def _states_index_keys(receipt_bytes):
        
        keys = []
        txn_receipt = TransactionReceiptStore._deserialize(receipt_bytes)
        
        LOGGER.debug('_states_index_keys: receipt tnx=%s', txn_receipt.transaction_id)
        for receipt in txn_receipt.state_changes:
            LOGGER.debug('_states_index_keys: receipt=%s', receipt)
            try:
                keys.append(receipt.address.encode())
            except :
                pass
        return keys

    @staticmethod
    def create_index_configuration():
        return {
            'states': TransactionReceiptStore._states_index_keys,
           
        }

    @staticmethod
    def _deserialize(receipt_bytes):
        receipt = TransactionReceipt()
        receipt.ParseFromString(receipt_bytes)
        return receipt

    @staticmethod
    def deserialize_receipt(value):
        #receipt = TransactionReceipt()
        #receipt.ParseFromString(value)
        return value

    @staticmethod
    def serialize_receipt(receipt):
        return receipt #.SerializeToString()

class ClientReceiptGetRequestHandler(Handler):
    """
    Handles receiving messages for getting transactionreceipts.
    """
    _msg_type = validator_pb2.Message.CLIENT_RECEIPT_GET_RESPONSE

    def __init__(self, txn_receipt_store):
        self._txn_receipt_store = txn_receipt_store

    def handle(self, connection_id, message_content):
        request = ClientReceiptGetRequest()
        request.ParseFromString(message_content)

        try:
            ids = [id for id in request.transaction_ids] 
            if request.ind == ClientReceiptGetRequest.INDEX_TNX:
                receipts = [self._txn_receipt_store.get(txn_id) for txn_id in request.transaction_ids] 
                
            else:
                receipts = self._txn_receipt_store.get_receipts_by_address(ids[0]) #"4490954ff00e098a60f4223327437f79975d58edb4633f673df9b002491db0cee96024")

            LOGGER.debug('ClientReceiptGetRequestHandler:index=%s receipts=%s ids=%s',request.ind,receipts,ids)
            response = ClientReceiptGetResponse(
                        receipts=receipts,
                        status=ClientReceiptGetResponse.OK)


        except KeyError:
            response = ClientReceiptGetResponse(status=ClientReceiptGetResponse.NO_RESOURCE)
        except Exception as ex:
            LOGGER.debug('ClientReceiptGetRequestHandler:error=%s',ex )
            response = ClientReceiptGetResponse(status=ClientReceiptGetResponse.NO_RESOURCE)


        return HandlerResult(
            HandlerStatus.RETURN,
            message_out=response,
            message_type=self._msg_type)
