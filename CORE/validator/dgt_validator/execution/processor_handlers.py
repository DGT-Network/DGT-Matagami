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

import logging

from dgt_validator.execution import processor_iterator

from dgt_validator.protobuf import processor_pb2
from dgt_validator.protobuf import validator_pb2
from dgt_validator.networking.dispatch import Handler
from dgt_validator.networking.dispatch import HandlerResult
from dgt_validator.networking.dispatch import HandlerStatus

LOGGER = logging.getLogger(__name__)


class ProcessorRegisterHandler(Handler):
    def __init__(self, processor_collection):
        self._collection = processor_collection

    def handle(self, connection_id, message_content):
        request = processor_pb2.TpRegisterRequest()
        request.ParseFromString(message_content)
        LOGGER.info("RM='%s'",message_content)
        LOGGER.info(
            'registered transaction processor: connection_id=%s, family=%s, version=%s, namespaces=%s',
            connection_id[:8],
            request.family,
            request.version,
            list(request.namespaces))

        processor_type = processor_iterator.ProcessorType(
            request.family,
            request.version)

        processor = processor_iterator.Processor(
            connection_id,
            request.namespaces)

        if processor_type in self._collection:
            LOGGER.debug('Already registered transaction processor:family=%s, version=%s, namespaces=%s',request.family,request.version,list(request.namespaces))
        
        self._collection[processor_type] = processor
        LOGGER.debug('All registered transaction processors=%s',self._collection)
        ack = processor_pb2.TpRegisterResponse()
        ack.status = ack.OK

        return HandlerResult(
            status=HandlerStatus.RETURN,
            message_out=ack,
            message_type=validator_pb2.Message.TP_REGISTER_RESPONSE)


class ProcessorUnRegisterHandler(Handler):
    def __init__(self, processor_collection):
        self._collection = processor_collection

    def handle(self, connection_id, message_content):
        request = processor_pb2.TpUnregisterRequest()
        request.ParseFromString(message_content)

        LOGGER.info("try to unregister all transaction processor "
                    "capabilities for connection_id %s", connection_id)

        self._collection.remove(processor_identity=connection_id)
        LOGGER.debug('Rest registered processors=%s',self._collection)
        ack = processor_pb2.TpUnregisterResponse()
        ack.status = ack.OK

        return HandlerResult(
            status=HandlerStatus.RETURN,
            message_out=ack,
            message_type=validator_pb2.Message.TP_UNREGISTER_RESPONSE)
