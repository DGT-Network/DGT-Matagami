# Copyright 2018 DGT NETWORK INC © Stanislav Parsov
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
# -----------------------------------------------------------------------------

import concurrent
import logging
from queue import Queue
from threading import Thread

from dgt_sdk.consensus.driver import Driver
from dgt_sdk.consensus.engine import StartupState
from dgt_sdk.consensus.zmq_service import ZmqService
from dgt_sdk.consensus import exceptions
from dgt_sdk.messaging.stream import Stream
from dgt_sdk.protobuf import consensus_pb2
from dgt_sdk.protobuf.validator_pb2 import Message


LOGGER = logging.getLogger(__name__)
REGISTER_TIMEOUT = 800
SERVICE_TIMEOUT = 800


class ZmqDriver(Driver):
    def __init__(self, engine):
        super().__init__(engine)
        self._engine = engine
        self._stream = None
        self._exit = False
        self._updates = None
        self._signed_consensus = self._engine.signed_consensus

    def start(self, endpoint):
        LOGGER.debug('ZmqDriver: start endpoint=%s',endpoint)
        self._stream = Stream(endpoint)

        startup_state = self._register()

        self._updates = Queue()

        driver_thread = Thread(
            target=self._driver_loop)
        driver_thread.start()

        try:
            self._engine.start(
                self._updates,
                ZmqService(
                    stream=self._stream,
                    timeout=SERVICE_TIMEOUT,
                    name=self._engine.name(),
                    version=self._engine.version()),
                startup_state)
        except Exception as ex:  # pylint: disable=broad-except
            LOGGER.exception("Uncaught engine exception(%s)",ex)

        self.stop()
        driver_thread.join()

    def _driver_loop(self):
        try:
            future = self._stream.receive()
            LOGGER.debug('ZmqDriver: _driver_loop future=%s',future)
            while True:
                if self._exit:
                    self._engine.stop()
                    break

                try:
                    message = future.result(1)
                    future = self._stream.receive()
                except concurrent.futures.TimeoutError:
                    continue
                #LOGGER.debug('ZmqDriver: _driver_loop _process')
                result = self._process(message)

                self._updates.put(result)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("Uncaught driver exception")

    def stop(self):
        self._exit = True
        self._engine.stop()
        self._stream.close()

    def _register(self):
        self._stream.wait_for_ready()

        request = consensus_pb2.ConsensusRegisterRequest(
            name=self._engine.name(),
            version=self._engine.version(),
        ).SerializeToString()

        while True:
            future = self._stream.send(
                message_type=Message.CONSENSUS_REGISTER_REQUEST,
                content=request)
            response = consensus_pb2.ConsensusRegisterResponse()
            response.ParseFromString(future.result(REGISTER_TIMEOUT).content)

            if (
                response.status
                == consensus_pb2.ConsensusRegisterResponse.NOT_READY
            ):
                #LOGGER.debug('ZmqDriver:register NOT_READY: url=%s',self._stream._url)
                continue

            if response.status == consensus_pb2.ConsensusRegisterResponse.OK :
                LOGGER.debug('ZmqDriver:register DONE: url=%s',self._stream._url)
                return StartupState(
                    response.chain_head,
                    response.peers,
                    response.local_peer_info,
                    response.peering_mode)

            raise exceptions.ReceiveError(
                'Registration failed with status {}'.format(response.status))

    def _process(self, message):
        type_tag = message.message_type

        if type_tag == Message.CONSENSUS_NOTIFY_PEER_CONNECTED:
            notification = consensus_pb2.ConsensusNotifyPeerConnected()
            notification.ParseFromString(message.content)

            data = notification.peer_info, notification.status, notification.mode , notification.info, notification.data

        elif type_tag == Message.CONSENSUS_NOTIFY_PEER_DISCONNECTED:
            notification = consensus_pb2.ConsensusNotifyPeerDisconnected()
            notification.ParseFromString(message.content)

            data = notification.peer_id

        elif type_tag == Message.CONSENSUS_NOTIFY_PEER_MESSAGE:
            notification = consensus_pb2.ConsensusNotifyPeerMessageNew() if self._signed_consensus else consensus_pb2.ConsensusNotifyPeerMessage()
            notification.ParseFromString(message.content)

            data = notification.message, notification.sender_id

        elif type_tag == Message.CONSENSUS_NOTIFY_BLOCK_NEW:
            notification = consensus_pb2.ConsensusNotifyBlockNew()
            notification.ParseFromString(message.content)

            data = notification.block

        elif type_tag == Message.CONSENSUS_NOTIFY_BLOCK_VALID:
            notification = consensus_pb2.ConsensusNotifyBlockValid()
            notification.ParseFromString(message.content)

            data = notification.block_id

        elif type_tag == Message.CONSENSUS_NOTIFY_BLOCK_INVALID:
            notification = consensus_pb2.ConsensusNotifyBlockInvalid()
            notification.ParseFromString(message.content)

            data = notification.block_id

        elif type_tag == Message.CONSENSUS_NOTIFY_BLOCK_COMMIT:
            notification = consensus_pb2.ConsensusNotifyBlockCommit()
            notification.ParseFromString(message.content)

            data = notification.block_id

        else:
            raise exceptions.ReceiveError(
                'Received unexpected message type: {}'.format(type_tag))

        self._stream.send_back(
            message_type=Message.CONSENSUS_NOTIFY_ACK,
            correlation_id=message.correlation_id,
            content=consensus_pb2.ConsensusNotifyAck().SerializeToString())

        return type_tag, data
