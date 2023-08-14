# Copyright 2019 DGT NETWORK INC © Stanislav Parsov 
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

from google.protobuf.message import DecodeError

from dgt_validator.consensus.proxy import UnknownBlock,TooManyBranch,BlockIsProcessedNow

from dgt_validator.protobuf import consensus_pb2
from dgt_validator.protobuf import validator_pb2

from dgt_validator.networking.dispatch import Handler
from dgt_validator.networking.dispatch import HandlerResult
from dgt_validator.networking.dispatch import HandlerStatus

from dgt_validator.journal.block_wrapper import BlockStatus
from dgt_validator.journal.publisher import BlockEmpty
from dgt_validator.journal.publisher import BlockInProgress
from dgt_validator.journal.publisher import BlockNotInitialized
from dgt_validator.journal.publisher import MissingPredecessor

from dgt_validator.protobuf.block_pb2 import BlockHeader
from dgt_validator.protobuf.consensus_pb2 import ConsensusSettingsEntry
from dgt_validator.protobuf.consensus_pb2 import ConsensusStateEntry
from dgt_validator.exceptions import NotRegisteredConsensusModule

LOGGER = logging.getLogger(__name__)


class ConsensusServiceHandler(Handler):
    def __init__(
        self,
        request_class,
        request_type,
        response_class,
        response_type,
        handler_status=HandlerStatus.RETURN
    ):
        self._request_class = request_class
        self._request_type = request_type
        self._response_class = response_class
        self._response_type = response_type
        self._handler_status = handler_status

    def handle_request(self, request, response):
        raise NotImplementedError()

    @property
    def request_class(self):
        return self._request_class

    @property
    def response_class(self):
        return self._response_class

    @property
    def response_type(self):
        return self._response_type

    @property
    def request_type(self):
        return self._request_type

    def handle(self, connection_id, message_content):
        request = self._request_class()
        response = self._response_class()
        response.status = response.OK

        try:
            request.ParseFromString(message_content)
        except DecodeError:
            response.status = response.BAD_REQUEST
        else:
            self.handle_request(request, response)

        return HandlerResult(
            status=self._handler_status,
            message_out=response,
            message_type=self._response_type)


class ConsensusRegisterHandler(ConsensusServiceHandler):
    def __init__(self, proxy, consensus_notifier):
        super().__init__(
            consensus_pb2.ConsensusRegisterRequest,
            validator_pb2.Message.CONSENSUS_REGISTER_REQUEST,
            consensus_pb2.ConsensusRegisterResponse,
            validator_pb2.Message.CONSENSUS_REGISTER_RESPONSE)

        self._proxy = proxy
        self._consensus_notifier = consensus_notifier
        self._last_status = None

    def handle_request(self, request, response):
        #LOGGER.debug('ConsensusRegisterHandler: proxy.register')
        startup_info = self._proxy.register()

        if startup_info is None:
            # not ready for working with consensus engine
            response.status = consensus_pb2.ConsensusRegisterResponse.NOT_READY
            if self._last_status != response.status:
                LOGGER.debug('ConsensusRegisterHandler: NOT READY yet for working with consensus engine!\n')
                self._last_status = response.status
            return

        #if self._proxy.is_recovery :
            # recovery mode
        #    response.status = consensus_pb2.ConsensusRegisterResponse.RECOVERY

        chain_head = startup_info.chain_head
        # README when not enought resource some peers could not be connected 
        peers = [bytes.fromhex(peer_id) for peer_id in startup_info.peers if peer_id is not None]
        local_peer_info = startup_info.local_peer_info
        LOGGER.debug('ConsensusRegisterHandler: peers=%s local=%s chain_head[%s]=%s header=%s block=%s',peers,local_peer_info,type(chain_head),chain_head,type(chain_head.header),type(chain_head.block))
        block_header = BlockHeader()
        """
        for last version validator(rust) used chain_head.header because  chain_head is Block not WrapperBlock as for python validator
        """
        block_header.ParseFromString(chain_head.block.header)  

        response.chain_head.block_id = bytes.fromhex(chain_head.header_signature)
        response.chain_head.previous_id = bytes.fromhex(block_header.previous_block_id)
        response.chain_head.signer_id = bytes.fromhex(block_header.signer_public_key)
        response.chain_head.block_num = block_header.block_num
        response.chain_head.payload = block_header.consensus

        response.peers.extend([
            consensus_pb2.ConsensusPeerInfo(peer_id=peer_id)
            for peer_id in peers
        ])

        response.local_peer_info.peer_id = local_peer_info
        response.peering_mode = startup_info.peering_mode 

        self._consensus_notifier.add_registered_engine(request.name,request.version)

        LOGGER.info("Consensus engine registered: %s %s",request.name,request.version)


class ConsensusSendToHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusSendToRequest,
            validator_pb2.Message.CONSENSUS_SEND_TO_REQUEST,
            consensus_pb2.ConsensusSendToResponse,
            validator_pb2.Message.CONSENSUS_SEND_TO_RESPONSE)
        self._proxy = proxy

    def handle_request(self, request, response):
        LOGGER.debug('ConsensusSendToHandler: proxy send_to')
        try:
            self._proxy.send_to(
                request.peer_id,
                request.message)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusSendTo")
            response.status = consensus_pb2.ConsensusSendToResponse.SERVICE_ERROR


class ConsensusBroadcastHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusBroadcastRequest,
            validator_pb2.Message.CONSENSUS_BROADCAST_REQUEST,
            consensus_pb2.ConsensusBroadcastResponse,
            validator_pb2.Message.CONSENSUS_BROADCAST_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusBroadcastHandler: proxy.broadcast')
            self._proxy.broadcast(request.message) #.SerializeToString())
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusBroadcast")
            response.status =\
                consensus_pb2.ConsensusBroadcastResponse.SERVICE_ERROR


class ConsensusBroadcastArbiterHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusBroadcastArbiterRequest,
            validator_pb2.Message.CONSENSUS_BROADCAST_ARBITER_REQUEST,
            consensus_pb2.ConsensusBroadcastArbiterResponse,
            validator_pb2.Message.CONSENSUS_BROADCAST_ARBITER_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusBroadcastArbiterHandler: proxy.broadcast2arbiter')
            self._proxy.broadcast2arbiter(request.message) #.SerializeToString())
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusBroadcast arbiter")
            response.status = consensus_pb2.ConsensusBroadcastArbiterResponse.SERVICE_ERROR


class ConsensusBroadcastClusterHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusBroadcastClusterRequest,
            validator_pb2.Message.CONSENSUS_BROADCAST_CLUSTER_REQUEST,
            consensus_pb2.ConsensusBroadcastClusterResponse,
            validator_pb2.Message.CONSENSUS_BROADCAST_CLUSTER_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusBroadcastClusterHandler: proxy.broadcast2cluster')
            self._proxy.broadcast2cluster(request.message)#.SerializeToString())
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusBroadcast cluster")
            response.status = consensus_pb2.ConsensusBroadcastClusterResponse.SERVICE_ERROR


class ConsensusInitializeBlockHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusInitializeBlockRequest,
            validator_pb2.Message.CONSENSUS_INITIALIZE_BLOCK_REQUEST,
            consensus_pb2.ConsensusInitializeBlockResponse,
            validator_pb2.Message.CONSENSUS_INITIALIZE_BLOCK_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusInitializeBlockHandler: initialize_block block=%s colour=(%s)',request.previous_id.hex()[:8],request.nest_colour)
            self._proxy.initialize_block(request.previous_id,request.nest_colour)
        except MissingPredecessor:
            response.status = consensus_pb2.ConsensusInitializeBlockResponse.UNKNOWN_BLOCK
        except BlockInProgress:
            response.status = consensus_pb2.ConsensusInitializeBlockResponse.INVALID_STATE
        except NotRegisteredConsensusModule:
            response.status = consensus_pb2.ConsensusInitializeBlockResponse.INVALID_STATE
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusInitializeBlock")
            response.status = consensus_pb2.ConsensusInitializeBlockResponse.SERVICE_ERROR


class ConsensusSummarizeBlockHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusSummarizeBlockRequest,
            validator_pb2.Message.CONSENSUS_SUMMARIZE_BLOCK_REQUEST,
            consensus_pb2.ConsensusSummarizeBlockResponse,
            validator_pb2.Message.CONSENSUS_SUMMARIZE_BLOCK_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            #LOGGER.debug('ConsensusSummarizeBlockHandler: proxy:summarize_block')
            summary,parent = self._proxy.summarize_block()
            response.summary,response.block_id = summary,bytes.fromhex(parent)
        except BlockNotInitialized:
            LOGGER.debug('ConsensusSummarizeBlockHandler: BlockNotInitialized')
            response.status =\
                consensus_pb2.ConsensusSummarizeBlockResponse.INVALID_STATE
        except BlockEmpty:
            #LOGGER.debug('ConsensusSummarizeBlockHandler: BlockEmpty')
            response.status =\
                consensus_pb2.ConsensusSummarizeBlockResponse.BLOCK_NOT_READY
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusSummarizeBlock")
            response.status =\
                consensus_pb2.ConsensusSummarizeBlockResponse.SERVICE_ERROR


class ConsensusFinalizeBlockHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusFinalizeBlockRequest,
            validator_pb2.Message.CONSENSUS_FINALIZE_BLOCK_REQUEST,
            consensus_pb2.ConsensusFinalizeBlockResponse,
            validator_pb2.Message.CONSENSUS_FINALIZE_BLOCK_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusFinalizeBlockHandler: proxy:finalize_block')
            response.block_id = self._proxy.finalize_block(request.data,request.block_id)
        except BlockNotInitialized:
            response.status =\
                consensus_pb2.ConsensusFinalizeBlockResponse.INVALID_STATE
        except BlockEmpty:
            response.status =\
                consensus_pb2.ConsensusFinalizeBlockResponse.BLOCK_NOT_READY
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusFinalizeBlock")
            response.status =\
                consensus_pb2.ConsensusFinalizeBlockResponse.SERVICE_ERROR


class ConsensusCancelBlockHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusCancelBlockRequest,
            validator_pb2.Message.CONSENSUS_CANCEL_BLOCK_REQUEST,
            consensus_pb2.ConsensusCancelBlockResponse,
            validator_pb2.Message.CONSENSUS_CANCEL_BLOCK_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusCancelBlockHandler: proxy:cancel_block ')
            self._proxy.cancel_block(request.branch_id)
        except BlockNotInitialized:
            response.status =\
                consensus_pb2.ConsensusCancelBlockResponse.INVALID_STATE
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusCancelBlock")
            response.status =\
                consensus_pb2.ConsensusCancelBlockResponse.SERVICE_ERROR


class ConsensusCheckBlocksHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusCheckBlocksRequest,
            validator_pb2.Message.CONSENSUS_CHECK_BLOCKS_REQUEST,
            consensus_pb2.ConsensusCheckBlocksResponse,
            validator_pb2.Message.CONSENSUS_CHECK_BLOCKS_RESPONSE,
            handler_status=HandlerStatus.RETURN_AND_PASS)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusCheckBlocksHandler: proxy:check_blocks')
            self._proxy.check_blocks(request.block_ids)
        except UnknownBlock:
            LOGGER.debug('ConsensusCheckBlocksHandler:proxy UNKNOWN_BLOCK')
            response.status =\
                consensus_pb2.ConsensusCheckBlocksResponse.UNKNOWN_BLOCK
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusCheckBlocks")
            response.status =\
                consensus_pb2.ConsensusCheckBlocksResponse.SERVICE_ERROR


class ConsensusCheckBlocksNotifier(Handler):
    request_type = validator_pb2.Message.CONSENSUS_CHECK_BLOCKS_REQUEST

    def __init__(self, proxy, consensus_notifier):
        self._proxy = proxy
        self._consensus_notifier = consensus_notifier

    def handle(self, connection_id, message_content):
        request = consensus_pb2.ConsensusCheckBlocksRequest()

        try:
            request.ParseFromString(message_content)
        except DecodeError:
            LOGGER.exception("Unable to decode ConsensusCheckBlocksRequest")
            return HandlerResult(status=HandlerResult.DROP)
        
        block_statuses = self._proxy.get_block_statuses(request.block_ids)
        LOGGER.debug('ConsensusCheckBlocksNotifier: CHECK_BLOCKS_REQUEST get_block_statuses=%s',block_statuses)
        for (block_id, block_status) in block_statuses:
            if block_status == BlockStatus.Valid:
                # at this point notify_block_valid message could be already sent
                self._consensus_notifier.notify_block_valid(block_id)
            elif block_status == BlockStatus.Invalid:
                self._consensus_notifier.notify_block_invalid(block_id)

        return HandlerResult(status=HandlerStatus.PASS)


class ConsensusCommitBlockHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusCommitBlockRequest,
            validator_pb2.Message.CONSENSUS_COMMIT_BLOCK_REQUEST,
            consensus_pb2.ConsensusCommitBlockResponse,
            validator_pb2.Message.CONSENSUS_COMMIT_BLOCK_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusCommitBlockHandler: proxy:commit_block')
            self._proxy.commit_block(request.block_id,request.seal)
        except UnknownBlock:
            response.status =\
                consensus_pb2.ConsensusCommitBlockResponse.UNKNOWN_BLOCK
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusCommitBlock")
            response.status =\
                consensus_pb2.ConsensusCommitBlockResponse.SERVICE_ERROR


class ConsensusIgnoreBlockHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusIgnoreBlockRequest,
            validator_pb2.Message.CONSENSUS_IGNORE_BLOCK_REQUEST,
            consensus_pb2.ConsensusIgnoreBlockResponse,
            validator_pb2.Message.CONSENSUS_IGNORE_BLOCK_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusIgnoreBlockHandler: proxy:ignore_block')
            self._proxy.ignore_block(request.block_id)
        except UnknownBlock:
            response.status =\
                consensus_pb2.ConsensusIgnoreBlockResponse.UNKNOWN_BLOCK
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusIgnoreBlock")
            response.status =\
                consensus_pb2.ConsensusIgnoreBlockResponse.SERVICE_ERROR


class ConsensusFailBlockHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusFailBlockRequest,
            validator_pb2.Message.CONSENSUS_FAIL_BLOCK_REQUEST,
            consensus_pb2.ConsensusFailBlockResponse,
            validator_pb2.Message.CONSENSUS_FAIL_BLOCK_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusFailBlockHandler: proxy:fail_block')
            self._proxy.fail_block(request.block_id)
        except UnknownBlock:
            response.status =\
                consensus_pb2.ConsensusFailBlockResponse.UNKNOWN_BLOCK
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusFailBlock")
            response.status =\
                consensus_pb2.ConsensusFailBlockResponse.SERVICE_ERROR


class ConsensusBlocksGetHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusBlocksGetRequest,
            validator_pb2.Message.CONSENSUS_BLOCKS_GET_REQUEST,
            consensus_pb2.ConsensusBlocksGetResponse,
            validator_pb2.Message.CONSENSUS_BLOCKS_GET_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            blocks = []
            for block in self._proxy.blocks_get(request.block_ids):
                if block is None:
                    LOGGER.debug('ConsensusBlocksGetHandler: IGNORE NONE BLOCK ids={}\n'.format(request.block_ids))
                    continue
                LOGGER.debug('ConsensusBlocksGetHandler: block %s',type(block.header))
                """
                block manager return blocks from store where header is string and we should decode it
                in case of chain controller it is object
                """
                if not isinstance(block.header,BlockHeader) :
                    block_header = BlockHeader()
                    block_header.ParseFromString(block.header)
                else:
                    block_header = block.header

                blocks.append(consensus_pb2.ConsensusBlock(
                    block_id=bytes.fromhex(block.header_signature),
                    previous_id=bytes.fromhex(block_header.previous_block_id),
                    signer_id=bytes.fromhex(block_header.signer_public_key),
                    block_num=block_header.block_num,
                    payload=block_header.consensus))
            response.blocks.extend(blocks)
        except UnknownBlock:
            LOGGER.debug('ConsensusBlocksGetHandler:proxy UNKNOWN_BLOCK')
            response.status = consensus_pb2.ConsensusBlocksGetResponse.UNKNOWN_BLOCK
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusBlocksGet")
            response.status = consensus_pb2.ConsensusBlocksGetResponse.SERVICE_ERROR


class ConsensusChainHeadGetHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusChainHeadGetRequest,
            validator_pb2.Message.CONSENSUS_CHAIN_HEAD_GET_REQUEST,
            consensus_pb2.ConsensusChainHeadGetResponse,
            validator_pb2.Message.CONSENSUS_CHAIN_HEAD_GET_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            LOGGER.debug('ConsensusChainHeadGetHandler: proxy parent_id=(%s) new_parent=(%s) is_new=%s',request.parent_id.hex()[:8],request.new_parent_id.hex()[:8],request.is_new)
            chain_head = self._proxy.chain_head_get(request.parent_id,request.new_parent_id,request.is_new)

            block_header = BlockHeader()
            """
            chain_head.header for RUST 
            """
            block_header.ParseFromString(chain_head.block.header)

            response.block.block_id = bytes.fromhex(
                chain_head.header_signature)
            response.block.previous_id =\
                bytes.fromhex(block_header.previous_block_id)
            response.block.signer_id =\
                bytes.fromhex(block_header.signer_public_key)
            response.block.block_num = block_header.block_num
            response.block.payload = block_header.consensus
        except TooManyBranch:
            response.status = consensus_pb2.ConsensusChainHeadGetResponse.TOO_MANY_BRANCH
            # change dgt.publisher.max_batches_per_block after nests were made
            self._proxy.reset_max_batches_per_block()
        except UnknownBlock:
            response.status = consensus_pb2.ConsensusChainHeadGetResponse.NO_CHAIN_HEAD
        except BlockIsProcessedNow:
            response.status = consensus_pb2.ConsensusChainHeadGetResponse.BLOCK_IS_PROCESSED_NOW
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusChainHeadGet")
            response.status = consensus_pb2.ConsensusChainHeadGetResponse.SERVICE_ERROR


class ConsensusSettingsGetHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusSettingsGetRequest,
            validator_pb2.Message.CONSENSUS_SETTINGS_GET_REQUEST,
            consensus_pb2.ConsensusSettingsGetResponse,
            validator_pb2.Message.CONSENSUS_SETTINGS_GET_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            response.entries.extend([
                ConsensusSettingsEntry(
                    key=key,
                    value=value)
                for key, value in self._proxy.settings_get(
                    request.block_id, request.keys)
            ])
        except UnknownBlock:
            LOGGER.debug('ConsensusSettingsGetHandler:proxy UNKNOWN_BLOCK')
            response.status = consensus_pb2.ConsensusSettingsGetResponse.UNKNOWN_BLOCK
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusSettingsGet")
            response.status = consensus_pb2.ConsensusSettingsGetResponse.SERVICE_ERROR


class ConsensusStateGetHandler(ConsensusServiceHandler):
    def __init__(self, proxy):
        super().__init__(
            consensus_pb2.ConsensusStateGetRequest,
            validator_pb2.Message.CONSENSUS_STATE_GET_REQUEST,
            consensus_pb2.ConsensusStateGetResponse,
            validator_pb2.Message.CONSENSUS_STATE_GET_RESPONSE)

        self._proxy = proxy

    def handle_request(self, request, response):
        try:
            #LOGGER.debug('ConsensusStateGetHandler:proxy ASK STATE ENTRY')
            response.entries.extend([
                ConsensusStateEntry(
                    address=address,
                    data=data)
                for address, data in self._proxy.state_get(
                    request.block_id, request.addresses)
            ])
            #LOGGER.debug('ConsensusStateGetHandler:proxy ASK STATE ENTRY DONE')
        except UnknownBlock:
            LOGGER.debug('ConsensusStateGetHandler:proxy UNKNOWN BLOCK=%s',request.block_id.hex()[0:8])
            response.status = consensus_pb2.ConsensusStateGetResponse.UNKNOWN_BLOCK
        except BlockIsProcessedNow:
            LOGGER.debug('ConsensusStateGetHandler:proxy BLOCK_IS_PROCESSED_NOW BLOCK=%s',request.block_id.hex()[0:8])
            response.status = consensus_pb2.ConsensusStateGetResponse.BLOCK_IS_PROCESSED_NOW
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("ConsensusStateGet")
            response.status =consensus_pb2.ConsensusStateGetResponse.SERVICE_ERROR
