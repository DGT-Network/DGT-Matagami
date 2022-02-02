# Copyright 2020 DGT NETWORK INC © Stanislav Parsov 
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

"""
sudo pip3 install apiai
sudo pip3  install pytelegrambotapi
sudo pip3 install dialogflow
sudo pip3 install pysocks

"""
import asyncio
import queue
import re
import logging
import json
import base64
from collections import namedtuple

from concurrent.futures import ThreadPoolExecutor,ProcessPoolExecutor

import bgt_bot_api.exceptions as errors
from bgt_bot_api import error_handlers
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError
from bgt_bot_api.messaging import DisconnectError
from bgt_bot_api.messaging import SendBackoffTimeoutError
from requests.exceptions import ConnectTimeout,ReadTimeout

from dgt_sdk.protobuf.validator_pb2 import Message
from dgt_sdk.protobuf import client_heads_pb2,client_topology_pb2
from dgt_sdk.protobuf import client_peers_pb2

import telebot
from telebot import apihelper
from bgt_bot_api.dflow import Dflow
LOGGER = logging.getLogger(__name__)

BotMessage = namedtuple('BotMessage', "message_id chat_id user_id user_first_name user_last_name intent confidence result batch_id")

FLUSH_TIMEOUT=3600
DEFAULT_TIMEOUT = 300
PROJECT_ID = 'small-talk-wfkygw'
SESSION_ID = '123456789'
language_code = 'ru'
TOKEN='1205652427:AAFr0eynwihWGyvObUA0QSjOfKMwiH3HkZs'
PROXIES = ['82.223.120.213:1080','138.201.6.102:1080','85.10.235.14:1080','217.69.10.129:32401','217.182.230.15:4485','96.96.33.133:1080','93.157.248.106:1080','81.17.20.50:1177','217.69.10.129:32401','1.179.185.253:8080']

class Tbot(object): 
    def __init__(self,loop, connection,tdb,token=TOKEN,project_id=PROJECT_ID,session_id=SESSION_ID,proxy=PROXIES,connects=None):
        self._connects = connects
        self._conn_n = 0
        self._tdb = tdb
        self._proxies = proxy if proxy else PROXIES
        self._project_id = project_id if project_id else PROJECT_ID
        self._session_id = session_id if session_id else SESSION_ID
        self._proxy_pos = 1
        self.set_proxy()
        self._connection = connection
        self._loop = loop
        self._token = token
        
        self._intent_handlers = {}
        self._keyboard1 = telebot.types.ReplyKeyboardMarkup(True, True,True)
        self._keyboard1.row('Привет', 'Пока','Sticker')
        self._timeout = DEFAULT_TIMEOUT
        self._bgt_queue = queue.Queue()
        self.is_pause = False
        LOGGER.info('USE proxy=%d from %d',self._proxy_pos,len(self._proxies))
        try:
            self._dflow = Dflow(self._project_id,self._session_id)
            LOGGER.info('DFLOW OK')
        except Exception as e:
            LOGGER.info('DFLOW error %s',e)
            self._dflow = None

    def set_proxy(self):
        proxy = self._proxies[self._proxy_pos]
        #apihelper.proxy = {'https': 'socks5://{}'.format(proxy)}
        self._proxy_pos += 1
        self._proxy_pos = self._proxy_pos % len(self._proxies)
        LOGGER.info("NEXT proxy %d",self._proxy_pos)

    def send_message(self,chat_id,repl):
        n = 3
        while n > 0:
            try:                                              
                if repl != '':                                
                    self._bot.send_message(chat_id,repl) 
                return   
            except ReadTimeout:           
                LOGGER.info('Cant send message err=Timeout') 
            except  Exception as ex:
                LOGGER.info('Cant send message err=%s',ex)
            n += 1
        
    def send_sticker(self,chat_id,sticker):
        try:                                              
                                            
            self._bot.send_sticker(chat_id,sticker)    
        except ReadTimeout:           
            LOGGER.info('Cant send send_sticker err=Timeout')  
    

    def _start_bot(self):
        bot = telebot.TeleBot(self._token)
        #blog = logging.getLogger('TeleBot')
        #blog.setLevel(logging.INFO)
        self._bot = bot
        keyboard1 = telebot.types.ReplyKeyboardMarkup(True, True,True,True)
        keyboard1.row('Привет', 'Admins','Sticker','Wallet')
        apihelper.delete_webhook(self._token)
        def send_message(chat_id,repl):
            try:                                              
                if repl != '':                                
                    bot.send_message(chat_id,repl)    
            except ReadTimeout:           
                LOGGER.info('Cant send message err=Timeout')  

        @bot.message_handler(commands=['start'])
        def start_message(message):
            self.send_message(message.chat.id, 'Привет {}, ты написал мне /start'.format(message.from_user.first_name),reply_markup=keyboard1)

        @bot.message_handler(commands=['info'])                                                               
        def info_message(message):                                                                            
            chat = bot.get_chat(message.chat.id)                                                              
            self.send_message(message.chat.id, 'Смотри {}, {}'.format(message.from_user.first_name,str(chat))) 

        @bot.message_handler(content_types=['sticker'])   
        def sticker_message(message):                     
            LOGGER.info("sticker_message %s",message)                                
            #bot.send_message(message.chat.id, message)   
            #bot.send_sticker(message.chat.id,message.sticker.file_id) 
            s_key = message.json['sticker']['file_unique_id'] #message.sticker.file_id
            if s_key not in self._tdb :
                LOGGER.info("NEW STICKER %s un=%s", s_key, message.sticker.file_id) #.file_unique_id)

                self._tdb.put(s_key,{'type':'sticker','file_id':message.sticker.file_id,'name': message.sticker.set_name, 'is_animated':message.sticker.is_animated}) 
                self.send_message(message.chat.id, 'Отличный стикер из {} сохраню'.format(message.sticker.set_name))
            else:
                self.send_message(message.chat.id, 'Спасибо за стикер из {},но такой есть'.format(message.sticker.set_name))
                  

        @bot.message_handler(content_types=['text'])
        def send_text(message):
            self.check_user(message.from_user)
            if message.text == 'Привет1' or message.text == 'привет1':                                                                                                                                   
                self.send_message(message.chat.id, 'Привет, мой {} {}'.format('создатель' if message.from_user.first_name == 'Stan' else 'господин',message.from_user.first_name),reply_to_message_id=0)
                photo = bot.get_user_profile_photos(message.chat.id,0,1)                                                                                                                               
                p1 = photo.photos[0][0]                                                                                                                                                                
                LOGGER.info('photo=%s',photo.photos[0][0])                                                                                                                                                              
                file = bot.get_file(p1.file_id)                                                                                                                                                        
                fnm = 'https://api.telegram.org/file/bot'+TOKEN+'/'+file.file_path                                                                                                                     
                bot.send_photo(message.chat.id,p1.file_id)                                                                                                                                             
                LOGGER.info("Пришел {}".format(message.from_user.first_name))  
                try:                                                                                                                              
                    bot.pin_chat_message(message.chat.id,message.message_id)  
                except Exception as e:                                                                                                                                                                               
                    LOGGER.info("cant pin message %s",e)                                                                                                                                
                #f = open('p1.jpg', 'w')                                                                                                                                                               
                #f.write(str(file))                                                                                                                                                                    
                #f.close  
                #                                                                                                                                                                             
            elif message.text == 'Sticker':
                try:
                    self.send_message("@sticker", '@sticker :)')
                except Exception as ex:
                    LOGGER.info("cant send message %s",ex)
            elif message.text == 'Пока1' or message.text == 'пока1':                                                                                                                                     
                self.send_message(message.chat.id, 'Прощай, {}'.format('создатель' if message.from_user.first_name == 'Stan' else 'господин'))                                                          
                try:                                                                                                                                                                                   
                    bot.set_chat_title("@Shiva64_bot","Хозяин покинул меня")                                                                                                                           
                except :                                                                                                                                                                               
                    LOGGER.info("cant set title")                                                                                                                                                            
            elif message.text[0] == '@':                                                                                                                                                               
                try:   
                    LOGGER.info("GET CHAT  %s",message.text[1:])                                                                                                                                                                                
                    chat = bot.get_chat(message.text[1:])                                                                                                                                                  
                    self.send_message(message.chat.id, 'Смотри {}, {}'.format(message.from_user.first_name,str(chat)))                                                                                  
                except Exception as e:                                                                                                                                                                 
                    self.send_message(message.chat.id, 'Смотри {}, {}'.format(message.from_user.first_name,e))                                                                                          
                # get chat info                                                                                                                                                                        
            else : #elif message.text[0] ==  '?':  
                if message.text == 'Привет':
                    LOGGER.info("message=%s",message)                                                                                                                                                      
                resp = self._dflow.detect_intent_text(message.text,language_code) if self._dflow else None                                                                                                                           
                
                if resp:   
                    response = resp.query_result.fulfillment_text  
                    confidence = round(resp.query_result.intent_detection_confidence,2)
                    intent = resp.query_result.intent.display_name 
                    if intent != '':
                        repl = "{}({})".format(response,confidence) if response != '' else ''
                    else:
                        repl = 'Так, погоди, не врубаюсь!'
                    if self.can_talk(intent):
                        self.send_message(message.chat.id,repl)

                    LOGGER.info("DFLOW QUERY %s param=%s RESULT=%s",type(resp.query_result),type(resp.query_result.parameters),resp.query_result)
                    for param,val in resp.query_result.parameters.items():
                        LOGGER.info("PARAM %s='%s'(%s) ",param,val,type(val))
                    if intent != '' and intent in self._intent_handlers:
                        
                        minfo = BotMessage(message.message_id,message.chat.id,message.from_user.id,message.from_user.first_name,message.from_user.last_name,intent,confidence,resp.query_result,None)
                        self.intent_handler(minfo)

                else: 
                    if not self.is_pause:
                        self.send_message(message.chat.id,'Я Вас не совсем понял {}!'.format(message.from_user.first_name))

                     
        # start polling
        LOGGER.info('START BOT via=%s',apihelper.proxy)
        self._stop = False         
        #self._bot.polling()  
        try:
            LOGGER.info('ME=%s',bot.get_me()) 
        except  Exception as ex:
            LOGGER.info('Cant get ME(%s)',ex)

    async def _polling(self):
        """
        get message from bot and do something useful
        """
        self._attemp = 0
        self._timeout = 1
        def shift_proxy():
            self.set_proxy()
            if self._attemp > len(self._proxies):
                self._stop = True
            self._attemp += 1


        while not self._stop:
            await self.process_queue()
            try:
                updates = self._bot.get_updates(offset=(self._bot.last_update_id+1),timeout=self._timeout) #get_me() # Execute an API call
                self._attemp = 0
            except ConnectTimeout:
                LOGGER.info('Get updates ConnectTimeout')
                if self._timeout < 6:
                    self._timeout += 1
                shift_proxy()
                updates = None 
            except Exception as ex  :
                LOGGER.info('Get updates except=%s',ex)
                shift_proxy()
                updates = None

            # Do some other operations...
            #LOGGER.info('get_updates DONE=%s',updates)
            if updates:
                LOGGER.info('UPDATE={}'.format(len(updates)))
                self.check_member_add_left(updates)
                try:
                    self._bot.process_new_updates(updates)
                except Exception as ex  :
                    LOGGER.info('Process updates except=%s',ex)

                LOGGER.info('last update=%s qsize=%s',self._bot.last_update_id,self._bgt_queue.qsize())
                #self._bot.get_updates(offset=(self._bot.last_update_id+1),timeout=0.1)
                
            else:
                pass
                #LOGGER.info('No updates')
    def check_user(self,from_user):
        u_key = '{}'.format(from_user.id)
        if u_key not in self._tdb :
            LOGGER.info("NEW USER %s un=%s", u_key, from_user.first_name) 
            self._tdb.put(u_key,{'type':'user','name':from_user.first_name,'last_name': from_user.last_name})
            return True
        return False

    def is_user_with_name(self,name):
        try:
            return self._tdb.contains_key(name,index='name')
        except Exception as ex:
            return False

    def check_member_add_left(self,updates):
        # for update in updates:'new_chat_member': None, 'new_chat_members': None, 'left_chat_member'
        for update in updates:
            if update.message.new_chat_member is not None:
                # new_chat_member {'id': 1205652427, 'is_bot': True, 'first_name': 'Mongoose', 'username': 'Shiva64_bot', 'last_name': None, 'language_code': None}
                if self.check_user(update.message.new_chat_member):
                    # make new wallet
                    new_chat_member = update.message.new_chat_member
                    LOGGER.info('new_chat_member7 %s',new_chat_member)
                    minfo = BotMessage(update.message.message_id,update.message.chat.id,new_chat_member.id,new_chat_member.first_name,new_chat_member.last_name,'smalltalk.agent.create_wallet',1.0,None,None)
                    self.intent_handler(minfo)
            if update.message.new_chat_members is not None:
                #new_chat_members [<telebot.types.User object at 0x7fd4b19e2d68>]
                LOGGER.info('new_chat_members %s',update.message.new_chat_members)
            if update.message.left_chat_member is not None:
                left_chat_member = update.message.left_chat_member 
                LOGGER.info('del left_chat_member %s from DB',left_chat_member)
                self._tdb.delete(str(left_chat_member.id))

    def add_intent_handler(self,intent_name,intent_handler):
        """
        add handler for intention
        """
        self._intent_handlers[intent_name] = intent_handler

    def intent_handler(self,minfo):
        # put intention into queue
        self._bgt_queue.put(minfo)
        LOGGER.info('RUN HANDLER FOR=%s size=%s',minfo.intent,self._bgt_queue.qsize())
    
    async def intent_hello(self,minfo):
        """
        Reply on hello
        """ 
        self._bot.send_message(minfo.chat_id, 'Чем могу помочь, мой {} {}?'.format('создатель' if minfo.user_first_name == 'Stan' else 'господин',minfo.user_first_name),reply_to_message_id=0)
        try:
            photo = self._bot.get_user_profile_photos(minfo.user_id,0,1)                                                                                                                               
            p1 = photo.photos[0][0]                                                                                                                                                                
            LOGGER.info('photo=%s',photo.photos[0][0])                                                                                                                                                               
            #file = self._bot.get_file(p1.file_id)                                                                                                                                                        
            #fnm = 'https://api.telegram.org/file/bot'+TOKEN+'/'+file.file_path                                                                                                                     
            self._bot.send_photo(minfo.chat_id,p1.file_id)  
        except Exception as ex:
            LOGGER.info("Cant get user photo mess (%s)",ex)

        LOGGER.info("Пришел {}".format(minfo.user_first_name))  
        try:                                                                                                                              
            self._bot.pin_chat_message(minfo.chat_id,minfo.message_id)  
        except Exception as ex:                                                                                                                                                                               
            LOGGER.info("Cant pin message %s",ex)                                                                                                                                

    async def intent_bye(self,minfo):
        self.send_message(minfo.chat_id, 'Заходи еще {}'.format('создатель' if minfo.user_first_name == 'Stan' else 'господин')) 

    async def intent_help(self,minfo):
        LOGGER.info('INTENT HELP chat_id=%s confidence=%s\n',minfo.chat_id,minfo.confidence)
        response = await self._query_validator(
            Message.CLIENT_HEADS_GET_REQUEST,
            client_heads_pb2.ClientHeadsGetResponse,
            client_heads_pb2.ClientHeadsGetRequest(head_id=''))
        self.send_message(minfo.chat_id, 'Посмотри: {}'.format(response))
        LOGGER.info('response HELP=%s\n',response)
        
    async def intent_chat_admins(self,minfo):
        #self._bot.send_message(minfo.chat_id, 'Посмотрю : {}'.format(response))
        try:
            repl = self._bot.get_chat_administrators(minfo.chat_id)
            LOGGER.info('admins :%s\n',repl)
        except Exception as ex:      
            #{"ok":false,"error_code":400,"description":"Bad Request:                                                                                                                                                                         
            LOGGER.info("cant get admins %s",ex)

    async def intent_get_users(self,minfo):
        users = ''
        with self._tdb.cursor(index='name') as curs:
            #values = list(curs.iter())
            for val in curs.iter():
                if val['type'] == 'user':
                    users += val['name']+','
        self.send_message(minfo.chat_id, 'Я знаю вот кого : {}'.format(users))        

    async def intent_hold_on(self,minfo):
        LOGGER.info('INTENT HOLD ON chat_id=%s confidence=%s\n',minfo.chat_id,minfo.confidence)

    async def intent_needs_advice(self,minfo):
        LOGGER.info('INTENT NEEDS_ADVICE chat_id=%s confidence=%s\n',minfo.chat_id,minfo.confidence)
        response = await self._query_validator(
            Message.CLIENT_PEERS_GET_REQUEST,
            client_peers_pb2.ClientPeersGetResponse,
            client_peers_pb2.ClientPeersGetRequest())
        
        self.send_message(minfo.chat_id, 'Посмотри: {}'.format(response))

    async def intent_pause(self,minfo):
         LOGGER.info('INTENT PAUSE chat_id=%s confidence=%s\n',minfo.chat_id,minfo.confidence)
         self.is_pause = True

    async def intent_unpause(self,minfo):
         LOGGER.info('INTENT UNPAUSE chat_id=%s confidence=%s\n',minfo.chat_id,minfo.confidence)
         self.is_pause = False
    @staticmethod
    def _parse_response(proto, response):
        """Parses the content from a validator response Message.
        """
        try:
            content = proto()
            content.ParseFromString(response.content)
            return content
        except (DecodeError, AttributeError):
            LOGGER.error('Validator response was not parsable: %s', response)
            return None
            #raise errors.ValidatorResponseInvalid()


    async def _query_validator(self, request_type, response_proto,payload, error_traps=None):
        """
        Sends a request to the validator and parses the response.
        """
        LOGGER.debug('Sending %s request to validator',self._get_type_name(request_type))

        payload_bytes = payload.SerializeToString()
        
        response = await self._send_request(request_type, payload_bytes)
        
        """
        #response = self._loop.run_until_complete(self._send_request(request_type, payload_bytes))
        resp = []
        async def send_request():
            return await self._send_request(request_type, payload_bytes)
        async def send_task(resp):
            task = self._loop.create_task(send_request())
            response = await task 
            resp.append(response)
            LOGGER.debug('Sending request finished %s',response)
        return None
        #self._loop.run_until_complete(send_task(resp))
        response = resp.pop()
        """
        LOGGER.debug('response %s',type(response))
        #task = asyncio.ensure_future(self._send_request(request_type, payload_bytes))
        #response = asyncio.wait(task)
        #response = await self._send_request(request_type, payload_bytes)
        #response =  self._send_request(request_type, payload_bytes)
        content = self._parse_response(response_proto, response)
        if content is not None:
            LOGGER.debug(
            'Received %s response from validator with status %s',
            self._get_type_name(response.message_type),
            self._get_status_name(response_proto, content.status))
            self._check_status_errors(response_proto, content, error_traps)
            return self._message_to_dict(content)

    async def _send_request(self, request_type, payload):
        """Uses an executor to send an asynchronous ZMQ request to the
        validator with the handler's Connection
        """
        try:
            return await self._connection.send( # await
                message_type=request_type,
                message_content=payload,
                timeout=self._timeout)
        except DisconnectError:
            LOGGER.warning('Validator disconnected while waiting for response')
            # reconnect
            self.change_gateway(self._conn_n)
            #raise errors.ValidatorDisconnected()
        except asyncio.TimeoutError:
            LOGGER.warning('Timed out while waiting for validator response')
            self.change_gateway(self._conn_n)
            #raise errors.ValidatorTimedOut()
        except SendBackoffTimeoutError:
            LOGGER.warning('Failed sending message - Backoff timed out')
            raise errors.SendBackoffTimeout()

    def change_gateway(self,num):
        
        url = self._connects[num]
        try:
            self._connection.reopen(url)
            self._conn_n = num
        except:
            pass
        return self._conn_n == num

    

    @staticmethod
    def _check_status_errors(proto, content, error_traps=None):
        """Raises HTTPErrors based on error statuses sent from validator.
        Checks for common statuses and runs route specific error traps.
        """
        if content.status == proto.OK:
            return

        try:
            if content.status == proto.INTERNAL_ERROR:
                raise errors.UnknownValidatorError()
        except AttributeError:
            # Not every protobuf has every status enum, so pass AttributeErrors
            pass

        try:
            if content.status == proto.NOT_READY:
                raise errors.ValidatorNotReady()
        except AttributeError:
            pass

        try:
            if content.status == proto.NO_ROOT:
                raise errors.HeadNotFound()
        except AttributeError:
            pass

        try:
            if content.status == proto.INVALID_PAGING:
                raise errors.PagingInvalid()
        except AttributeError:
            pass

        try:
            if content.status == proto.INVALID_SORT:
                raise errors.SortInvalid()
        except AttributeError:
            pass

        # Check custom error traps from the particular route message
        if error_traps is not None:
            for trap in error_traps:
                trap.check(content.status)


    @staticmethod
    def _message_to_dict(message):
        """Converts a Protobuf object to a python dict with desired settings.
        """
        return MessageToDict(
            message,
            including_default_value_fields=True,
            preserving_proto_field_name=True)

    @staticmethod
    def _get_type_name(type_enum):
        return Message.MessageType.Name(type_enum)

    @staticmethod
    def _get_status_name(proto, status_enum):
        try:
            return proto.Status.Name(status_enum)
        except ValueError:
            return 'Unknown ({})'.format(status_enum)

    def _drop_empty_props(self, item):
        """Remove properties with empty strings from nested dicts.
        """
        if isinstance(item, list):
            return [self._drop_empty_props(i) for i in item]
        if isinstance(item, dict):
            return {
                k: self._drop_empty_props(v)
                for k, v in item.items() if v != ''
            }
        return item

    def _drop_id_prefixes(self, item):
        """Rename keys ending in 'id', to just be 'id' for nested dicts.
        """
        if isinstance(item, list):
            return [self._drop_id_prefixes(i) for i in item]
        if isinstance(item, dict):
            return {
                'id' if k.endswith('id') else k: self._drop_id_prefixes(v)
                for k, v in item.items()
            }
        return item
    def can_talk(self,intent):
        return not self.is_pause or (intent == "smalltalk.agent.unpause")
    async def validator_task(self):
        try:                                                                                                                 
            LOGGER.debug("validator_task:queue...")       
            while True:  
                await self.process_queue()                                                                                                    
                                                                                                                     
        # pylint: disable=broad-except                                                                                       
        except Exception as exc:                                                                                             
            LOGGER.exception(exc)                                                                                            
            LOGGER.critical("validator_task thread exited with error.")                                                      

    async def process_queue(self):
        try:                                                      
            request = self._bgt_queue.get(timeout=0.01)            
            LOGGER.debug("VALIDATOR_TASK: intent=%s qsize=%s pause=%s",request.intent,self._bgt_queue.qsize(),self.is_pause)   
            if self.can_talk(request.intent):
                await self._intent_handlers[request.intent](request)   
        except queue.Empty:
            pass
        except  errors.ValidatorDisconnected:
            LOGGER.debug("VALIDATOR Disconnected")
            self.send_message(request.chat_id, 'Похоже BGT временно не доступен (:')
        except KeyError as key:
            LOGGER.debug("VALIDATOR_TASK: ignore=%s (no handler %s)",request.intent,key)
            #LOGGER.debug("VALIDATOR_TASK:queue=%s EMPTY",self._bgt_queue.qsize())
            #return         


    def start(self):
        
        async def main_task():
            LOGGER.info('START MAIN...')
            while True:
                await asyncio.sleep(FLUSH_TIMEOUT)
        
        def bot_poll():
            LOGGER.info('START BOT via=%s',PROXIES[0])
            self._bot.polling()
            LOGGER.info('STOP BOT')
        
        
        self._pool = ThreadPoolExecutor(max_workers=2) #ProcessPoolExecutor(max_workers=2)
        self._start_bot()
        #self._pool = ProcessPoolExecutor(max_workers=2)
        #self._pool.submit(self._start_bot())
        #self._pool.start()
        #task = loop.create_task(self.validator_task())
        #task1 = loop.create_task(self._polling())
        #loop.run_in_executor(self._pool,task1)
        #loop.run_in_executor(self._pool,task)
        LOGGER.info('START ...')
        #self._bgt_queue.put('smalltalk.agent.can_you_help')
        self._loop.run_until_complete(self._polling()) #main_task())
        #loop.run_until_complete(main_task())
        #LOGGER.info('START')
        #self._start_bot_start_bot()
        LOGGER.info('STOP')
        self._loop.close()
        LOGGER.info('STOP DONE')

#
"""
{'content_type': 'sticker', 'message_id': 17, 'from_user': {'id': 456125525, 'is_bot': False, 'first_name': 'Stan', 'username': 'Thou_shalt', 'last_name': 'P', 'language_code': 'ru'}, 'date': 1587126688, 'chat': {'type': 'private', 'last_name': 'P', 'first_name': 'Stan', 'username': 'Thou_shalt', 'id': 456125525, 'title': None, 'all_members_are_administrators': None, 'photo': None, 'description': None, 'invite_link': None, 'pinned_message': None, 'sticker_set_name': None, 'can_set_sticker_set': None}, 'forward_from_chat': None, 'forward_from_message_id': None, 'forward_from': None, 'forward_date': None, 'reply_to_message': None, 'edit_date': None, 'media_group_id': None, 'author_signature': None, 'text': None, 'entities': None, 'caption_entities': None, 'audio': None, 'document': None, 'photo': None, 'sticker': {'file_id': 'CAACAgIAAxkBAAMRXpmhoAlC4ghzi1DpcbrNLuIJbaMAAgMAA8A2TxOkKe7mffPAeBgE', 'width': 512, 'height': 512, 'thumb': <telebot.types.PhotoSize object at 0x7f7e51f3f2b0>, 'emoji': '😨', 'set_name': 'HotCherry', 'mask_position': None, 'file_size': 12727, 'is_animated': True}, 'video': None, 'video_note': None, 'voice': None, 'caption': None, 'contact': None, 'location': None, 'venue': None, 'animation': None, 'new_chat_member': None, 'new_chat_members': None, 'left_chat_member': None, 'new_chat_title': None, 'new_chat_photo': None, 'delete_chat_photo': None, 'group_chat_created': None, 'supergroup_chat_created': None, 'channel_chat_created': None, 'migrate_to_chat_id': None, 'migrate_from_chat_id': None, 'pinned_message': None, 'invoice': None, 'successful_payment': None, 'connected_website': None, 'json': {'message_id': 17, 'from': {'id': 456125525, 'is_bot': False, 'first_name': 'Stan', 'last_name': 'P', 'username': 'Thou_shalt', 'language_code': 'ru'}, 'chat': {'id': 456125525, 'first_name': 'Stan', 'last_name': 'P', 'username': 'Thou_shalt', 'type': 'private'}, 'date': 1587126688, 'sticker': {'width': 512, 'height': 512, 'emoji': '😨', 'set_name': 'HotCherry', 'is_animated': True, 'thumb': {'file_id': 'AAMCAgADGQEAAxFemaGgCULiCHOLUOlxus0u4gltowACAwADwDZPE6Qp7uZ988B4AAHthQ8ABAEAB20AA8eUAAIYBA', 'file_unique_id': 'AQAE7YUPAATHlAAC', 'file_size': 4448, 'width': 128, 'height': 128}, 'file_id': 'CAACAgIAAxkBAAMRXpmhoAlC4ghzi1DpcbrNLuIJbaMAAgMAA8A2TxOkKe7mffPAeBgE', 'file_unique_id': 'AgADAwADwDZPEw', 'file_size': 12727}}}
################################
{'update_id': 674365978, 'message': {'content_type': 'text', 'message_id': 1723, 'from_user': <telebot.types.User object at 0x7fc7d2dcb240>, 'date': 1587888825, 'chat': <telebot.types.Chat object at 0x7fc7d2dcb128>, 'forward_from_chat': None, 'forward_from_message_id': None, 'forward_from': None, 'forward_date': None, 'reply_to_message': None, 'edit_date': None, 'media_group_id': None, 'author_signature': None, 'text': 'Как успехи', 'entities': None, 'caption_entities': None, 'audio': None, 'document': None, 'photo': None, 'sticker': None, 'video': None, 'video_note': None, 'voice': None, 'caption': None, 'contact': None, 'location': None, 'venue': None, 'animation': None, 'new_chat_member': None, 'new_chat_members': None, 'left_chat_member': None, 'new_chat_title': None, 'new_chat_photo': None, 'delete_chat_photo': None, 'group_chat_created': None, 'supergroup_chat_created': None, 'channel_chat_created': None, 'migrate_to_chat_id': None, 'migrate_from_chat_id': None, 'pinned_message': None, 'invoice': None, 'successful_payment': None, 'connected_website': None, 'json': {'message_id': 1723, 'from': {'id': 456125525, 'is_bot': False, 'first_name': 'Stan', 'last_name': 'P', 'username': 'Thou_shalt', 'language_code': 'ru'}, 'chat': {'id': 456125525, 'first_name': 'Stan', 'last_name': 'P', 'username': 'Thou_shalt', 'type': 'private'}, 'date': 1587888825, 'text': 'Как успехи'}}, 'edited_message': None, 'channel_post': None, 'edited_channel_post': None, 'inline_query': None, 'chosen_inline_result': None, 'callback_query': None, 'shipping_query': None, 'pre_checkout_query': None}
################################
sticker_message {'content_type': 'sticker', 'message_id': 1725, 'from_user': {'id': 456125525, 'is_bot': False, 'first_name': 'Stan', 'username': 'Thou_shalt', 'last_name': 'P', 'language_code': 'ru'}, 'date': 1587888938, 'chat': {'type': 'private', 'last_name': 'P', 'first_name': 'Stan', 'username': 'Thou_shalt', 'id': 456125525, 'title': None, 'all_members_are_administrators': None, 'photo': None, 'description': None, 'invite_link': None, 'pinned_message': None, 'sticker_set_name': None, 'can_set_sticker_set': None}, 'forward_from_chat': None, 'forward_from_message_id': None, 'forward_from': None, 'forward_date': None, 'reply_to_message': None, 'edit_date': None, 'media_group_id': None, 'author_signature': None, 'text': None, 'entities': None, 'caption_entities': None, 'audio': None, 'document': None, 'photo': None, 'sticker': {'file_id': 'CAACAgIAAxkBAAIGvV6lQyo1b6Yvtzi3uKcGj47RiUdcAALCAQACVp29Cpl4SIBCOG2QGQQ', 'width': 512, 'height': 512, 'thumb': <telebot.types.PhotoSize object at 0x7fc7d005ef60>, 'emoji': '👍', 'set_name': 'TheVirus', 'mask_position': None, 'file_size': 7420, 'is_animated': True}, 'video': None, 'video_note': None, 'voice': None, 'caption': None, 'contact': None, 'location': None, 'venue': None, 'animation': None, 'new_chat_member': None, 'new_chat_members': None, 'left_chat_member': None, 'new_chat_title': None, 'new_chat_photo': None, 'delete_chat_photo': None, 'group_chat_created': None, 'supergroup_chat_created': None, 'channel_chat_created': None, 'migrate_to_chat_id': None, 'migrate_from_chat_id': None, 'pinned_message': None, 'invoice': None, 'successful_payment': None, 'connected_website': None, 'json': {'message_id': 1725, 'from': {'id': 456125525, 'is_bot': False, 'first_name': 'Stan', 'last_name': 'P', 'username': 'Thou_shalt', 'language_code': 'ru'}, 'chat': {'id': 456125525, 'first_name': 'Stan', 'last_name': 'P', 'username': 'Thou_shalt', 'type': 'private'}, 'date': 1587888938, 'sticker': {'width': 512, 'height': 512, 'emoji': '👍', 'set_name': 'TheVirus', 'is_animated': True, 'thumb': {'file_id': 'AAMCAgADGQEAAga9XqVDKjVvpi-3OLe4pwaPjtGJR1wAAsIBAAJWnb0KmXhIgEI4bZB6wdWRLgADAQAHbQADeiIAAhkE', 'file_unique_id': 'AQADesHVkS4AA3oiAAI', 'file_size': 6186, 'width': 128, 'height': 128}, 'file_id': 'CAACAgIAAxkBAAIGvV6lQyo1b6Yvtzi3uKcGj47RiUdcAALCAQACVp29Cpl4SIBCOG2QGQQ', 'file_unique_id': 'AgADwgEAAladvQo', 'file_size': 7420}}}

+++++++++++++++++++++++++++++++++=
{'message_id': 1798, 'from': {'id': 456125525, 'is_bot': False, 'first_name': 'Stan', 'last_name': 'P', 'username': 'Thou_shalt', 'language_code': 'ru'}, 'chat': {'id': 456125525, 'first_name': 'Stan', 'last_name': 'P', 'username': 'Thou_shalt', 'type': 'private'}, 'date': 1587914988, 'sticker': {'width': 512, 'height': 512, 'emoji': '👍', 'set_name': 'TheVirus', 'is_animated': True, 'thumb': {'file_id': 'AAMCAgADGQEAAgcGXqWo7KbDR7NPdeq-Ish0T_k2e2wAAsIBAAJWnb0KmXhIgEI4bZB6wdWRLgADAQAHbQADeiIAAhkE', 'file_unique_id': 'AQADesHVkS4AA3oiAAI', 'file_size': 6186, 'width': 128, 'height': 128}, 'file_id': 'CAACAgIAAxkBAAIHBl6lqOymw0ezT3XqviLIdE_5NntsAALCAQACVp29Cpl4SIBCOG2QGQQ', 'file_unique_id': 'AgADwgEAAladvQo', 'file_size': 7420}}
"""
