# Copyright 2020 DGT NETWORK INC 
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
import dialogflow_v2 as dialogflow
LOGGER = logging.getLogger(__name__)

class Dflow(object):
    def __init__(self, project_id,session_id):
        self.session_client = dialogflow.SessionsClient() 
        self.session = self.session_client.session_path(project_id, session_id)
        LOGGER.info('Session path:%s',self.session)
        

    def detect_intent_text(self,text,language_code):
        text_input = dialogflow.types.TextInput(text=text, language_code=language_code)
        query_input = dialogflow.types.QueryInput(text=text_input)
        try:
            response = self.session_client.detect_intent(session=self.session, query_input=query_input)
            LOGGER.info('{} {}'.format('=' * 20,language_code))                                                                    
            LOGGER.info('Query text: %s',response.query_result.query_text)                   
            LOGGER.info('Detected intent: {} (confidence: {})\n'.format(response.query_result.intent.display_name,response.query_result.intent_detection_confidence))                            
            LOGGER.info('Fulfillment text: %s(%s)\n',response.query_result.fulfillment_text,round(response.query_result.intent_detection_confidence,2)) 
            
            return response
        except Exception as e:
            LOGGER.info('detect  error(%s)',e)
            return None

def detect_intent_texts(project_id, session_id, texts, language_code):
    """Returns the result of detect intent with texts as inputs.

    Using the same `session_id` between requests allows continuation
    of the conversation."""
    dflow = Dflow(project_id,session_id)
    

    for text in texts:
        dflow.detect_intent_text(text,language_code)
        

p_id = 'small-talk-wfkygw'
s_id = '123456789'
key='3b6d8e29ed33fbdb7bc48ebefb212ccc7ccb16b7'
if __name__ == "__main__":
    detect_intent_texts(p_id,s_id,["Как дела","Не кури","С праздником"],'ru')
