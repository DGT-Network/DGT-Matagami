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
import  os
import json
from base64 import b64encode
from http.client import RemoteDisconnected
import requests

# pylint: disable=no-name-in-module,import-error
# needed for the google.protobuf imports to pass pylint
from google.protobuf.message import Message as BaseMessage

from dgt_cli.exceptions import CliException
from dgt_sdk.oauth.requests import OAuth2Session


DEFAULT_URL = 'https://api-dgt-c1-1:8108' 

DGT_API_URL = os.environ.get('DGT_API_URL',DEFAULT_URL) or DEFAULT_URL

HTTPS_SRV_KEY = '/project/peer/keys/http_srv.key'  
HTTPS_SRV_CERT = '/project/peer/keys/http_srv.crt'




class RestClient:
    def __init__(self, base_url=None, user=None,token=None,client=None,scopes=None):
        self._base_url = base_url or DGT_API_URL
        
        if user:
            b64_string = b64encode(user.encode()).decode()
            self._auth_header = 'Basic {}'.format(b64_string)
        else:
            self._auth_header = None

        # request oauth client   
        
        self._scopes = scopes 
        self._client = client                                                                   
        self._username = None
        self._password = None
        self._cert = (HTTPS_SRV_CERT, HTTPS_SRV_KEY) if self._base_url.startswith("https://") else None
        if user:
            up = user.split(':')
            self._username = up[0]
            if len(up) > 1:
                self._password = up[1]

        
        self._requests = OAuth2Session(client=None, 
                              client_id=client if token is None else None,                       
                              scope =scopes if token is None else None,                             
                              token = {'access_token': token} if token is not None else None, 
                              grant_type = 'password'  if token is None else None,
                              cert=self._cert                         
                              #redirect_uri='http://127.0.0.1:8003/calendar',                 
                              #**dgt_data                                                     
                              )                                                               
    def list_blocks(self, limit=None):
        """Return a block generator.

        Args:
            limit (int): The page size of requests
        """
        return self._get_data('/blocks', limit=limit)

    def get_block(self, block_id):
        return self._get('/blocks/' + block_id)['data']

    def list_batches(self,args):
        add_url = '/batches'
            
        return self._get_data(add_url,limit=args.limit,start=args.start)

    def get_batch(self, batch_id):
        return self._get('/batches/' + batch_id)['data']

    def list_peers(self):
        return self._get('/peers')['data']

    def list_dag(self):
        return self._get('/dag')['data']

    def get_dag(self,head_id):
        return self._get('/dag/' + head_id)['data']

    def get_token(self):
        dgt_data = {     #'code': 'json',                                              
                         #'grant_type': 'password', #'authorization_code',             
                         # 'username': 'john',                                         
                         #'password':  'doe',                                          
                         'scope'  :  self._scopes                                            
                         #'redirect_uri': 'http://127.0.0.1:8003/calendar'             
                }                                                                      
        turl = '{}/token'.format(self._base_url)
        #print("TURL",turl)
        resp = self._requests.fetch_token(
                    token_url= turl, 
                    code='json',                                                                                     
                    #auth=auth,                                                                                      
                    client_id=self._client,                                                                             
                    #client_secret=client_secret,                                                                    
                    username=self._username ,                                                                              
                    password=self._password ,
                    verify=False,cert=self._cert,                                                                              
                    **dgt_data                                                                                       
                 )                                                                                                                             
        return resp     

    def list_token(self):                  
        return self._get('/token_list') 

    def del_token(self,token_id):              
        return self._get('/del_token/'+token_id)

    def get_status(self):
        return self._get('/status')['data']

    def list_transactions(self):
        return self._get_data('/transactions')

    def get_transaction(self, transaction_id):
        return self._get('/transactions/' + transaction_id)['data']

    def list_state(self, subtree=None, head=None):
        return self._get('/state', address=subtree, head=head)

    def get_leaf(self, address, head=None):
        return self._get('/state/' + address, head=head)

    def get_statuses(self, batch_ids, wait=None):
        """Fetches the committed status for a list of batch ids.

        Args:
            batch_ids (list of str): The ids to get the status of.
            wait (optional, int): Indicates that the api should wait to
                respond until the batches are committed or the specified
                time in seconds has elapsed.

        Returns:
            list of dict: Dicts with 'id' and 'status' properties
        """
        return self._post('/batch_statuses', batch_ids, wait=wait)['data']

    def send_batches(self, batch_list):
        """Sends a list of batches to the validator.

        Args:
            batch_list (:obj:`BatchList`): the list of batches

        Returns:
            dict: the json result data, as a dict
        """
        if isinstance(batch_list, BaseMessage):
            batch_list = batch_list.SerializeToString()

        return self._post('/batches', batch_list)

    def _get(self, path, **queries):
        code, json_result = self._submit_request(
            self._base_url + path,
            params=self._format_queries(queries),
        )

        # concat any additional pages of data
        while code == 200 and 'next' in json_result.get('paging', {}):
            previous_data = json_result.get('data', [])
            code, json_result = self._submit_request(
                json_result['paging']['next'])
            json_result['data'] = previous_data + json_result.get('data', [])

        if code == 200:
            return json_result
        if code == 404:
            raise CliException('{}: There is no resource with the identifier "{}"'.format(self._base_url, path.split('/')[-1]))

        raise CliException("{}: {} {}".format(self._base_url, code, json_result))

    def _get_data(self, path, **queries):
        url = self._base_url + path
        params = self._format_queries(queries)

        while url:
            code, json_result = self._submit_request(
                url,
                params=params,
            )

            if code == 404:
                raise CliException(
                    '{}: There is no resource with the identifier "{}"'.format(
                        self._base_url, path.split('/')[-1]))
            elif code != 200:
                raise CliException(
                    "{}: {} {}".format(self._base_url, code, json_result))

            for item in json_result.get('data', []):
                yield item

            url = json_result['paging'].get('next', None)

    def _post(self, path, data, **queries):
        if isinstance(data, bytes):
            headers = {'Content-Type': 'application/octet-stream'}
        else:
            data = json.dumps(data).encode()
            headers = {'Content-Type': 'application/json'}
        headers['Content-Length'] = '%d' % len(data)

        code, json_result = self._submit_request(
            self._base_url + path,
            params=self._format_queries(queries),
            data=data,
            headers=headers,
            method='POST')

        if code in (200, 201, 202):
            return json_result

        raise CliException("({}): {}".format(code, json_result))

    def _submit_request(self, url, params=None, data=None, headers=None, method="GET"):
        """Submits the given request, and handles the errors appropriately.

        Args:
            url (str): the request to send.
            params (dict): params to be passed along to get/post
            data (bytes): the data to include in the request.
            headers (dict): the headers to include in the request.
            method (str): the method to use for the request, "POST" or "GET".

        Returns:
            tuple of (int, str): The response status code and the json parsed
                body, or the error message.

        Raises:
            `CliException`: If any issues occur with the URL.
        """
        if headers is None:
            headers = {}

        if self._auth_header is not None:
            headers['Authorization'] = self._auth_header

        try:
            if method == 'POST':
                result = self._requests.post(url, params=params, data=data, headers=headers,verify=False)
            elif method == 'GET':
                result = self._requests.get(url, params=params, data=data, headers=headers,verify=False)

            result.raise_for_status()
            return (result.status_code, result.json())
        except requests.exceptions.HTTPError as e:
            return (e.response.status_code, e.response.reason)
        except RemoteDisconnected as e:
            raise CliException(e)
        except (requests.exceptions.MissingSchema,
                requests.exceptions.InvalidURL) as e:
            raise CliException(e)
        except requests.exceptions.ConnectionError as e:
            raise CliException(
                ('Unable to connect to "{}": '
                 'make sure URL is correct').format(self._base_url))

    @staticmethod
    def _format_queries(queries):
        queries = {k: v for k, v in queries.items() if v is not None}
        return queries if queries else ''
