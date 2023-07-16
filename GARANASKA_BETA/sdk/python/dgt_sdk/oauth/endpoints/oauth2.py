import functools
import json
from oauthlib.common import add_params_to_uri
from oauthlib.oauth2 import FatalClientError
from oauthlib.oauth2 import OAuth2Error,RequestValidator
from aiohttp import web,BasicAuth,hdrs

from requests import auth as req_auth
from aiohttp_session import get_session
from yarl import URL
import logging

log = logging.getLogger(__name__)
OAUTH_KEY = 'aiohttp_oauth_policy'
AUTH_SCOPE_LIST = '_scopes_'
AUTH_USER_LIST ='_users_'
AUTH_CONFIG_NM = 'oauth_conf.json'

async def extract_params(arequest):
    """Extract request informations to oauthlib implementation.
    HTTP Authentication Basic is read but overloaded by payload, if any.

    returns tuple of :
    - url
    - method
    - body (or dict)
    - headers (dict)
    """
    #auth = BasicAuth('')
    # this returns (None, None) for Bearer Token.
    #body = await arequest.text()
    forms = await arequest.post()
    #print("query",arequest.query)
    """
    for i,v in arequest.query.items():
        print("q[{}]={}".format(i,v))
    for i,v in forms.items(): 
        print("F[{}]={}".format(i,v)) 
    """ 
    username,password = None,None
    auth_header = arequest.headers.get(hdrs.AUTHORIZATION)
    if auth_header is not None:
        #print('Authorization={}'.format(arequest.headers['Authorization']))
        try:
            
            rauth = BasicAuth.decode(auth_header)
            #print('rauth={}'.format(auth_header))
            username,password = rauth.login,rauth.password
        except ValueError:
            pass
    
    print('username={}, password=/{}/ h={}'.format(username, password,dict(arequest.headers)))
    if "application/x-www-form-urlencoded" in arequest.content_type:
        client = {}
        if username is not None:
            client["client_id"] = username
        if password is not None:
            client["client_secret"] = password
        print('forms',dict(client, **forms),type(arequest.url))
        return \
            str(arequest.url), \
            arequest.method, \
            dict(client, **forms), \
            dict(arequest.headers)

    basic_auth = {}
    try:
        body = arequest.body if arequest.body_exists   else None # and arequest.can_read_body
    except Exception:
        log.debug("Gant get body from request")
        body = None
    # TODO: Remove HACK of using body for GET requests. Use commented code below
    # once https://github.com/oauthlib/oauthlib/issues/609 is fixed.
    if username is not None:
        print('username={}, password={}'.format(username, password))
        basic_auth = {
            "Authorization": req_auth._basic_auth_str(username, password)
        }
        body = dict(client_id=username, client_secret=password)
    print('body',dict(arequest.headers, **basic_auth))
    return \
        str(arequest.url), \
        arequest.method, \
        body, \
        dict(arequest.headers, **basic_auth)


def add_params_to_request(arequest, params):
    """
    try:
        arequest.oauth
    except AttributeError:
        arequest.oauth = {}
    """
    print('add_params={}'.format(params))
    if params:
        for k, v in params.items():
            arequest[k] = v


def set_response(arequest, status, headers, dbody, force_json=False):
    """Set status/headers/body into response.

    Headers is a dict
    Body is ideally a JSON string (not dict).
    """
    if not isinstance(headers, dict):
        raise TypeError("a dict-like object is required, not {0}".format(type(headers)))
    if not dbody:                                                                     
        return                                                                       
                                                                                     
    if not isinstance(dbody, str):                                                    
        raise TypeError("a str-like object is required, not {0}".format(type(dbody))) 
    content_type = None
    charset=None
    try:                                                                                                            
        values = json.loads(dbody)                                                                                   
    except json.decoder.JSONDecodeError:                                                                            
        # consider body as string but not JSON, we stop here.                                                       
        body = dbody                                                                                 
        log.debug("Body Bottle response body created as is: %r",body)                              
    else:  # consider body as JSON                                                                                  
        # request want a json as response  
        rheaders = dict(arequest.headers)                                                                         
        if force_json is True or (                                                                                  
                "Accept" in rheaders and                                                              
                "application/json" in rheaders["Accept"]):                                            
            content_type = "application/json" 
            charset= "UTF-8"                                    
            body = dbody                                                                             
            log.debug("Body Bottle response body created as json: %r",body)                        
        else:                                                                                                       
            from urllib.parse import quote                                                                          
                                                                                                                    
            content_type = "application/x-www-form-urlencoded" 
            charset = "UTF-8"                    
            body = "&".join([                                                                       
                "{0}={1}".format(                                                                                   
                    quote(k) if isinstance(k, str) else k,                                                          
                    quote(v) if isinstance(v, str) else v                                                           
                ) for k, v in values.items()                                                                        
            ])                                                                                                      
            log.debug("Body Bottle response body created as form-urlencoded: %r", body)             




    print('content_type={} body={}'.format(content_type,body))
    return web.Response(
                status=status,
                content_type=content_type if "Content-Type" not in headers else None,
                #charset=charset,
                headers=headers,
                body=body)
    


#  Request vaidation
class Client():
    client_id  = None


class OAuth2_RequestValidator(RequestValidator):
    """dict of clients containing list of valid scopes"""
    clients_scopes = {
            "clientA": ["mail", "calendar","state"],
            "clientB": ["calendar"],
            "dgtcli": ["mail", "calendar","state"],
    }
    """dict of username containing password"""
    users_password = {
        "john": "doe",
        "foo": "bar",
        "dgt" : "matagami"
    }
    tokens_info = {
    }
    def __init__(self,db=None,users=None,scopes=None,conf=None):
        self._db = db
        self._token_expires_in = 60*60*24*90
        self._endpoints = {}
        self._create_token = "/token"

        if db is not None:
            #if AUTH_SCOPE_LIST not in db:
            if scopes is None:                       
                scopes = self.clients_scopes         
            if users is None:                        
                users = self.users_password          

            if conf is not None:
                with open(conf,"r") as cfile: 
                    try:                                   
                        aconf = json.load(cfile) 
                        scopes = aconf['clients'] 
                        users = aconf['users'] 
                        if 'token' in aconf :
                            tinfo = aconf['token']
                            if 'token_expires_in' in tinfo:
                                self._token_expires_in = tinfo['token_expires_in']
                        if 'rest' in aconf:
                            rest = aconf['rest']
                            if "endpoints" in rest:
                                self._endpoints = rest['endpoints']
                                print('end',self._endpoints)
                            if "create_token" in rest:
                                self._create_token = rest["create_token"]

                    except json.decoder.JSONDecodeError as ex:
                        print("Cant load oauth conf - {}".format(ex)) 
                        pass 
            
            for nm,scope in scopes.items():
                print('ADD CLIENT',nm)
                self._db.put("{}.{}".format(AUTH_SCOPE_LIST,nm), {'client' : nm,'scopes' : scope})
            for nm,pwd in users.items():                         
                print('ADD USER',nm)                                           
                self._db.put("{}.{}".format(AUTH_USER_LIST,nm), {'client' : nm,'pass' : pwd})  

            with db.cursor() as curs:        
                for val in curs.iter():                     
                    log.debug('TOKENS={}'.format(val))            
                     

    @property
    def token_expires_in(self):
        return self._token_expires_in

    def is_token_req(self,rpath): 
        return rpath == self._create_token  

    def get_rest_verify_scopes(self,rpath):
        if rpath in self._endpoints:
            return self._endpoints[rpath]
        elif '*' in self._endpoints:
            return self._endpoints['*']

    def client_authentication_required(self, request, *args, **kwargs):
        log.debug('client_authentication_required False')
        return False  # Allow public clients

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        log.debug('authenticate client_id {}'.format(client_id))
        is_cid = self.clients_scopes.get(client_id) if self._db is None else "{}.{}".format(AUTH_SCOPE_LIST,client_id) in self._db

        if is_cid:
            request.client = Client()
            request.client.client_id = client_id
            log.debug('OK authenticate_client_id {}'.format(client_id))
            return True
        log.debug('FALSE authenticate_client_id {}'.format(client_id))
        return False

    def validate_user(self, username, password, client, request, *args, **kwargs):
        #print('validate_user',username)
        if self._db is not None:
            ukey = "{}.{}".format(AUTH_USER_LIST,username)
            if ukey in self._db:
                info = self._db[ukey]
                request.user = username
                return password == info['pass']
        else:
            if self.users_password.get(username):
                request.user = username
                log.debug("validate_user {} {}".format(username,client))
                return password == self.users_password.get(username)
        log.debug("err validate_user",username)
        return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        log.debug('validate_grant_type {}'.format(grant_type))
        return grant_type in ["password",'authorization_code','client_credentials']

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        
        if self._db is not None:
            ckey = "{}.{}".format(AUTH_SCOPE_LIST,client_id)
            cli_scopes = self._db[ckey]['scopes'] if ckey in self._db else []
        else:
            cli_scopes = self.clients_scopes.get(client_id)
        log.debug('validate id={} scopes {}~{}'.format(client_id,scopes,cli_scopes))
        #scopes= scopes.split(':')
        return all(scope in cli_scopes for scope in scopes)

    def save_bearer_token(self, token_response, request, *args, **kwargs):
        token = token_response["access_token"]
        log.debug('SAVE_BEARER_TOKEN user={} client={} token={}'.format(request.user, request.client,token))
        tval = {
            "client": request.client.client_id,
            "user"  : request.user,
            "scopes": request.scopes
        }
        if self._db is not None:
            self._db.put(token, tval)
        else:
            self.tokens_info[token] = tval

    def validate_bearer_token(self, access_token, scopes_required, request):
        log.debug('VALIDATE_BEARER_TOKEN token={}'.format(access_token))
        if self._db is not None:
            #
            info = self._db[access_token] if access_token is not None and access_token in self._db else None
             
            
        else:
            info = self.tokens_info.get(access_token, None)
        log.debug('VALIDATE_BEARER_TOKEN token={} info={} '.format(access_token,info))
        if info:
            request.client = Client()
            request.client.client_id  = info["client"]
            request.user              = info["user"]
            request.scopes            = info["scopes"]
            return all(scope in request.scopes for scope in scopes_required)
        log.debug('VALIDATE_BEARER_TOKEN FALSE - scopes={}'.format(scopes_required))
        return False





class AioHttpOAuth2Server(object):
    def __init__(self, oauthlib,userval,error_uri=None):
        
        self._error_uri = error_uri
        self._oauthlib = oauthlib
        self._userval = userval

    def is_token_req(self,rpath):
        return self._userval.is_token_req(rpath)

    def get_rest_verify_scopes(self,rpath):
        return self._userval.get_rest_verify_scopes(rpath)

    def create_metadata_response(self):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args):
                assert self._oauthlib, "AioHttpOAuth2 not initialized with OAuthLib"
                request = args[0]
                uri, http_method, body, headers = extract_params(request)

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_metadata_response(
                        uri, http_method, body, headers
                    )
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code
                resp = set_response(request, resp_status,resp_headers, resp_body, force_json=True)

                func_response = f()
                if func_response:
                    return func_response
                return resp
            return wrapper
        return decorator

    async def create_token_response(self,request,credentials=None):
        assert self._oauthlib, "AioHttpOAuth2 not initialized with OAuthLib"

        try:                                               
            credentials_extra = credentials(request)       
        except TypeError:                                  
            credentials_extra = credentials                


        uri, http_method, body, headers = await extract_params(request)                                                                                               
        log.debug("create_token_response:url={} metod={} body={} head={} cred={}".format(uri, http_method, body, headers,credentials_extra))                              
        try:                                                                                                                                                          
            resp_headers, resp_body, resp_status = self._oauthlib.create_token_response(                                                                              
                uri, http_method, body, headers, credentials_extra                                                                                                    
            )                                                                                                                                                         
            print("create_token_response: cred={} rhead={} rbody={} rst={}".format(credentials_extra,resp_headers, resp_body, resp_status))                           
        except OAuth2Error as e:   
            log.debug("create_token_response ERROR {}",format(e))                                                                                                                                  
            resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code   
                                                                                            
        print('st={} head={} b={}'.format(type(resp_status),type(resp_headers),type(resp_body)))                                                                      
        resp = set_response(request, resp_status,resp_headers, resp_body)                                                                                             
        return resp                                                                                                                                                   

    async def verify_request(self,request,scopes=None):
        assert self._oauthlib, "AioHttpOAuth2 not initialized with OAuthLib"                                              
        # Get the list of scopes                                                                                          
        try:                                                                                                              
            scopes_list = scopes(request)                                                                                 
        except TypeError:                                                                                                 
            scopes_list = scopes                                                                                          
                                                                                                                          
        uri, http_method, body, headers = await extract_params(request)                                                   
        print('uri={}, method={}, body={}, headers={} scopes={}'.format(uri, http_method, body, headers,scopes_list))                           
        valid, req = self._oauthlib.verify_request(uri, http_method, body, headers, scopes_list)                          
        log.debug('valid={}, req={}'.format(valid, req))                                                                      
        # For convenient parameter access in the view                                                                     
        add_params_to_request(request, {                                                                                  
            'client': req.client,                                                                                         
            'user': req.user,                                                                                             
            'scopes': req.scopes                                                                                          
        })                                                                                                                
        if not valid:    
            raise web.HTTPUnauthorized()                                                                                                     


    def create_introspect_response(self):
        def decorator(f):
            @functools.wraps(f)
            async def wrapper(*args, **kwargs):
                assert self._oauthlib, "AioHttpOAuth2 not initialized with OAuthLib"
                request = args[0]
                uri, http_method, body, headers = await extract_params(request)

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_introspect_response(
                        uri, http_method, body, headers
                    )
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code
                resp = set_response(request, resp_status, resp_headers,resp_body, force_json=True)

                func_response = f(request) #*args, **kwargs)
                if func_response:
                    return func_response
                return resp
            return wrapper
        return decorator

    def create_authorization_response(self):
        def decorator(f):
            @functools.wraps(f)
            async def wrapper(*args, **kwargs):
                assert self._oauthlib, "AioHttpOAuth2 not initialized with OAuthLib"
                request = args[0]
                uri, http_method, body, headers = await extract_params(request)
                # maybe request.params is request.query
                scope = request.params.get('scope', '').split(' ')

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_authorization_response(
                        uri, http_method=http_method, body=body, headers=headers, scopes=scope
                    )
                except FatalClientError as e:
                    if self._error_uri:
                        raise web.Response(#bottle.HTTPResponse(
                            status=302, headers={"Location": add_params_to_uri(
                            self._error_uri, {'error': e.error, 'error_description': e.description}
                            )})
                    raise e
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code
                resp = set_response(request, resp_status, resp_headers, resp_body)

                func_response = f(request) #*args, **kwargs)
                if func_response:
                    return func_response
                return resp
            return wrapper
        return decorator

    def create_revocation_response(self):
        def decorator(f):
            @functools.wraps(f)
            async def wrapper(*args, **kwargs):
                assert self._oauthlib, "AioHttpOAuth2 not initialized with OAuthLib"
                request = args[0]
                uri, http_method, body, headers = await extract_params(request)

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_revocation_response(
                        uri, http_method=http_method, body=body, headers=headers
                    )
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code

                resp = set_response(request, resp_status, resp_headers, resp_body)

                func_response = f(request) #*args, **kwargs)
                if func_response:
                    return func_response
                return resp
            return wrapper
        return decorator

    def create_userinfo_response(self):
        def decorator(f):
            @functools.wraps(f)
            async def wrapper(*args, **kwargs):
                assert self._oauthlib, "AioHttpOAuth2 not initialized with OAuthLib"
                request = args[0]
                uri, http_method, body, headers = await extract_params(request)

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_userinfo_response(
                        uri, http_method=http_method, body=body, headers=headers
                    )
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code

                resp = set_response(request, resp_status, resp_headers, resp_body, force_json=True)

                func_response = f(request) #*args, **kwargs)
                if func_response:
                    return func_response
                return resp
            return wrapper
        return decorator


# oauth middleware
def setup(app: web.Application, oauth_policy: AioHttpOAuth2Server ) -> None:
    
    if not isinstance(oauth_policy, AioHttpOAuth2Server):
        raise ValueError("OAuth is not subclass of AioHttpOAuth2Server")

    app[OAUTH_KEY] = oauth_policy
    

async def create_token_response(request: web.Request,credentials=None) :
    auth = request.config_dict.get(OAUTH_KEY)
    if auth is None :
        return None
    credentials_extra = None
    resp = await auth.create_token_response(request,credentials_extra)
    return resp

async def verify_request(request: web.Request,scopes=None) -> None:               
    auth = request.config_dict.get(OAUTH_KEY)                                          
    if auth is None :                                                                  
        return None                                                                    
    await auth.verify_request(request,scopes)                     



@web.middleware                                                                                                            
async def oauth_middleware(request: web.Request,handler):# : Callable[[web.Request], Awaitable[web.Response]] 
    rpath = request.path                                                                  
    log.debug('>>> HANDLER req={} url={}'.format(request.query,request.rel_url))                                                                                
    #ses = await get_session(request) 
    auth = request.config_dict.get(OAUTH_KEY)  
    if auth.is_token_req(rpath):
        log.debug("create_token_response ...")
        resp =  await create_token_response(request) 
        user_resp = await handler(request)
        if user_resp is not None:
            resp = user_resp
    else:
        scopes = auth.get_rest_verify_scopes(rpath)
        try:
            ses = await get_session(request)
        except Exception:
            ses = None
        if ses is not None:
            if 'access_token' in request.query:
                ses['access_token'] = request.query['access_token']
            elif 'access_token' in ses:
                nq = 'access_token={}'.format(ses['access_token'])
                for arg,val in request.query.items():
                    nq += "&{}={}".format(arg,val)
                nurl = request.rel_url.with_query(nq)
                req = request.clone(rel_url=nurl)
                log.debug('COPY={} nurl={}'.format(req,nurl)) 
                request = req

        log.debug('SCOPE={} SES={}'.format(scopes,ses))
        if scopes is not None:
            # control access
            await verify_request(request,scopes=scopes)
        resp = await handler(request)
    
    
    
    log.debug('<<< HANDLER={}'.format(rpath))                                                                                   
    return resp                                                                                                            
