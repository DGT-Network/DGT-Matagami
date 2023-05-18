# Copyright 2023 DGT NETWORK INC © Stanislav Parsov
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
from .oauth2 import oauth_middleware,AioHttpOAuth2Server,OAuth2_RequestValidator,create_token_response,verify_request,AUTH_SCOPE_LIST,AUTH_USER_LIST,AUTH_CONFIG_NM
from .oauth2 import setup as setup_oauth                                                                               
