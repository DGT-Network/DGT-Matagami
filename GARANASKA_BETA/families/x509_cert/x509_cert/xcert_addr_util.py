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

import hashlib
from x509_cert.client_cli.xcert_attr import FAMILY_NAME

XCERT_ADDRESS_PREFIX = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]      
                                                                                         
                                                                                         
def make_xcert_address(name):                                                            
    return XCERT_ADDRESS_PREFIX + hashlib.sha512(name.encode('utf-8')).hexdigest()[-64:] 

