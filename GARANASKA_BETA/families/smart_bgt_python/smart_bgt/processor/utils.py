# Copyright 2018 NTRLab
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
import hashlib

FAMILY_NAME = 'smart-bgt'
FAMILY_VER  = '1.0'
SMART_BGT_META = 'BGX_Token'
SMART_BGT_CREATOR_KEY = 'creator_key'
SMART_BGT_FEE = 5 
SMART_BGT_PRESENT_AMOUNT = 7
SMART_BGT_ADDRESS_PREFIX = hashlib.sha512(FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]


def make_smart_bgt_address(name):
    return SMART_BGT_ADDRESS_PREFIX + hashlib.sha512(name.encode('utf-8')).hexdigest()[-64:]



