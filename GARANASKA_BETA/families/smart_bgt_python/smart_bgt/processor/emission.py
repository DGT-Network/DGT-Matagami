
 # Copyright 2018 NTRlab (https://ntrlab.ru)
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #      http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
 #
 # Author: Mikhail Kashchenko


import time
#import services
#import inspect

from smart_bgt.processor.services import BGXlistener
from smart_bgt.processor.crypto import BGXCrypto
from smart_bgt.processor.token import Token, MetaToken


# Prototype for a EmissionMechanism class
# without check of ethereum account

class EmissionMechanism:

    def __init__(self):
        self.type = "BGX"

    def checkEthereum(self, bgt_amount, wallet_address, bgt_price, dec_price):
        dec_amount = BGXlistener.balanceOf(wallet_address)
        return int(bgt_amount) * bgt_price <= dec_amount * dec_price

    # TODO: implement

    def getProvedHashOfClass(self):
        return True

    # TODO: implement

    def checkHashOfClass(self):
        #lines = inspect.getsource(EmissionMechanism)
        #hash = BGXCrypto.intHash(lines)
        return True



    def releaseTokens(self, name, symbol, company_id, digital_signature, ethereum_address, num_bgt, description, \
                      bgt_price = 1, dec_price = 1):

        if not self.checkEthereum(num_bgt, ethereum_address, bgt_price, dec_price):
            return None, None

        imprint = name + str(num_bgt) + str(bgt_price)
        group_code = BGXCrypto.strHash(imprint)

        meta = MetaToken(name, symbol, company_id, group_code, num_bgt, description, bgt_price, digital_signature)
        token = Token(group_code, num_bgt, digital_signature)
        return token, meta

    def releaseExtraTokens(self, token, meta_token, digital_signature, ethereum_address, num_bgt, bgt_price, dec_price):

        if not isinstance(meta_token, MetaToken):
            return None, None

        if not self.checkEthereum(num_bgt, ethereum_address, bgt_price, dec_price):
            return None, None

        if not isinstance(token, Token):
            group_code = meta.get_group_code()
            token = Token(group_code, num_bgt, digital_signature)
        else:
            token.add(num_bgt)

        meta_token.add(num_bgt)
        return token, meta_token
