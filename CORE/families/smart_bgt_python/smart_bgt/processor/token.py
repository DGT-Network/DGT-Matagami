

from smart_bgt.processor.crypto import BGXCrypto
import math
import json
import logging

from smart_bgt.processor.utils  import SMART_BGT_CREATOR_KEY
from sawtooth_sdk.processor.exceptions import InternalError

LOGGER = logging.getLogger(__name__)

BASIC_DECIMALS = 18

# Prototype for a MetaToken class.

class MetaToken:

    def __init__(self, name = 'Test', symbol = 'None', company_id = 'None', group_code = 'None', total_supply = 0, \
                 description = 'None', internal_token_price = 0, digital_signature = 'None'):

        if not name == 'Test' and not self.__checkValues(total_supply, internal_token_price, digital_signature):
            LOGGER.error("Init metatoken - wrong args")
            raise InternalError('Failed to init metatoken')

        self.name = name
        self.symbol = symbol
        self.company_id = company_id
        self.group_code = group_code
        self.total_supply = total_supply
        self.granularity = 1
        self.decimals = BASIC_DECIMALS
        self.description = description
        self.currency_code = 1
        self.internal_token_price = internal_token_price
        self.bgx_conversion = False
        self.internal_conversion = False
        self.ethereum_conversion = False

        if not name == 'Test':
            self.owner_key = digital_signature.getVerifyingKey()

    def __checkValues(self, total_supply, internal_token_price, digital_signature = None):

        if not isinstance(total_supply, int) or total_supply < 0:
            LOGGER.debug('Bad integer : total_supply')
            return False

        if not isinstance(internal_token_price, int) or internal_token_price < 0:
            LOGGER.debug('Bad integer : internal_token_price')
            return False

        if digital_signature is not None and not isinstance(digital_signature, BGXCrypto.DigitalSignature):
            LOGGER.debug('Bad digital signature')
            return False
        return True

    def toJSON(self):
        data = {'name': self.name, 'symbol': self.symbol, 'company_id': self.company_id, 'group_code': self.group_code,\
                'total_supply': str(self.total_supply), 'granularity': str(self.granularity), \
                'decimals': str(self.decimals), 'description': self.description, 'currency_code': \
                str(self.currency_code), 'internal_token_price': str(self.internal_token_price), 'bgx_conversion': \
                str(self.bgx_conversion), 'internal_conversion': str(self.internal_conversion), \
                'ethereum_conversion': str(self.ethereum_conversion),  SMART_BGT_CREATOR_KEY: self.owner_key}
        return json.dumps(data)

    def fromJSON(self, json_string):

        try:
            data = json.loads(json_string)
        except:
            LOGGER.error('Cant read json with metatoken: %s', sys.exc_info()[0])
            raise InternalError('Failed to load metatoken')

        try:
            name = data['name']
            symbol = data['symbol']
            company_id = data['company_id']
            group_code = data['group_code']
            total_supply = int(data['total_supply'])
            granularity = int(data['granularity'])
            decimals = int(data['decimals'])
            description = data['description']
            currency_code = int(data['currency_code'])
            internal_token_price = int(data['internal_token_price'])
            bgx_conversion = data['bgx_conversion']
            internal_conversion = data['internal_conversion']
            ethereum_conversion = data['ethereum_conversion']
            owner_key = data[SMART_BGT_CREATOR_KEY]
        except KeyError:
            LOGGER.error("json with metatoken has not all arg")
            raise InternalError('Failed to load metatoken')

        if not self.__checkValues(total_supply, internal_token_price):
            LOGGER.error("Init metatoken - wrong args")
            raise InternalError('Failed to init metatoken')

        self.name = name
        self.symbol = symbol
        self.company_id = company_id
        self.group_code = group_code
        self.total_supply = total_supply
        self.granularity = granularity
        self.decimals = decimals
        self.description = description
        self.currency_code = currency_code
        self.internal_token_price = internal_token_price
        self.bgx_conversion = bgx_conversion
        self.internal_conversion = internal_conversion
        self.ethereum_conversion = ethereum_conversion
        self.owner_key = owner_key

    def get_total_supply(self):
        return self.total_supply

    def get_group_code(self):
        return self.group_code

    def get_internal_token_price(self):
        return self.internal_token_price

    def get_owner_key(self):
        return self.owner_key

    def add(self, amount):
        if (not isinstance(amount, float) and not isinstance(amount, int)) or amount <= 0 or \
                pow(10, BASIC_DECIMALS) * amount < 1:
            LOGGER.debug("Add extra tokens - wrong args")
            return False

        self.total_supply += amount
        return True

# Prototype for a Token class.
# Note: must be JSON-serializable

class Token:

    def __init__(self, group_code = None, balance = 0, digital_signature = None, granularity = 1, decimals = 18):

        if group_code == None:
            self.active_flag = False
            self.group_code = 'None'
            self.balance = 0
            self.granularity = granularity
            self.decimals = decimals
            self.owner_key = 'None'
            self.sign = 'None'
        else:
            if not self.__checkValues(balance, granularity, decimals, digital_signature):
                LOGGER.error("Init token - wrong args")
                raise InternalError('Failed to init token')

            self.active_flag = True
            self.group_code = str(group_code)
            self.balance = balance
            self.granularity = granularity
            self.decimals = decimals
            self.owner_key = str(digital_signature.getVerifyingKey())
            self.sign = str(digital_signature.sign(self.getImprint()))

    def __str__(self):
        return self.getImprint()


    def getGroupId(self):
        return self.group_code

    def copy(self, token):
        self.active_flag = True
        self.group_code = token.getGroupId()
        #self.owner_key = owner_key

    def __checkValues(self, balance, granularity, decimals, digital_signature=None):

        if not isinstance(balance, int) or balance < 0:
            LOGGER.debug('Bad integer : balance')
            return False

        if not isinstance(granularity, int) or granularity < 0:
            LOGGER.debug('Bad integer : granularity')
            return False

        if not isinstance(decimals, int) or decimals < 0:
            LOGGER.debug('Bad integer : decimals')
            return False

        if digital_signature is not None and not isinstance(digital_signature, BGXCrypto.DigitalSignature):
            LOGGER.debug('Bad digital signature')
            return False
        return True

    def verifyToken(self, digital_signature):
        return digital_signature.verify(self.sign, self.getImprint())

    def getImprint(self):
        imprint = self.group_code + str(self.balance) + str(self.granularity) + \
                  str(self.decimals) + self.owner_key
        return imprint

    def toJSON(self):
        data = {'group_code': str(self.group_code), 'granularity': str(self.granularity), 'balance': str(self.balance),\
                'decimals': str(self.decimals), 'owner_key': str(self.owner_key), 'sign': str(self.sign)}
        return json.dumps(data)

    def fromJSON(self, json_string):

        try:
            data = json.loads(json_string)
        except:
            LOGGER.error('Cant read json with token: %s', sys.exc_info()[0])
            raise InternalError('Failed to load token')

        try:
            group_code = data['group_code']
            balance = int(data['balance'])
            granularity = int(data['granularity'])
            decimals = int(data['decimals'])
            owner_key = data['owner_key']
            sign = data['sign']
        except KeyError:
            LOGGER.error("json with token has not all arg")
            raise InternalError('Failed to load token')

        if not self.__checkValues(balance, granularity, decimals):
            LOGGER.error("Loading token from JSON - wrong args")
            raise InternalError('Failed to load token')

        if not self.active_flag:
            msg = 'Update "{n}"'.format(n=self.toJSON())
            LOGGER.debug(msg)

        self.active_flag = True
        self.group_code = group_code
        self.balance = balance
        self.granularity = granularity
        self.decimals = decimals
        self.owner_key = owner_key
        self.sign = sign

    def getSign(self):
        return self.sign

    def getOwnerKey(self):
        return self.owner_key

    def getBalance(self):
        return self.balance

    def get_amount(self):
        return self.balance * pow(10, self.decimals - BASIC_DECIMALS)

    def __setBalance(self, balance):
        self.balance = balance

    def getDecimals(self):
        return self.decimals

    def __setDecimals(self, decimals):
        self.decimals = decimals

    def __intToIternalFormat(self, amount):
        if amount <= 0:
            return BASIC_DECIMALS, 0

        decimals = 0
        flag = amount / 10
        while int(flag) == flag:
            amount /= 10
            flag /= 10
            decimals += 1
        return decimals, int(amount)

    def send(self, to_token, amount = 0):
        LOGGER.debug("SMART_BGT>processor>token>send"
                     "\nself=%s\nto_token=%s\namount=%s",
                     str(self), to_token, amount)

        if  not isinstance(to_token, Token) or (not isinstance(amount, float) and \
            not isinstance(amount, int)) or amount <= 0 or pow(10, BASIC_DECIMALS) * amount < 1:
            LOGGER.debug("Sending token - wrong args")
            return False

        from_decimals = self.getDecimals()
        from_balance = self.getBalance()

        to_decimals = to_token.getDecimals()
        to_balance = to_token.getBalance()

        from_amount = from_balance * pow(10, from_decimals)
        to_amount = to_balance * pow(10, to_decimals)
        send_amount = int(amount * pow(10, BASIC_DECIMALS))

        if from_amount < send_amount:
            LOGGER.debug("Sending token - not enough money")
            return False

        from_amount -= send_amount
        to_amount += send_amount
        from_decimals, from_balance = self.__intToIternalFormat(from_amount)
        to_decimals, to_balance = self.__intToIternalFormat(to_amount)

        self.__setDecimals(from_decimals)
        self.__setBalance(from_balance)
        to_token.__setDecimals(to_decimals)
        to_token.__setBalance(to_balance)
        return True

    def send_allowance(self, amount = 0):
        if (not isinstance(amount, float) and not isinstance(amount, int)) or amount <= 0 or \
                pow(10, BASIC_DECIMALS) * amount < 1:
            LOGGER.debug("Sending token allowance - wrong args")
            return False

        from_decimals = self.getDecimals()
        from_balance = self.getBalance()

        from_amount = from_balance * pow(10, from_decimals)
        send_amount = int(amount * pow(10, BASIC_DECIMALS))

        if from_amount < send_amount:
            LOGGER.debug("Sending token allowance - not enough money")
            return False
        return True

    def add(self, amount = 0):
        if (not isinstance(amount, float) and not isinstance(amount, int)) or amount <= 0 or \
                pow(10, BASIC_DECIMALS) * amount < 1:
            LOGGER.debug("Add extra tokens - wrong args")
            return False

        cur_decimals = self.getDecimals()
        cur_balance = self.getBalance()

        cur_amount = cur_balance * pow(10, cur_decimals)
        add_amount = int(amount * pow(10, BASIC_DECIMALS))

        cur_amount += add_amount
        decimals, balance = self.__intToIternalFormat(cur_amount)

        self.__setDecimals(decimals)
        self.__setBalance(balance)
        return True
