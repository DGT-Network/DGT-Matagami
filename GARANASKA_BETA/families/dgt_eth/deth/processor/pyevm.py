from eth_keys import keys

from eth_utils import decode_hex,to_bytes,to_wei,from_wei,function_abi_to_4byte_selector
from eth_abi import encode as  encode_abi
from eth_typing import Address

from eth import constants

from eth.chains.base import MiningChain
from eth.chains.ropsten import RopstenChain
from eth.consensus.pow import mine_pow_nonce

from eth.vm.forks.byzantium import ByzantiumVM

from eth.db.atomic import AtomicDB,MemoryDB
from eth.vm.forks.frontier import FrontierVM
from eth.vm.forks.frontier.blocks import FrontierBlock
from eth.chains.base import Chain
from eth.chains.base import MiningChain
from eth.consensus.pow import PowConsensus
from eth.tools.factories.transaction import (
    new_transaction,
)
from eth.tools.fixtures import (
    verify_state
)
import binascii
import logging
from collections.abc import Mapping
from .chain_plumbing import get_eth_chain,FUNDED_ADDRESS_PRIVATE_KEY,FUNDED_ADDRESS,SECOND_ADDRESS_PRIVATE_KEY,SECOND_ADDRESS

logging.basicConfig(level=8) #logging.DEBUG)

#                                                         0x4f68505f5637e475f5e242bf9d9bf303697f848f9cb37506b5cf89cf67ff79ab
sender_private_key = keys.PrivateKey(to_bytes(hexstr=   '0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8'))
sender_address = sender_private_key.public_key.to_canonical_address()
if True:
    some_private_key = FUNDED_ADDRESS_PRIVATE_KEY 
    SOME_ADDRESS = FUNDED_ADDRESS
else:
    some_private_key = keys.PrivateKey(to_bytes(hexstr=     '0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2ff'))
    SOME_ADDRESS = some_private_key.public_key.to_canonical_address()


                                                                                                                                                                                                
def check_computation(computation,title="computation",is_out=False,is_code=False):
    comput =  computation[2]                                                                                                             
    msg= comput.msg                                                                                                                                                                     
    receipt  = computation[1]                                                                                                                                                                   
    addr_contr = msg.storage_address                                                                                                                                                            
    logging.debug('{}:: {} \nreceipt={}\n msg={} storage_addr={} caddr={} TRNSF={} val={} TO={} data={} ISC={}'.format(
                        title,computation[0],receipt,msg,msg.storage_address,                            
                        msg.code_address,msg.should_transfer_value,msg.value,msg.to,msg.data.hex(),                                                          
                        msg.is_create                                                                                                                 
                ))                                                                                                                            
    try:                                                                                                                                                                                        
        logging.debug('{}:: GAS_USED={} REMAIN={} PRECOMP={}'.format(title,receipt.gas_used,
                                                                     comput.get_gas_remaining(),                                                                 
                                                                     comput.get_precompiles()))                                                                                         
    except Exception as ex:                                                                                                                                                                     
        logging.debug('{}:: err {}'.format(title,ex))                                                                                                                                           
    try:                                                                                                                                                                                        
        logging.debug('{}:: RAW ENTRIES={}   OUT={}({}) SUCCESS={} RET={} CODE={}'.format(title,
                                                                                comput.get_raw_log_entries(),                                                           
                                                                                comput.output if is_out else '**',len(comput.output),
                                                                                comput.is_success,                 
                                                                                comput.return_data,msg.code if is_code else '**'                                                        
                                                                            ))                                                                                                                  
    except Exception as ex:                                                                                                                                                                     
        logging.debug('{}::msg={} err {}'.format(title,dir(msg),ex))                                                                                                                            
    return computation[2]                                                                                                                                                                       
                                                                                                                                                                                                


class MyAtomicDB(AtomicDB):                                                  
    def __setitem__(self, key: bytes, value: bytes) -> None:                 
        logging.debug('SET DB::{}={}'.format(key.hex(),value.hex()))         
        super().__setitem__(key,value)                                       
    def __getitem__(self, key: bytes) -> bytes:                              
        logging.debug('GET DB::{}'.format(key.hex()))                        
        return super().__getitem__(key)                                      
                                                                             
class PyevmTransactionHandler():
    def __init__(self,eth_db):
        """
        init chain for py-evm
        """
        self.db = MyAtomicDB()

        
        #consensus = PowConsensus(constants.GENESIS_DIFFICULTY) 
        if True:
            self._chain = get_eth_chain(self.db,path_db=eth_db)
        else:
            self.genesis_params = {                                                                                                       
                  'difficulty': 1,                                                                                                        
                  'gas_limit': 3141592000000,                                                                                             
                  'timestamp': 1514764800,                                                                                                
              }                                                                                                                           
            acc1 =  {                                                                                                                     
                "balance": to_wei(5000000, 'ether'), #int(5000000 * (10 ** 18)) ,#to_wei(10000000, 'ether'),                              
                "nonce": 0,                                                                                                               
                "code": b'',                                                                                                              
                "storage": {}                                                                                                             
            }                                                                                                                             
                                                                                                                                          
                                                                                                                                          
                                                                                                                                          
                                                                                                                                          
            self.genesis_state = {                                                                                                        
                SOME_ADDRESS: {                                                                                                           
                    "balance": to_wei(500000000, 'ether'),                                                                                  
                    "nonce": 0,                                                                                                           
                    "code": b'',                                                                                                          
                    "storage": {}                                                                                                         
                }                                                                                                                         
                                                                                                                                          
            }                                                                                                                             

            self._chain = MiningChain.configure( # RopstenChain.configure( #                                                               
                __name__='MyChain',                                                                                                  
                                                                                                                                     
                vm_configuration=((constants.GENESIS_BLOCK_NUMBER, FrontierVM ),), #FrontierVM  ByzantiumVM                          
                #consensus_context=consensus,                                                                                        
                chain_id=1,                                                                                                          
            ).from_genesis(self.db,self.genesis_params,self.genesis_state)                                                                          
                                                                                                                                 
        # 
        genesis_blk = self._chain.get_canonical_block_header_by_number(0)
        #self._vm = self._chain.get_vm()
        changes = self._vm.state
        self.nonce_val = self._vm.state.get_nonce(FUNDED_ADDRESS)
        non = self._vm.state.get_nonce(SECOND_ADDRESS)
        #367b2ddf0d9d15e14d3dd33eeeb4f31db8cd0ce8
        logging.debug('genesis={} NONE={}~{} ADD={} \nVMSTATE={} '.format(genesis_blk,self.nonce_val,non,SOME_ADDRESS.hex(),dir(changes))#,'adb',dir(vm.state._account_db),'\nACC',vm.state._account_db.account_exists(SOME_ADDRESS)
                      )

        #self.genesis_state[sender_address] = acc1
        smart_fnm = './SimpleStorage.bin'       
        #smart_fnm = './BGXToken.bin'           
        with open(smart_fnm, 'r') as f:         
            contract_bytecode = f.read()      
        #self.create_account()
        #self.send2add(some_private_key,sender_address,100)
        #self.create_smart(some_private_key,contract_bytecode)
        self.get_direct_balance(FUNDED_ADDRESS)
        self.get_direct_balance(SECOND_ADDRESS)
        #self.test_send(2)
        self.nonce_val = non
        #self.test_send(num=2,direct=False)

        #bal,bal1 = changes.get_balance(SOME_ADDRESS),self._vm.state.get_balance(sender_address)
        #stor = changes.get_storage(SOME_ADDRESS,0)
        #logging.debug('SOME bal={} stor={} bal1={}'.format(bal,stor,bal1))

    @property
    def _vm(self):
        return self._chain.get_vm()



    def apply_transaction(self,signed_tx):
        comp = self._chain.apply_transaction(signed_tx)       
        check_computation(comp) 
        self.nonce_val += 1                              

    def main_all(self,transactions):
        try:
            mining_result, receipts, computations = self._chain.mine_all(transactions)
            #self.nonce_val += 1
            logging.debug('mining_result {}'.format(dir(mining_result)))
            #for receipt, computation in zip(receipts, computations):
            check_computation((mining_result,receipts[0],computations[0]),is_out=True)
        except Exception as ex:
            logging.debug('MAIN_ALL err -{}'.format(ex))
            raise 
            
        return mining_result, receipts, computations

    def test_send(self,num = 1,direct=True):
        logging.debug('TEST:: {} '.format(num))
        trans = []
        for i  in range(num):
            if direct:
                tx = self.make_send_tx(FUNDED_ADDRESS_PRIVATE_KEY,FUNDED_ADDRESS,SECOND_ADDRESS,100) 
            else:
                tx = self.make_send_tx(SECOND_ADDRESS_PRIVATE_KEY,SECOND_ADDRESS,FUNDED_ADDRESS,10)
            self.nonce_val += 1
            trans.append(tx)
        logging.debug('TEST:: gas limit ={} '.format(self._chain.get_block().header.gas_limit))
        mining_result, receipts, computations = self.main_all(trans)
        vm = self._vm
        non = self._vm.state.get_nonce(FUNDED_ADDRESS)
        bal,bal1 = vm.state.get_balance(FUNDED_ADDRESS),vm.state.get_balance(SECOND_ADDRESS)
        logging.debug('TEST:: NON={} {} {}'.format(non,bal,bal1))

    def get_balance(self,addr):
        #5c620004051f2439f3eb56b5242f1e41d15e7573
        private_key = keys.PrivateKey(to_bytes(hexstr=addr))
        address = private_key.public_key.to_canonical_address()


        try:
            bal = self._vm.state.get_balance(address)
        except Exception as ex:
            bal = None
            logging.debug('get_balance {} err -{}'.format(addr,ex))
        logging.debug('get_balance BAL={} '.format(bal))
        return bal

    def get_direct_balance(self,address):                                                          
        try:                                                                             
            bal = self._vm.state.get_balance(address)                                    
        except Exception as ex:                                                          
            bal = None                                                                   
            logging.debug('get_balance {} err -{}'.format(address.hex(),ex))                      
        logging.debug('get_balance BAL={} '.format(bal))                                 
        return bal                                                                       


    def create_account(self,addr=None):
        if addr:
            private_key = keys.PrivateKey(to_bytes(hexstr=addr))
            address = private_key.public_key.to_canonical_address()
            logging.debug('create_account addr={}'.format(address.hex()))
        else:
            address = sender_address
            private_key = some_private_key

        nonce = self._vm.state.get_nonce(FUNDED_ADDRESS)
        transaction = self._chain.create_unsigned_transaction(
            nonce=nonce,#self._vm.state.get_nonce(sender_address),#vm.state.get_nonce(sender_address),
            gas_price=1,#1,#vm.state.get_gas_price(),
            gas=21000,  # Здесь можно указать другое значение газа
            to = address,  # В этом случае контракт будет развернут, поэтому адрес None
            value=10000000000000021000,#to_wei(5000, 'ether'),#to_wei(0.5, 'ether'),
            data = b'',#selector_setCrowdsaleInterface,
        )
        signed_tx = transaction.as_signed_transaction(FUNDED_ADDRESS_PRIVATE_KEY)
        mining_result, receipts, computations = self.main_all([signed_tx])
        #self._vm.state.lock_changes()
        #self.apply_transaction(signed_tx)
        
        return address,self._vm.state.get_nonce(FUNDED_ADDRESS),from_wei(self._vm.state.get_balance(address),"ether" )# to_wei(self._vm.state.get_balance(address), "ether") 

    def send2add(self,sender_private_key,to_address,val):                                                                                
        sender_address = sender_private_key.public_key.to_canonical_address()                                                       

        transaction = self._chain.create_unsigned_transaction(                                                                            
            nonce=self._vm.state.get_nonce(sender_address),                                                                               
            gas_price=1,#vm.state.get_gas_price(),                                                                                  
            gas=21000,  # Здесь можно указать другое значение газа                                                                  
            to=to_address,#b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02',                                                           
            value=to_wei(val, 'ether'),  # Здесь можно указать другое количество ETH                                                
            data=b'',                                                                                                               
            #v=chain.network_id,                                                                                                    
            #r=0,                                                                                                                   
            #s=0,                                                                                                                   
        ) 
        
        signed_tx = transaction.as_signed_transaction(sender_private_key)                                                           
        self.apply_transaction(signed_tx)  
        self._vm.finalize_block(self._chain.get_block()) 
                                                                                        
    def add(self,addr,val):                                                 
        private_key = keys.PrivateKey(to_bytes(hexstr=addr))          
        to_address = private_key.public_key.to_canonical_address()  
        logging.debug('ADD {}->{}'.format(val,to_address)) 
        #vm = self._chain.get_vm()    
        if False:
            transaction = self._chain.create_unsigned_transaction(                                               
            nonce=self.nonce_val,                                                  
            gas_price=1,#vm.state.get_gas_price(),                                                           
            gas=21000,  # Здесь можно указать другое значение газа                                           
            to=to_address,#b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02',                                    
            value=to_wei(val, 'ether'),  # Здесь можно указать другое количество ETH                         
            data=b'',                                                                                        
            #v=chain.network_id,                                                                             
            #r=0,                                                                                            
            #s=0,                                                                                            
            ) 
            signed_tx = transaction.as_signed_transaction(some_private_key) 
        else:
            signed_tx = new_transaction(
                vm=self._vm,
                private_key=FUNDED_ADDRESS_PRIVATE_KEY,
                from_=FUNDED_ADDRESS,
                to=to_address,
                amount=val,#to_wei(val, 'ether'),
                data=b"",
                nonce=self.nonce_val,
            )
            logging.debug(f"Built Transaction {signed_tx}")

        self.nonce_val += 1                                                                                                   
           
        logging.debug('ADD {} TO={}'.format(val,to_address.hex())) 
        mining_result, receipts, computations = self.main_all([signed_tx])
        vm = self._vm
        bal = vm.state.get_balance(FUNDED_ADDRESS)
        bal1 = vm.state.get_balance(to_address)
        logging.debug('BAL={}->{} RES {} COMP={}'.format(bal,bal1,mining_result,computations)) 
        #check_computation(computations[0]) 
                                  
        #self.apply_transaction(signed_tx) 
        #self._vm.state.lock_changes()                                                                   
        #self._vm.finalize_block(self._chain.get_block())   
        #
    def send(self,ac_from,ac_to,val): 
        # V=1~1000000000000000000   BAL=5999999999999897000 
        #                           BAL=3999999999999855000
        #                           BAL=9979999999999999742000
        from_private_key = keys.PrivateKey(to_bytes(hexstr=ac_from))                      
        from_address = from_private_key.public_key.to_canonical_address() 
        to_private_key = keys.PrivateKey(to_bytes(hexstr=ac_to))                           
        to_address = to_private_key.public_key.to_canonical_address()
        nonce = self._vm.state.get_nonce(from_address)
        logging.debug('SEND {}->{} NONCE={} V={}~{}'.format(ac_from,ac_to,nonce,val,to_wei(val, 'ether')))
        transaction = self._chain.create_unsigned_transaction(                              
            nonce=nonce,                                                           
            gas_price=1,#vm.state.get_gas_price(),                                  
            gas=21000,  # Здесь можно указать другое значение газа                          
            to=to_address,#b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02',                   
            value=to_wei(val, 'ether'),  # Здесь можно указать другое количество ETH        
            data=b'',                                                                       
            #v=chain.network_id,                                                            
            #r=0,                                                                           
            #s=0,                                                                           
        )                                                                                   
                                                                                            
        signed_tx = transaction.as_signed_transaction(from_private_key) 
        mining_result, receipts, computations = self.main_all([signed_tx])
        logging.debug('SEND {} TO={} DONE'.format(val,to_address.hex())) 
        computations[0].raise_if_error()                    
        logging.debug('SEND {} TO={} DONE'.format(val,to_address.hex()))                          
        #self.apply_transaction(signed_tx)  
        bal1 = from_wei(self._vm.state.get_balance(from_address),"ether")
        bal2 = from_wei(self._vm.state.get_balance(to_address),"ether")
        return to_address,self._vm.state.get_nonce(from_address),bal1,bal2                                                        
        
           
    
    def create_smart(self,creator,contract_bytecode,gas_price=1,gas_limit=2000000):

        private_key = keys.PrivateKey(to_bytes(hexstr=creator))          
        creater_address = private_key.public_key.to_canonical_address()
        nonce = self._vm.state.get_nonce(creater_address)
        
        transaction = self._chain.create_unsigned_transaction(                                                                                                                         
            nonce=nonce,
            gas_price=gas_price,#1,#vm.state.get_gas_price(),                                                                                                                     
            gas=gas_limit,#21000,  # Здесь можно указать другое значение газа                                                                                                     
            to = constants.CREATE_CONTRACT_ADDRESS,#contract_address,#b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x00',  # В этом случае контракт будет развернут, поэтому адрес None
            value=0,#to_wei(0.5, 'ether'),                                                                                                                                        
            data = bytes.fromhex(contract_bytecode),                                                                                                                                             
        )                                                                                                                                                                         
        signed_tx = transaction.as_signed_transaction(private_key) 
        #self.apply_transaction(signed_tx)                                                                                                      
        mining_result, receipts, computations = self.main_all([signed_tx])
        computations[0].raise_if_error()
        contract_address  =computations[0].msg.storage_address                                                                                                                               
        slot = self._vm.state.get_code(contract_address) #contract_address,1) 
        bal = self._vm.state.get_balance(contract_address)  
        stor = self._vm.state.get_storage(contract_address,1)                                                                                                                                                         
        logging.debug('SMART ADDR={} SLOT={} BAL={} stor={}'.format(contract_address.hex(),slot,bal,stor))
        return contract_address,self._vm.state.get_nonce(creater_address)
        
    def make_send_tx(self,sender_key,from_addr,to_addr,val):                                                                          

        signed_tx = new_transaction(                                                             
            vm=self._vm,                                                                         
            private_key=sender_key,                                              
            from_=from_addr,                                                                
            to=to_addr,#to_address,                                                       
            amount=val,#to_wei(val, 'ether'),                                                    
            data=b"",                                                                            
            nonce=self.nonce_val,                                                                
        )  
        non = self._vm.state.get_nonce(FUNDED_ADDRESS)                                                                                      
        logging.debug(f"NON={non} Built Transaction {signed_tx}")                                          
        return signed_tx

    def call_smart_func(self,addr,contract_address,func,gas_price=1,gas_limit=200000):            
        private_key = keys.PrivateKey(to_bytes(hexstr=addr))                                
        creater_address = private_key.public_key.to_canonical_address()                     
        nonce = self._vm.state.get_nonce(creater_address) 
        logging.debug('CALL SMART ADDR={} NONCE={}'.format(contract_address.hex(),nonce))
        transaction = self._chain.create_unsigned_transaction(                          
            nonce=nonce,                                                                
            gas_price=gas_price,#1,#vm.state.get_gas_price(),                           
            gas=gas_limit,#21000,  # Здесь можно указать другое значение газа           
            to = contract_address,#contract_address,#b'\0\0\0\0\0\0\0\0
            value=0,#to_wei(0.5, 'ether'),                                              
            data = bytes.fromhex(func[2:]),                                    
        )                                                                                                                 
        signed_tx = transaction.as_signed_transaction(private_key)                      
        #self.apply_transaction(signed_tx)  
        bstate  = self._vm.state                                           
        mining_result, receipts, computations = self.main_all([signed_tx])  
                   
        computations[0].raise_if_error()
        storage_address  =computations[0].msg.storage_address 
        try:
            verify_state(self._vm.state,bstate) 
        except Exception as ex:
            logging.debug('VERIFY STATE ERR {} state={}'.format(ex,bstate._db,dir(bstate)))
        stor = self._vm.state.get_storage(contract_address, 1)
        logging.debug('CALL SMART DONE {} STOR={} msg={}'.format(computations,storage_address,dir(computations[0].msg)))
                                                      





#logging.debug("Start test")

#tx_nonce = 0
#logging.debug("SENDER={} SOME={}".format(sender_address.hex(),SOME_ADDRESS.hex()))


def send2add(sender_private_key,to_address,val):
    global tx_nonce
    sender_address = sender_private_key.public_key.to_canonical_address()
    logging.debug('>>> TX NONCE={}'.format(tx_nonce))
    transaction = chain.create_unsigned_transaction(                                                              
        nonce=vm.state.get_nonce(sender_address),                                                                     
        gas_price=1,#vm.state.get_gas_price(),                                                                        
        gas=21000,  # Здесь можно указать другое значение газа                                                        
        to=to_address,#b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02',                                               
        value=to_wei(val, 'ether'),  # Здесь можно указать другое количество ETH                                       
        data=b'',                                                                                                     
        #v=chain.network_id,                                                                                          
        #r=0,                                                                                                         
        #s=0,                                                                                                         
    ) 
    signed_tx = transaction.as_signed_transaction(sender_private_key)
    comp = chain.apply_transaction(signed_tx) 
    logging.debug('<<<TX')
    #tx_nonce = tx_nonce + 1
    return comp                                                                                                                
        
                                                               

#vm = FrontierVM(constants.GENESIS_BLOCK_NUMBER, db)
#chain = Chain(vm)


#SOME_ADDRESS = b'\x85\x82\xa2\x89V\xb9%\x93M\x03\xdd\xb4Xu\xe1\x8e\x85\x93\x12\xc1'
#SOME_ADDRESS1 = b'\x85\x82\xa2\x89V\xb9%\x93M\x03\xdd\xb4Xu\xe1\x8e\x85\x93\x12\xc2'

if False :
    comp0 = send2add(sender_private_key,SOME_ADDRESS,10)
    check_computation(comp0,"SEND COMP0 >>")
    comp0 = send2add(some_private_key,sender_address,10)
    check_computation(comp0,"COMP0 >>")
    #comp0 = send2add(some_private_key,sender_address,10)
if False:
    contract_address = to_bytes(hexstr='0x742d35Cc6634C0532925a3b844Bc454e4438f44e')

    contract_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"  # Address for your contract
    contract_address = binascii.unhexlify('742d35Cc6634C0532925a3b844Bc454e4438f44e')
    contract_address = constants.CREATE_CONTRACT_ADDRESS
    smart_fnm = "./HelloWorld.bin" #
    #smart_fnm = "./int.bin" #'./intkey.bin'                                
    smart_fnm = './SimpleStorage.bin'
    #smart_fnm = './BGXToken.bin'
    with open(smart_fnm, 'r') as f:
        contract_bytecode = f.read()

    logging.debug('CONTR>> len={} HEX={}'.format(len(contract_bytecode),bytes.fromhex(contract_bytecode)))
    # Create a new transaction to deploy the contract
    # Создать объект транзакции
    gas_price = 1  # Укажите желаемую цену газа
    gas_limit = 73921+2454+22514+2402  # Укажите желаемый лимит газа
    #gas_limit = 91139+2402+10000
    gas_limit = 2000000
    root0 = vm.state.state_root

if False:
    block = vm.mine_block(
       coinbase=sender_address,
       transactions=[signed_tx],
    )
    chain.apply_block(block)

if False:
    ex = vm.state.get_transaction_executor()
    print('EXEC',ex,dir(ex))
    comp = ex.validate_transaction(signed_tx)
    print('comp',comp)

if False:
    bal= vm.state._account_db.get_balance(sender_address)
    print('BAL',bal)

    #vm.state.commit()
    root1 = vm.state.state_root
    st1 = type(vm.state.commit)
    logging.debug('ROOT={},st={}'.format(root0.hex(),st1))
    logging.debug('ROOT={} ~={}'.format(root1.hex(),root0 == root1))



if False:
    block = FrontierBlock(vm.state)

    # Имитируем выполнение транзакции в контексте блока
    transaction_context = BaseTransactionContext(
        gas_price=transaction.gas_price,
        origin=sender,
        gas_limit=transaction.gas,
        block=block,
    )





if False:
    nonce_val = 0 
    
    сdata = bytes.fromhex(contract_bytecode)
    
    transaction1 = chain.create_unsigned_transaction(                                                                                   
        nonce=nonce_val,#vm.state.get_nonce(sender_address),                                                                                    
        gas_price=gas_price,#1,#vm.state.get_gas_price(),                                                                               
        gas=gas_limit,#21000,  # Здесь можно указать другое значение газа                                                               
        to = contract_address,#b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x00',  # В этом случае контракт будет развернут, поэтому адрес None               
        value=0,#to_wei(0.5, 'ether'),                                                                                                  
        data = сdata,#bytes.fromhex(contract_bytecode),                                                                                                       
    ) 
    nonce_val += 1                                                                                                                                  
    signed_tx1 = transaction1.as_signed_transaction(sender_private_key)

    function_set_abi = [{"inputs":[{"internalType":"uint256","name":"x","type":"uint256"}],"name":"set","outputs":[],"stateMutability":"nonpayable","type":"function"}]
    f_get_abi = [{"inputs":[],"name":"get","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]
    args = []
    selector = encode_abi(['uint256'], [12345])#encode_abi(['function'], [function_set_abi]).hex()[:10]
    #function_selector = encode_abi(['bytes4', 'uint256'], ['set(uint256)', [123]])

    #print('SELECTOR',selector)
    method_signature = ['get()'.encode()]
    method_arguments = [            ]
    selector1 = encode_abi(['bytes'], ['get()'.encode()])
    selector = binascii.unhexlify('60fe47b1')
    selector = decode_hex('0xef5fb05b5b')#: sayHello() ef5fb05b
    #logging.debug('selector ={} {} '.format(selector,selector1))

    
    root0 = vm.state.state_root
    logging.debug("LOAD SMART>>>")
    comp1 = chain.apply_transaction(signed_tx1)
    check_computation(comp1,"COMP1>>")
    addr_contr  =comp1[2].msg.storage_address
    logging.debug('ADDR_CONTR>>> {} {} diff={}'.format(addr_contr.hex(),contract_address,addr_contr==contract_address))
    #vm.finalize_block(chain.get_block())
    bal1 = changes.get_balance(addr_contr)
    print('BAL1',bal1)

    if False:
        nonce_val += 1
        transaction1 = chain.create_unsigned_transaction(                                                                                   
            nonce=nonce_val,#vm.state.get_nonce(sender_address),                                                                                    
            gas_price=gas_price,#1,#vm.state.get_gas_price(),                                                                               
            gas=gas_limit,#21000,  # Здесь можно указать другое значение газа                                                               
            to = constants.CREATE_CONTRACT_ADDRESS,#contract_address,#b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x00',  # В этом случае контракт будет развернут, поэтому адрес None               
            value=0,#to_wei(0.5, 'ether'),                                                                                                  
            data = contract_bytecode,                                                                                                       
        )                                                                                                                                   
        signed_tx1 = transaction1.as_signed_transaction(sender_private_key)
        comp1 = chain.apply_transaction(signed_tx1)
        slot = vm.state.get_code(contract_address) #contract_address,1)
        print('SLOT',slot)
        root1 = vm.state.state_root
        print('ROOT',root0.hex())
        print('ROOT',root1.hex(),root0 == root1)
        check_computation(comp1,"COMP1 DUP>>")
        addr_contr  =comp1[2].msg.storage_address
        print('ADDR_CONTR>>>',addr_contr,contract_address,addr_contr==contract_address)
    if False :
        selector = decode_hex('0xef5fb05b')
        vm.state.apply_message(
            sender=sender_address,
            to=addr_contr,
            gas=50000,
            value=0,
            data=selector,
            )


    if False and smart_fnm == './SimpleStorage.bin':
        
        selector = bytes.fromhex('ef5fb05b5b')
        selector = bytes.fromhex('8a46e603')
        selector_get = bytes.fromhex('6d4ce63c')
        selector_store = bytes.fromhex('2a1afcd9')
        selector_set = bytes.fromhex('60fe47b1')+encode_abi(['uint256'], [1024])
        #6d4ce63c: get()
        #60fe47b1: set(uint256)
        #2a1afcd9: storedData()
        
        transaction2 = chain.create_unsigned_transaction(
            nonce=nonce_val,#vm.state.get_nonce(sender_address),
            gas_price=1,#1,#vm.state.get_gas_price(),
            gas=100000,#21000,  # Здесь можно указать другое значение газа
            to = addr_contr,  # В этом случае контракт будет развернут, поэтому адрес None
            value=0,#to_wei(0.5, 'ether'),
            data = selector_set,
        )
        nonce_val += 1
        signed_tx2 = transaction2.as_signed_transaction(sender_private_key)
        comp2 = chain.apply_transaction(signed_tx2)
        check_computation(comp2,"COMP2")
        
        transaction2 = chain.create_unsigned_transaction(
            nonce=nonce_val,#vm.state.get_nonce(sender_address),
            gas_price=1,#1,#vm.state.get_gas_price(),
            gas=100000,#21000,  # Здесь можно указать другое значение газа
            to = addr_contr,  # В этом случае контракт будет развернут, поэтому адрес None
            value=0,#to_wei(0.5, 'ether'),
            data = selector_store,#selector_get,
        )
        nonce_val += 1
        signed_tx2 = transaction2.as_signed_transaction(sender_private_key)
        comp2 = chain.apply_transaction(signed_tx2)
        check_computation(comp2,"COMP3")
        bal1 = changes.get_balance(addr_contr)
        logging.debug('bal1={}'.format(bal1))
        data= db.get(addr_contr)
        logging.debug('DATA={}'.format(data))

    if False and smart_fnm == './BGXToken.bin':
        """======= BGXToken.sol:BGXToken =======
        Function signatures:
        dd62ed3e: allowance(address,address)
        095ea7b3: approve(address,uint256)
        70a08231: balanceOf(address)
        31d2f891: crowdsaleAddress()
        313ce567: decimals()
        66188463: decreaseApproval(address,uint256)
        fb932108: distribute(address,uint256)
        76e7430e: finally(address)
        d73dd623: increaseApproval(address,uint256)
        158ef93e: initialized()
        06fdde03: name()
        8da5cb5b: owner()
        dcbda04c: setCrowdsaleInterface(address)
        95d89b41: symbol()
        1c75f085: teamAddress()
        ad9fb75e: teamDate()
        18160ddd: totalSupply()
        ee31f9f6: totalSupplyTmp()
        a9059cbb: transfer(address,uint256)
        23b872dd: transferFrom(address,address,uint256)
        f2fde38b: transferOwnership(address)
        """
        # 06fdde03 name
        logging.debug("BGXToken>>>>")
        selector_name = bytes.fromhex('06fdde03')
        selector_initialized = bytes.fromhex('158ef93e')
        selector_const = bytes.fromhex('60078054')
        selector_symbol = bytes.fromhex('95d89b41')
        selector_totalSupply = bytes.fromhex('18160ddd')
        selector_setCrowdsaleInterface = bytes.fromhex('dcbda04c')+encode_abi(['address'], [sender_address])
        selector_crowdsaleAddress = bytes.fromhex('31d2f891')
        selector_distribute = bytes.fromhex('fb932108')+encode_abi(['address','uint256'], [SOME_ADDRESS,1024])
        #vm.state.get_changes()
        nonce_val += 1
        transaction2 = chain.create_unsigned_transaction(
            nonce=nonce_val,#vm.state.get_nonce(sender_address),
            gas_price=1,#1,#vm.state.get_gas_price(),
            gas=100000,#21000,  # Здесь можно указать другое значение газа
            to = addr_contr,  # В этом случае контракт будет развернут, поэтому адрес None
            value=0,#to_wei(0.5, 'ether'),
            data = selector_setCrowdsaleInterface,
        )
        signed_tx2 = transaction2.as_signed_transaction(sender_private_key)
        vm.state.lock_changes()
        comp2 = chain.apply_transaction(signed_tx2)
        vm.finalize_block(chain.get_block())
        comput = check_computation(comp2,"COMP-"+str(nonce_val),is_out=True)

        #vm.state.get_changes()
        #
        if True:
            logging.debug('SENDER={} LOGS={}'.format(sender_address,comput.get_log_entries()))
            logging.debug('LOCK_CHANGES >>')
            vm.state.lock_changes()
            logging.debug('LOCK_CHANGES <<')
            nonce_val += 1                                                                       
            transaction2 = chain.create_unsigned_transaction(                                    
                nonce=nonce_val,#vm.state.get_nonce(sender_address),                             
                gas_price=1,#1,#vm.state.get_gas_price(),                                        
                gas=100000,#21000,  # Здесь можно указать другое значение газа                   
                to = addr_contr,  # В этом случае контракт будет развернут, поэтому адрес None   
                value=0,#to_wei(0.5, 'ether'),                                                   
                data = selector_crowdsaleAddress,#selector_distribute,                                           
            )                                                                                    
            signed_tx2 = transaction2.as_signed_transaction(sender_private_key)                  
            comp2 = chain.apply_transaction(signed_tx2)                                          
            comput = check_computation(comp2,"COMP-"+str(nonce_val),is_out=True)
            adb = None#comput.state.get_changes()
            logs = comput.get_log_entries()
            alist = None #dir(adb._get_changed_roots())
            #for jj in adb._get_changed_roots():
            #    print('k',jj)
            logging.debug("!!DIFF={} comp={} \nstat={} \nslot={} \nlogs={}".format(vm.state.difficulty,dir(comput),dir(comput.state),adb,logs))                          


if False:
    block_result = vm.finalize_block(chain.get_block())
    block = block_result.block
    logging.debug('block={}'.format(block))


    balance = vm.state.get_balance(sender_address) 
    logging.debug("balance={} sender={} ".format(balance,sender_address))
    bal = changes.get_balance(SOME_ADDRESS)
    logging.debug('SOME bal={} state-root={}'.format(bal,vm.state.state_root))
    #for key,data in vm.state._db.items() :
    #    print('db:key {}'.format(key))
    ditems = vm.state._db.items()
    logging.debug('keys={}'.format(ditems))
    if isinstance(ditems, Mapping):
        for key, value in ditems:
            logging.debug(f'Key: {key}, Value: {value}')
    #print('\nVMSTATE',dir(vm))

