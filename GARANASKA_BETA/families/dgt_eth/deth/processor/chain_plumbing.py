from pathlib import (
    Path,
)
import tempfile
from typing import (
    Any,
    Dict,
    Iterable,
    Tuple,
    Type,
)

from eth_keys import (
    keys,
)
from eth_typing import (
    Address,
)
from eth_utils import (
    decode_hex,
    to_wei,
)

from eth import (
    constants,
)
from eth.abc import (
    VirtualMachineAPI,
)
from eth.chains.base import (
    MiningChain,
)
from eth.chains.mainnet import (
    BaseMainnetChain,
)
from eth.db.backends.level import (
    LevelDB,
)
from eth.tools.builder.chain import (
    build,
    disable_pow_check,
    fork_at,
    genesis,
)
from eth.vm.forks.frontier import FrontierVM
from eth.vm.forks.byzantium import ByzantiumVM
ALL_VM = [vm for _, vm in BaseMainnetChain.vm_configuration]

FUNDED_ADDRESS_PRIVATE_KEY = keys.PrivateKey(
    decode_hex("0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
)

FUNDED_ADDRESS = Address(FUNDED_ADDRESS_PRIVATE_KEY.public_key.to_canonical_address())

DEFAULT_INITIAL_BALANCE = to_wei(10000, "ether")

SECOND_ADDRESS_PRIVATE_KEY = keys.PrivateKey(
    decode_hex("0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d0")
)

SECOND_ADDRESS = Address(SECOND_ADDRESS_PRIVATE_KEY.public_key.to_canonical_address())

GENESIS_PARAMS = {
    "coinbase": constants.ZERO_ADDRESS,
    "transaction_root": constants.BLANK_ROOT_HASH,
    "receipt_root": constants.BLANK_ROOT_HASH,
    "difficulty": 1,
    "gas_limit": 3141592,
    "extra_data": constants.GENESIS_EXTRA_DATA,
    "nonce": constants.GENESIS_NONCE,
}

DEFAULT_GENESIS_STATE = [
    (
        FUNDED_ADDRESS,
        {
            "balance": DEFAULT_INITIAL_BALANCE,
            "code": b"",
        },
    ),
    (
        SECOND_ADDRESS,
        {
            "balance": DEFAULT_INITIAL_BALANCE,
            "code": b"",
        },
    ),
]

GenesisState = Iterable[Tuple[Address, Dict[str, Any]]]


def get_chain(
    vm: Type[VirtualMachineAPI], genesis_state: GenesisState
) -> Iterable[MiningChain]:
    with tempfile.TemporaryDirectory() as temp_dir:
        #print("PATH:",Path(temp_dir))
        level_db_obj = LevelDB(Path(temp_dir))
        level_db_chain = build(
            MiningChain,
            fork_at(vm, constants.GENESIS_BLOCK_NUMBER),
            disable_pow_check(),
            genesis(db=level_db_obj, params=GENESIS_PARAMS, state=genesis_state),
        )
        yield level_db_chain


def get_all_chains(
    genesis_state: GenesisState = DEFAULT_GENESIS_STATE,
) -> Iterable[MiningChain]:

    for vm in ALL_VM:
        if num == 1:
            break
        num += 1
        yield from get_chain(vm, genesis_state)

def get_eth_chain(level_db_obj,path_db : str=None,genesis_state: GenesisState = DEFAULT_GENESIS_STATE):
    if path_db is not None:
        level_db_obj = LevelDB(Path(path_db))
    #vm = FrontierVM 
    vm =   ByzantiumVM                                                       
    level_db_chain = build(                                                                         
        MiningChain,                                                                                
        fork_at(vm, constants.GENESIS_BLOCK_NUMBER),                                                
        disable_pow_check(),                                                                        
        genesis(db=level_db_obj, params=GENESIS_PARAMS, state=genesis_state),                       
    )                                                                                               
    return level_db_chain                                                                            
                                                                                                        
