import json
import pathlib
import subprocess
from typing import (
    Dict,
    Iterable,
)


def derive_compile_path(contract_path: pathlib.Path) -> pathlib.Path:
    return contract_path.with_name(f"{contract_path.name}-compiled")


def compile_contract(contract_path: str,out_path: str) -> None:
    #out_path = derive_compile_path(contract_path)
    p = pathlib.Path(contract_path)
    #print('N',p.name,dir(p),p.stem,pathlib.PurePath(out_path,p.stem))
    ret = subprocess.run(
        [
            "solc",
            contract_path,
            "--pretty-json",
            "--combined-json",
            "bin,abi",
            "--overwrite",
            "--evm-version","byzantium",
            "-o",
            pathlib.PurePath(out_path,p.stem),
        ],
        stdout=subprocess.PIPE,
    )
    return ret


def compile_contracts(contract_paths: Iterable[pathlib.Path],out_path: str) -> None:
    for path in contract_paths:
        compile_contract(path,out_path)


def get_compiled_contract(out_path: str,contract_path: str, contract_name: str) -> Dict[str, str]:
    p = pathlib.Path(contract_path)
    compiled_path = pathlib.PurePath(out_path,p.stem,"combined.json")

    with open(compiled_path) as file:
        data = json.load(file)
    return data["contracts"][f"{contract_path}:{contract_name}"]
