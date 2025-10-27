import os
import json
from dotenv import load_dotenv
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from web3 import Account, Web3
from web3.types import Wei


def estimate_l2_gas(
    w3: Web3,
    to: ChecksumAddress | None,
    from_: ChecksumAddress,
    value: Wei,
    data: bytes,
) -> int:
    if to is None:
        gas_estimate = w3.eth.estimate_gas(
            {"from": from_, "value": value, "data": data},
            "latest",
            {from_: {"balance": w3.to_wei(1000, "ether")}},
        )
    else:
        gas_estimate = w3.eth.estimate_gas(
            {"to": to, "from": from_, "value": value, "data": data},
            "latest",
            {from_: {"balance": w3.to_wei(1000, "ether")}},
        )

    buffer = int(20_000)
    return int(1.3 * gas_estimate) + buffer


def get_account() -> LocalAccount:
    load_dotenv()

    pvt_key = os.getenv("PRIVATE_KEY")

    if type(pvt_key) is not str:
        raise TypeError(f"Store private key in .env as it is of type `{type(pvt_key)}")

    account: LocalAccount = Account.from_key(pvt_key)

    return account


def get_abi(path: str):
    if os.path.isfile(path):
        with open(path, "r") as file:
            abi = json.load(file)

        return abi
    else:
        raise BaseException(f"File path not found: {path}")
