import os
import json
from typing import Optional
from dotenv import load_dotenv
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from web3 import Account, Web3
from web3.types import Wei

from .config import BUFFER, MULTIPLIER


def add_gas_buffer(
    gas_estimate: int, multiplier: Optional[float] = None, buffer: Optional[int] = None
) -> int:
    if multiplier is not None:
        if multiplier < 1.0:
            raise ValueError("`multiplier` should be >= 1.0 to ensure sufficient gas")
        effective_multiplier = multiplier
    else:
        effective_multiplier = MULTIPLIER

    # Use provided buffer, fallback to global BUFFER if not provided
    if buffer is not None:
        if buffer < 0:
            raise ValueError("`buffer` must be non-negative")
        effective_buffer = buffer
    else:
        effective_buffer = BUFFER

    return int(gas_estimate * effective_multiplier) + effective_buffer


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

    return add_gas_buffer(gas_estimate)


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
