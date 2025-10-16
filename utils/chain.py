from eth_typing import ChecksumAddress
from web3 import Web3
from web3.types import Wei


def estimate_l2_gas(
    w3: Web3, to: ChecksumAddress | None, from_: str, value: Wei, data: bytes
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

    return gas_estimate
