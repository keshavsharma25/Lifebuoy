import os
import json
from typing import NamedTuple, Optional, Sequence
from dotenv import load_dotenv
from eth_account.signers.local import LocalAccount
from eth_typing import ABIComponent, ChecksumAddress
from hexbytes import HexBytes
from web3 import Account, Web3
from web3.eth import Contract
from web3.exceptions import ContractCustomError
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


def get_abi(path: str) -> str:
    if os.path.isfile(path):
        with open(path, "r") as file:
            abi = json.load(file)

        return abi
    else:
        raise BaseException(f"File path not found: {path}")


class ContractErrorInfo(NamedTuple):
    """
    Named tuple containing contract error information.

    Attributes:
        name: Error name (e.g., "NoTicketWithID")
        signature: Full error signature (e.g., "NoTicketWithID()")
        inputs: List of input parameters from ABI
        selector: 4-byte error selector hex string (e.g., "0x80698456")
    """

    name: str
    signature: str
    inputs: Sequence[ABIComponent]
    selector: str


def get_contract_error_info(
    contract: Contract, error: Exception
) -> Optional[ContractErrorInfo]:
    """
    Match a contract error to its ABI definition and return error information.

    Args:
        contract: Web3 Contract instance containing ABI
        error: Exception raised by contract call

    Returns:
        ContractErrorInfo named tuple if matched, None otherwise

    Example:
        >>> try:
        >>>     contract.functions.redeem(ticket_id).call()
        >>> except Exception as e:
        >>>     error_info = get_contract_error_info(contract, e)
        >>>     if error_info:
        >>>         print(f"Error: {error_info.name}")
        >>>         print(f"Signature: {error_info.signature}")
        >>>         print(f"Selector: {error_info.selector}")
    """
    if not isinstance(error, ContractCustomError):
        return None

    error_selector = error.args[0]
    print(error_selector)

    for item in contract.abi:
        if item.get("type") != "error":
            continue

        error_name = item.get("name")
        if error_name is None:
            continue

        inputs = item.get("inputs", [])

        input_types = []
        for inp in inputs:
            inp_type = inp.get("type")
            if inp_type is None:
                continue
            input_types.append(inp_type)

        signature = f"{error_name}({','.join(input_types)})"

        hash_bytes = Web3.keccak(text=signature)
        selector = HexBytes(hash_bytes[:4]).to_0x_hex()

        if selector == error_selector:
            return ContractErrorInfo(
                name=error_name,
                signature=signature,
                inputs=inputs,
                selector=selector,
            )

    return None
