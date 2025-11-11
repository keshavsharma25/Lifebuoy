from typing import Optional
from hexbytes import HexBytes
from web3 import Web3
from web3.eth import Contract
from web3.exceptions import ContractCustomError

from utils.chain import get_contract_error_info


class NitroStackError(Exception):
    """Base Exception for Nitro Stack operations."""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.original_error = original_error


class NitroStackRetryableTicketError(NitroStackError):
    """Raised in case retryable ticket manual-redeem fails."""

    @classmethod
    def from_contract_error(cls, contract: Contract, error: Exception):
        error_info = get_contract_error_info(contract, error)

        if error_info and error_info.name == "NoTicketWithID":
            raise NitroStackRetryableTicketError(
                f"`{error_info.signature}` from ArbRetryableTx precompile! "
                "Either doesn't exist, expired or redeemed already.",
                original_error=error,
            )

        return NitroStackError(str(error), original_error=error)


class NitroStackForceInclusionError(NitroStackError):
    """Raised in case force inclusion fails and throws a custom contract error."""

    @classmethod
    def from_contract_error(cls, contract: Contract, error: Exception):
        error_info = get_contract_error_info(contract, error)

        if error_info:
            raise NitroStackForceInclusionError(
                f"`{error_info.signature}` error occurred.",
                original_error=error,
            )

        return NitroStackError(str(error), original_error=error)
