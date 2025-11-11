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


class NitroStackOutboxError(NitroStackError):
    """Raised in case of interacting with Outbox contract functions (example - executeTransaction)"""

    # Reason is error types don't exist in the provided ABI
    # https://github.com/OffchainLabs/nitro-contracts/blob/0b8c04e8f5f66fe6678a4f53aa15f23da417260e/src/libraries/Error.sol#L122-L142
    OUTBOX_ERROR_SIGNATURES = (
        "ProofTooLong(uint256)",
        "PathNotMinimal(uint256,uint256)",
        "UnknownRoot(bytes32)",
        "AlreadySpent(uint256)",
    )

    @classmethod
    def from_contract_error_info(cls, error: Exception):
        if isinstance(error, ContractCustomError):
            received_error_selector = HexBytes(error.args[0])

            if len(received_error_selector) > 4:
                received_error_selector = received_error_selector[:4]

            error_selectors = {
                HexBytes(Web3.keccak(text=sign))[:4]: sign
                for sign in cls.OUTBOX_ERROR_SIGNATURES
            }
            if received_error_selector in error_selectors:
                return NitroStackOutboxError(
                    f"{error_selectors[received_error_selector]} error occurred.",
                    original_error=error,
                )

        return NitroStackError(str(error), error)
