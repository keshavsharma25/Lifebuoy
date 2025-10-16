from enum import StrEnum
import os

from eth_account.signers.local import LocalAccount
from web3 import Account


class ENV(StrEnum):
    ALCHEMY_API_KEY = "ALCHEMY_API_KEY"
    ETH_SEPOLIA_RPC_URL = "ETH_SEPOLIA_RPC_URL"
    ARB_SEPOLIA_RPC_URL = "ARB_SEPOLIA_RPC_URL"
    BASE_SEPOLIA_RPC_URL = "BASE_SEPOLIA_RPC_URL"
    OP_SEPOLIA_RPC_URL = "OP_SEPOLIA_RPC_URL"


class ChainName(StrEnum):
    ETH_SEPOLIA = "ETH_SEPOLIA"
    ARB_SEPOLIA = "ARB_SEPOLIA"
    BASE_SEPOLIA = "BASE_SEPOLIA"
    OP_SEPOLIA = "OP_SEPOLIA"


class LocalAcc:
    def __init__(self) -> None:
        pvt_key = os.getenv("PRIVATE_KEY")

        if not pvt_key:
            raise ValueError("PRIVATE_KEY not set in .env...")

        self._account: LocalAccount = Account.from_key(pvt_key)

    def get_account(self) -> LocalAccount:
        return self._account
