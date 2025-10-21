from enum import StrEnum
from typing import Dict, TypedDict

from eth_typing import ChecksumAddress
from eth_utils.address import to_checksum_address


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


# OP STACK CONFIG


class OP_STACK_SEPOLIA(TypedDict):
    OPTIMISM_PORTAL: ChecksumAddress
    DISPUTE_GAME_FACTORY: ChecksumAddress


class OP_STACK_L2(TypedDict):
    L2_TO_L1_MESSAGE_PASSER: ChecksumAddress


OP_STACK_SEPOLIA_CONTRACTS: Dict[ChainName, OP_STACK_SEPOLIA] = {
    ChainName.OP_SEPOLIA: {
        "OPTIMISM_PORTAL": to_checksum_address(
            "0x16FC5058F25648194471939DF75CF27A2FDC48BC"
        ),
        "DISPUTE_GAME_FACTORY": to_checksum_address(
            "0x05F9613aDB30026FFd634f38e5C4dFd30a197Fa1"
        ),
    },
    ChainName.BASE_SEPOLIA: {
        "OPTIMISM_PORTAL": to_checksum_address(
            "0x49f53e41452C74589E85cA1677426Ba426459e85"
        ),
        "DISPUTE_GAME_FACTORY": to_checksum_address(
            "0xd6E6dBf4F7EA0ac412fD8b65ED297e64BB7a06E1"
        ),
    },
}

OP_STACK_L2_CONTRACTS = {}
