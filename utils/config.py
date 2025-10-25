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


class Contract(TypedDict):
    address: ChecksumAddress
    ABI: str


# OP STACK CONFIG


class OP_STACK_SEPOLIA(TypedDict):
    OPTIMISM_PORTAL: Contract
    DISPUTE_GAME_FACTORY: Contract


class OP_STACK_L2(TypedDict):
    L2_TO_L1_MESSAGE_PASSER: Contract


OP_STACK_SEPOLIA_CONTRACTS: Dict[ChainName, OP_STACK_SEPOLIA] = {
    ChainName.OP_SEPOLIA: {
        "OPTIMISM_PORTAL": {
            "address": to_checksum_address(
                "0x16FC5058F25648194471939DF75CF27A2FDC48BC"
            ),
            "ABI": "chains/op_stack/ABI/OptimismPortal2.json",
        },
        "DISPUTE_GAME_FACTORY": {
            "address": to_checksum_address(
                "0x05F9613aDB30026FFd634f38e5C4dFd30a197Fa1"
            ),
            "ABI": "chains/op_stack/ABI/DisputeGameFactory.json",
        },
    },
    ChainName.BASE_SEPOLIA: {
        "OPTIMISM_PORTAL": {
            "address": to_checksum_address(
                "0x49f53e41452C74589E85cA1677426Ba426459e85"
            ),
            "ABI": "chains/op_stack/ABI/OptimismPortal2.json",
        },
        "DISPUTE_GAME_FACTORY": {
            "address": to_checksum_address(
                "0xd6E6dBf4F7EA0ac412fD8b65ED297e64BB7a06E1"
            ),
            "ABI": "chains/op_stack/ABI/DisputeGameFactory.json",
        },
    },
}

OP_STACK_L2_CONTRACTS: Dict[ChainName, OP_STACK_L2] = {
    ChainName.OP_SEPOLIA: {
        "L2_TO_L1_MESSAGE_PASSER": {
            "address": to_checksum_address(
                "0x4200000000000000000000000000000000000016"
            ),
            "ABI": "chains/op_stack/ABI/L2ToL1MessagePasser.json",
        },
    },
}
