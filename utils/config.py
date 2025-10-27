from enum import StrEnum
from typing import Dict, Final, Literal, TypedDict

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

ABI_OPTIMISM_PORTAL = "chains/op_stack/ABI/OptimismPortal2.json"
ABI_DISPUTE_GAME_FACTORY = "chains/op_stack/ABI/DisputeGameFactory.json"
ABI_L2_TO_L1_MESSAGE_PASSER = "chains/op_stack/ABI/L2ToL1MessagePasser.json"
ABI_FAULT_DISPUTE_GAME = "chains/op_stack/ABI/FaultDisputeGame.json"


OPStackChainName = Literal[ChainName.OP_SEPOLIA, ChainName.BASE_SEPOLIA]


class OP_STACK_SEPOLIA(TypedDict):
    OPTIMISM_PORTAL: Contract
    DISPUTE_GAME_FACTORY: Contract


class OP_STACK_L2(TypedDict):
    L2_TO_L1_MESSAGE_PASSER: Contract


def _contract(address: str, abi_path: str) -> Contract:
    return {
        "address": to_checksum_address(address),
        "ABI": abi_path,
    }


OP_STACK_SEPOLIA_CONTRACTS: Final[Dict[ChainName, OP_STACK_SEPOLIA]] = {
    ChainName.OP_SEPOLIA: {
        "OPTIMISM_PORTAL": _contract(
            "0x16FC5058F25648194471939DF75CF27A2FDC48BC", ABI_OPTIMISM_PORTAL
        ),
        "DISPUTE_GAME_FACTORY": _contract(
            "0x05F9613aDB30026FFd634f38e5C4dFd30a197Fa1", ABI_DISPUTE_GAME_FACTORY
        ),
    },
    ChainName.BASE_SEPOLIA: {
        "OPTIMISM_PORTAL": _contract(
            "0x49f53e41452C74589E85cA1677426Ba426459e85", ABI_OPTIMISM_PORTAL
        ),
        "DISPUTE_GAME_FACTORY": _contract(
            "0xd6E6dBf4F7EA0ac412fD8b65ED297e64BB7a06E1", ABI_DISPUTE_GAME_FACTORY
        ),
    },
}


OP_STACK_L2_CONTRACTS: Dict[ChainName, OP_STACK_L2] = {
    ChainName.OP_SEPOLIA: {
        "L2_TO_L1_MESSAGE_PASSER": _contract(
            "0x4200000000000000000000000000000000000016", ABI_L2_TO_L1_MESSAGE_PASSER
        ),
    },
    ChainName.BASE_SEPOLIA: {
        "L2_TO_L1_MESSAGE_PASSER": _contract(
            "0x4200000000000000000000000000000000000016", ABI_L2_TO_L1_MESSAGE_PASSER
        )
    },
}
