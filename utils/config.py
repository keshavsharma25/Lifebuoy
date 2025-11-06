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


class ContractType(TypedDict):
    address: ChecksumAddress
    ABI: str


def _contract(address: str, abi_path: str) -> ContractType:
    return {
        "address": to_checksum_address(address),
        "ABI": abi_path,
    }


# GAS ESTIMATE

MULTIPLIER = 1.3
BUFFER = 20_000


# OP STACK CONFIG

ABI_OPTIMISM_PORTAL = "chains/op_stack/ABI/OptimismPortal2.json"
ABI_DISPUTE_GAME_FACTORY = "chains/op_stack/ABI/DisputeGameFactory.json"
ABI_L2_TO_L1_MESSAGE_PASSER = "chains/op_stack/ABI/L2ToL1MessagePasser.json"
ABI_FAULT_DISPUTE_GAME = "chains/op_stack/ABI/FaultDisputeGame.json"
ABI_ANCHOR_STATE_REGISTRY = "chains/op_stack/ABI/AnchorStateRegistry.json"

OPStackChainName = Literal[ChainName.OP_SEPOLIA, ChainName.BASE_SEPOLIA]


class OP_STACK_ETHEREUM(TypedDict):
    OPTIMISM_PORTAL: ContractType
    DISPUTE_GAME_FACTORY: ContractType
    ANCHOR_STATE_REGISTRY: ContractType


class OP_STACK_L2(TypedDict):
    L2_TO_L1_MESSAGE_PASSER: ContractType


OP_STACK_ETHEREUM_CONTRACTS: Final[Dict[ChainName, OP_STACK_ETHEREUM]] = {
    ChainName.OP_SEPOLIA: {
        "OPTIMISM_PORTAL": _contract(
            "0x16FC5058F25648194471939DF75CF27A2FDC48BC", ABI_OPTIMISM_PORTAL
        ),
        "DISPUTE_GAME_FACTORY": _contract(
            "0x05F9613aDB30026FFd634f38e5C4dFd30a197Fa1", ABI_DISPUTE_GAME_FACTORY
        ),
        "ANCHOR_STATE_REGISTRY": _contract(
            "0xa1Cec548926eb5d69aa3B7B57d371EdBdD03e64b", ABI_ANCHOR_STATE_REGISTRY
        ),
    },
    ChainName.BASE_SEPOLIA: {
        "OPTIMISM_PORTAL": _contract(
            "0x49f53e41452C74589E85cA1677426Ba426459e85", ABI_OPTIMISM_PORTAL
        ),
        "DISPUTE_GAME_FACTORY": _contract(
            "0xd6E6dBf4F7EA0ac412fD8b65ED297e64BB7a06E1", ABI_DISPUTE_GAME_FACTORY
        ),
        "ANCHOR_STATE_REGISTRY": _contract(
            "0x2fF5cC82dBf333Ea30D8ee462178ab1707315355", ABI_ANCHOR_STATE_REGISTRY
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


# NITRO CONFIG

ABI_DELAYED_INBOX = "chains/nitro_stack/ABI/delayed_inbox.json"
ABI_NODE_INTERFACE = "chains/nitro_stack/ABI/node_interface.json"
ABI_ARB_BRIDGE = "chains/nitro_stack/ABI/bridge.json"
ABI_ARB_RETRYABLE_TX = "chains/nitro_stack/ABI/arb_retryable_tx_precompile.json"
ABI_SEQUENCER_INBOX = "chains/nitro_stack/ABI/sequencer_inbox.json"

NitroStackChainName = Literal[ChainName.ARB_SEPOLIA]


class NITRO_STACK_ETHEREUM(TypedDict):
    DELAYED_INBOX: ContractType
    BRIDGE: ContractType
    SEQUENCER_INBOX: ContractType


class NITRO_STACK_L2(TypedDict):
    NODE_INTERFACE: ContractType
    ARB_RETRYABLE_TX: ContractType


NITRO_STACK_ETHEREUM_CONTRACTS: Final[Dict[ChainName, NITRO_STACK_ETHEREUM]] = {
    ChainName.ARB_SEPOLIA: {
        "DELAYED_INBOX": _contract(
            "0xaAe29B0366299461418F5324a79Afc425BE5ae21",
            ABI_DELAYED_INBOX,
        ),
        "BRIDGE": _contract(
            "0x38f918D0E9F1b721EDaA41302E399fa1B79333a9",
            ABI_ARB_BRIDGE,
        ),
        "SEQUENCER_INBOX": _contract(
            "0x6c97864CE4bEf387dE0b3310A44230f7E3F1be0D",
            ABI_SEQUENCER_INBOX,
        ),
    }
}


NITRO_STACK_L2_CONTRACTS: Final[Dict[ChainName, NITRO_STACK_L2]] = {
    ChainName.ARB_SEPOLIA: {
        "NODE_INTERFACE": _contract(
            "0x00000000000000000000000000000000000000C8",
            ABI_NODE_INTERFACE,
        ),
        "ARB_RETRYABLE_TX": _contract(
            "0x000000000000000000000000000000000000006E",
            ABI_ARB_RETRYABLE_TX,
        ),
    }
}
