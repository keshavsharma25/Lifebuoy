from enum import Enum, StrEnum
from typing import Dict, Final, Literal, TypedDict

from eth_typing import ChecksumAddress
from eth_utils.address import to_checksum_address


class ENV(StrEnum):
    ALCHEMY_API_KEY = "ALCHEMY_API_KEY"
    ETH_SEPOLIA_RPC_URL = "ETH_SEPOLIA_RPC_URL"
    ARB_SEPOLIA_RPC_URL = "ARB_SEPOLIA_RPC_URL"
    BASE_SEPOLIA_RPC_URL = "BASE_SEPOLIA_RPC_URL"
    OP_SEPOLIA_RPC_URL = "OP_SEPOLIA_RPC_URL"
    SCROLL_SEPOLIA_RPC_URL = "SCROLL_SEPOLIA_RPC_URL"


class ChainName(StrEnum):
    ETH_SEPOLIA = "ETH_SEPOLIA"
    ARB_SEPOLIA = "ARB_SEPOLIA"
    BASE_SEPOLIA = "BASE_SEPOLIA"
    OP_SEPOLIA = "OP_SEPOLIA"
    SCROLL_SEPOLIA = "SCROLL_SEPOLIA"


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


class OP_STACK_ETHEREUM(Enum):
    OPTIMISM_PORTAL = "OPTIMISM_PORTAL"
    DISPUTE_GAME_FACTORY = "DISPUTE_GAME_FACTORY"
    ANCHOR_STATE_REGISTRY = "ANCHOR_STATE_REGISTRY"


class OP_STACK_L2(Enum):
    L2_TO_L1_MESSAGE_PASSER = "L2_TO_L1_MESSAGE_PASSER"


OP_STACK_ETHEREUM_CONTRACTS: Final[
    Dict[OPStackChainName, Dict[OP_STACK_ETHEREUM, ContractType]]
] = {
    ChainName.OP_SEPOLIA: {
        OP_STACK_ETHEREUM.OPTIMISM_PORTAL: _contract(
            "0x16FC5058F25648194471939DF75CF27A2FDC48BC", ABI_OPTIMISM_PORTAL
        ),
        OP_STACK_ETHEREUM.DISPUTE_GAME_FACTORY: _contract(
            "0x05F9613aDB30026FFd634f38e5C4dFd30a197Fa1", ABI_DISPUTE_GAME_FACTORY
        ),
        OP_STACK_ETHEREUM.ANCHOR_STATE_REGISTRY: _contract(
            "0xa1Cec548926eb5d69aa3B7B57d371EdBdD03e64b", ABI_ANCHOR_STATE_REGISTRY
        ),
    },
    ChainName.BASE_SEPOLIA: {
        OP_STACK_ETHEREUM.OPTIMISM_PORTAL: _contract(
            "0x49f53e41452C74589E85cA1677426Ba426459e85", ABI_OPTIMISM_PORTAL
        ),
        OP_STACK_ETHEREUM.DISPUTE_GAME_FACTORY: _contract(
            "0xd6E6dBf4F7EA0ac412fD8b65ED297e64BB7a06E1", ABI_DISPUTE_GAME_FACTORY
        ),
        OP_STACK_ETHEREUM.ANCHOR_STATE_REGISTRY: _contract(
            "0x2fF5cC82dBf333Ea30D8ee462178ab1707315355", ABI_ANCHOR_STATE_REGISTRY
        ),
    },
}


OP_STACK_L2_CONTRACTS: Dict[OPStackChainName, Dict[OP_STACK_L2, ContractType]] = {
    ChainName.OP_SEPOLIA: {
        OP_STACK_L2.L2_TO_L1_MESSAGE_PASSER: _contract(
            "0x4200000000000000000000000000000000000016", ABI_L2_TO_L1_MESSAGE_PASSER
        ),
    },
    ChainName.BASE_SEPOLIA: {
        OP_STACK_L2.L2_TO_L1_MESSAGE_PASSER: _contract(
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
ABI_ARB_SYS = "chains/nitro_stack/ABI/arb_sys_precompile.json"
ABI_OUTBOX = "chains/nitro_stack/ABI/outbox.json"

NitroStackChainName = Literal[ChainName.ARB_SEPOLIA]


class NITRO_STACK_ETHEREUM(Enum):
    DELAYED_INBOX = "DELAYED_INBOX"
    BRIDGE = "BRIDGE"
    SEQUENCER_INBOX = "SEQUENCER_INBOX"
    OUTBOX = "OUTBOX"


class NITRO_STACK_L2(Enum):
    NODE_INTERFACE = "NODE_INTERFACE"
    ARB_RETRYABLE_TX = "ARB_RETRYABLE_TX"
    ARB_SYS = "ARB_SYS"


NITRO_STACK_ETHEREUM_CONTRACTS: Final[
    Dict[NitroStackChainName, Dict[NITRO_STACK_ETHEREUM, ContractType]]
] = {
    ChainName.ARB_SEPOLIA: {
        NITRO_STACK_ETHEREUM.DELAYED_INBOX: _contract(
            "0xaAe29B0366299461418F5324a79Afc425BE5ae21",
            ABI_DELAYED_INBOX,
        ),
        NITRO_STACK_ETHEREUM.BRIDGE: _contract(
            "0x38f918D0E9F1b721EDaA41302E399fa1B79333a9",
            ABI_ARB_BRIDGE,
        ),
        NITRO_STACK_ETHEREUM.SEQUENCER_INBOX: _contract(
            "0x6c97864CE4bEf387dE0b3310A44230f7E3F1be0D",
            ABI_SEQUENCER_INBOX,
        ),
        NITRO_STACK_ETHEREUM.OUTBOX: _contract(
            "0x65f07C7D521164a4d5DaC6eB8Fac8DA067A3B78F",
            ABI_OUTBOX,
        ),
    }
}

NITRO_STACK_L2_CONTRACTS: Final[
    Dict[NitroStackChainName, Dict[NITRO_STACK_L2, ContractType]]
] = {
    ChainName.ARB_SEPOLIA: {
        NITRO_STACK_L2.NODE_INTERFACE: _contract(
            "0x00000000000000000000000000000000000000C8",
            ABI_NODE_INTERFACE,
        ),
        NITRO_STACK_L2.ARB_RETRYABLE_TX: _contract(
            "0x000000000000000000000000000000000000006E",
            ABI_ARB_RETRYABLE_TX,
        ),
        NITRO_STACK_L2.ARB_SYS: _contract(
            "0x0000000000000000000000000000000000000064",
            ABI_ARB_SYS,
        ),
    }
}


# SCROLL CONFIG

ABI_ENFORCED_TX_GATEWAY = "chains/scroll/ABI/EnforcedTxGateway.json"
ABI_L1_MESSAGE_QUEUE_V2 = "chains/scroll/ABI/L1MessageQueueV2.json"
ABI_L1_GATEWAY_ROUTER = "chains/scroll/ABI/L1GatewayRouter.json"
ABI_L1_SCROLL_MESSENGER = "chains/scroll/ABI/L1ScrollMessenger.json"
ABI_L2_GATEWAY_ROUTER = "chains/scroll/ABI/L2GatewayRouter.json"
ABI_L2_SCROLL_MESSENGER = "chains/scroll/ABI/L2ScrollMessenger.json"

ScrollChainName = Literal[ChainName.SCROLL_SEPOLIA]


class SCROLL_ETHEREUM(Enum):
    ENFORCED_TX_GATEWAY = "ENFORCED_TX_GATEWAY"
    L1_MESSAGE_QUEUE_V2 = "L1_MESSAGE_QUEUE_V2"
    L1_GATEWAY_ROUTER = "L1_GATEWAY_ROUTER"
    L1_SCROLL_MESSENGER = "L1_SCROLL_MESSENGER"


class SCROLL_L2(Enum):
    L2_GATEWAY_ROUTER = "L2_GATEWAY_ROUTER"
    L2_SCROLL_MESSENGER = "L2_SCROLL_MESSENGER"


SCROLL_ETHEREUM_CONTRACTS: Final[
    Dict[ScrollChainName, Dict[SCROLL_ETHEREUM, ContractType]]
] = {
    ChainName.SCROLL_SEPOLIA: {
        SCROLL_ETHEREUM.ENFORCED_TX_GATEWAY: _contract(
            "0x97f421CA37889269a11ae0fef558114b984C7487",
            ABI_ENFORCED_TX_GATEWAY,
        ),
        SCROLL_ETHEREUM.L1_MESSAGE_QUEUE_V2: _contract(
            "0xA0673eC0A48aa924f067F1274EcD281A10c5f19F",
            ABI_L1_MESSAGE_QUEUE_V2,
        ),
        SCROLL_ETHEREUM.L1_GATEWAY_ROUTER: _contract(
            "0x13FBE0D0e5552b8c9c4AE9e2435F38f37355998a",
            ABI_L1_GATEWAY_ROUTER,
        ),
        SCROLL_ETHEREUM.L1_SCROLL_MESSENGER: _contract(
            "0x50c7d3e7f7c656493D1D76aaa1a836CedfCBB16A",
            ABI_L1_SCROLL_MESSENGER,
        ),
    }
}

SCROLL_L2_CONTRACTS: Final[Dict[ScrollChainName, Dict[SCROLL_L2, ContractType]]] = {
    ChainName.SCROLL_SEPOLIA: {
        SCROLL_L2.L2_GATEWAY_ROUTER: _contract(
            "0x9aD3c5617eCAa556d6E166787A97081907171230", ABI_L2_GATEWAY_ROUTER
        ),
        SCROLL_L2.L2_SCROLL_MESSENGER: _contract(
            "0xBa50f5340FB9F3Bd074bD638c9BE13eCB36E603d",
            ABI_L2_SCROLL_MESSENGER,
        ),
    },
}
