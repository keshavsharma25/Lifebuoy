from web3 import Web3
from dataclasses import dataclass
from typing import Dict
from enum import StrEnum


class ChainName(StrEnum):
    op_sepolia = "op_sepolia"
    arb_sepolia = "arb_sepolia"
    base_sepolia = "base_sepolia"


@dataclass
class ProviderConfig:
    rpc_url: str
    chain_id: int


providers: Dict[ChainName, ProviderConfig] = {
    ChainName.op_sepolia: ProviderConfig(
        rpc_url="https://sepolia.optimism.io",
        chain_id=11155420,
    ),
    ChainName.arb_sepolia: ProviderConfig(
        rpc_url="https://sepolia-rollup.arbitrum.io/rpc",
        chain_id=421614,
    ),
    ChainName.base_sepolia: ProviderConfig(
        rpc_url="https://sepolia.base.org",
        chain_id=84532,
    ),
}


def get_web3(chain_name: ChainName) -> Web3:
    if chain_name not in providers:
        raise ValueError(f"Unknown chain: {chain_name}")
    config = providers[chain_name]
    w3 = Web3(Web3.HTTPProvider(config.rpc_url))

    if w3.eth.chain_id != config.chain_id:
        raise ValueError(f"Chain ID mismatch for {chain_name}")

    return w3
