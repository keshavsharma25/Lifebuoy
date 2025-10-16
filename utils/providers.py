from typing import Dict
from web3 import Web3
from .config import ENV, ChainName
from dotenv import load_dotenv
import os


load_dotenv()


def get_providers() -> Dict[ChainName, str]:
    providers: Dict[ChainName, str] = {
        chain: str(os.getenv(ENV[f"{chain.name}_RPC_URL"]))
        + str(os.getenv(ENV.ALCHEMY_API_KEY))
        for chain in ChainName
    }
    return providers


def get_web3(chain_name: ChainName) -> Web3:
    providers = get_providers()

    if chain_name not in providers:
        raise ValueError(f"Unknown chain: {chain_name}")
    w3 = Web3(Web3.HTTPProvider(providers[chain_name]))

    return w3
