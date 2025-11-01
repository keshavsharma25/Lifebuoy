from typing import TypedDict

from eth_typing import ChecksumAddress, HexAddress


class WithdrawalParams(TypedDict):
    nonce: int
    sender: ChecksumAddress
    target: ChecksumAddress
    value: int
    gasLimit: int
    data: bytes


class GameSearchResult(TypedDict):
    index: int
    metadata: bytes
    timestamp: int
    root_claim: bytes
    extra_data: bytes


class OutputRootProof(TypedDict):
    version: bytes
    state_root: bytes
    message_passer_storage_root: bytes
    latest_block_hash: bytes


class CheckWithdrawalResponse(TypedDict):
    is_withdrawal_enabled: bool
    fault_dispute_game_address: HexAddress
    timestamp: int
