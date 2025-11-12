from typing import NamedTuple, TypedDict

from eth_typing import ChecksumAddress


class WithdrawalParams(NamedTuple):
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
    """
    - `version`: 32-byte proof format version (currently
    `b'\\x00' * 32`).
    - `state_root`: 32-byte post-state root of the L2 block.
    - `message_passer_storage_root`: 32-byte storage root of the
    `L2ToL1MessagePasser` contract in that block.
    - `latest_block_hash`: 32-byte canonical block hash.
    """

    version: bytes
    state_root: bytes
    message_passer_storage_root: bytes
    latest_block_hash: bytes


class ProvenWithdrawalResponse(TypedDict):
    fault_dispute_game_address: ChecksumAddress
    timestamp: int
