from typing import TypedDict

from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3.types import Wei


class QueueTransactionEvent(TypedDict):
    sender: ChecksumAddress
    target: ChecksumAddress
    value: Wei
    queueIndex: int
    gasLimit: int
    data: HexBytes


class SentMessageEvent(TypedDict):
    sender: ChecksumAddress
    target: ChecksumAddress
    value: Wei
    messageNonce: int
    gasLimit: int
    message: HexBytes


class ProofParams(TypedDict):
    batchIndex: int
    merkleProof: HexBytes


class RelayMessageWithProofParams(TypedDict):
    from_: ChecksumAddress
    to: ChecksumAddress
    value: Wei
    nonce: int
    message: HexBytes
    proof: ProofParams
