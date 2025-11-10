from enum import Enum
from typing import List, TypedDict

from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3.types import Wei


class EstimateRetryableTicketParams(TypedDict):
    sender: ChecksumAddress
    to: ChecksumAddress
    l2_call_value: Wei
    excess_fee_refund_address: ChecksumAddress
    call_value_refund_address: ChecksumAddress
    data: HexBytes


class GasRelatedResponse(TypedDict):
    max_fee_per_gas: int
    l2_gas_limit: int
    l1_submission_cost: int
    deposit: int


class RetryableTicketParams(TypedDict):
    to: ChecksumAddress
    l2CallValue: int
    maxSubmissionCost: int
    excessFeeRefundAddress: ChecksumAddress
    callValueRefundAddress: ChecksumAddress
    gasLimit: int
    maxFeePerGas: int
    data: HexBytes


class TicketStatus(Enum):
    NOT_YET_CREATED = 1
    CREATION_FAILED = 2
    FUNDS_DEPOSITED_ON_CHILD = 3
    REDEEMED = 4
    EXPIRED = 5


class L2ToL1TxArgs(TypedDict):
    caller: ChecksumAddress
    destination: ChecksumAddress
    hash: int
    position: int
    arbBlockNum: int
    ethBlockNum: int
    timestamp: int
    callvalue: Wei
    data: HexBytes


class OutboxProofResponse(TypedDict):
    send: HexBytes
    root: HexBytes
    proof: List[HexBytes]
