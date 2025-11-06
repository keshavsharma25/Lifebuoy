from typing import TypedDict
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3 import Web3
from web3.eth import Contract
from web3.types import Wei, BlockData
from utils.chain import add_gas_buffer, get_abi
from utils.config import (
    NITRO_STACK_L2_CONTRACTS,
    NITRO_STACK_ETHEREUM_CONTRACTS,
    ChainName,
)


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


class GasEstimator:
    # 500% increase
    GAS_PRICE_MULTIPLIER = 5
    # 300% increase
    SUBMISSION_COST_MULITPLIER = 3

    def __init__(
        self, chain_name: ChainName, l1_provider: Web3, l2_provider: Web3
    ) -> None:
        self.chain_name = chain_name
        self.l1_provider = l1_provider
        self.l2_provider = l2_provider

    def _get_node_interface(self) -> Contract:
        contracts = NITRO_STACK_L2_CONTRACTS.get(self.chain_name)
        if not (contracts and contracts["NODE_INTERFACE"]):
            raise ValueError()

        info = contracts.get("NODE_INTERFACE")

        contract = self.l2_provider.eth.contract(
            info["address"],
            abi=get_abi(info["ABI"]),
        )

        return contract

    def _get_delayed_inbox_contract(self) -> Contract:
        contracts = NITRO_STACK_ETHEREUM_CONTRACTS[self.chain_name]
        info = contracts.get("DELAYED_INBOX")

        contract = self.l1_provider.eth.contract(
            info["address"], abi=get_abi(info["ABI"])
        )

        return contract

    def rt_max_l2_fee_per_gas(self) -> int:
        l2_gas_price = self.l2_provider.eth.gas_price

        return add_gas_buffer(
            l2_gas_price,
            multiplier=(1 + self.GAS_PRICE_MULTIPLIER),
            buffer=0,
        )

    def rt_estimate_l2_gas(self, params: EstimateRetryableTicketParams) -> int:
        node_interface = self._get_node_interface()

        assumed_deposit = Web3.to_wei(1, "ether")

        try:
            gas_limit = node_interface.functions.estimateRetryableTicket(
                params["sender"],
                assumed_deposit,
                params["to"],
                params["l2_call_value"],
                params["excess_fee_refund_address"],
                params["call_value_refund_address"],
                params["data"],
            ).estimate_gas(
                {"from": params["sender"]},
                "latest",
            )

            return gas_limit
        except Exception as e:
            raise ValueError(e)

    def rt_max_l1_submission_cost(self, data: HexBytes) -> int:
        inbox = self._get_delayed_inbox_contract()

        latest_l1_block: BlockData = self.l1_provider.eth.get_block("latest")
        l1_base_fee = latest_l1_block.get("baseFeePerGas")

        base_submission_cost = inbox.functions.calculateRetryableSubmissionFee(
            len(data),
            l1_base_fee,
        ).call()

        return add_gas_buffer(
            gas_estimate=base_submission_cost,
            multiplier=(1 + self.SUBMISSION_COST_MULITPLIER),
            buffer=0,
        )

    def estimate_all(self, params: EstimateRetryableTicketParams) -> GasRelatedResponse:
        max_fee_per_gas = self.rt_max_l2_fee_per_gas()
        l2_gas_limit = self.rt_estimate_l2_gas(params)
        l1_submission_cost = self.rt_max_l1_submission_cost(params.get("data"))
        l2_call_value = params.get("l2_call_value")

        deposit = l2_gas_limit * max_fee_per_gas + l1_submission_cost + l2_call_value

        return {
            "max_fee_per_gas": max_fee_per_gas,
            "l2_gas_limit": l2_gas_limit,
            "l1_submission_cost": l1_submission_cost,
            "deposit": deposit,
        }
