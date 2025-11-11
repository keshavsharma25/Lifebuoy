""""""

from typing import List, Optional, Tuple, cast
from web3 import Web3
from web3.constants import ADDRESS_ZERO
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3.eth import Contract
from web3.logs import DISCARD
from web3.types import TxParams, TxReceipt, Wei
import rlp
from .types import (
    L2ToL1TxArgs,
    OutboxProofResponse,
    RetryableTicketParams,
    TicketStatus,
)

from .gas_estimator import (
    GasEstimator,
    GasRelatedResponse,
)
from utils.chain import add_gas_buffer, get_abi, get_account
from utils.config import (
    NITRO_STACK_ETHEREUM_CONTRACTS,
    NITRO_STACK_L2_CONTRACTS,
    ChainName,
    NitroStackChainName,
)
from utils.providers import get_web3
from eth_abi import abi
from .custom_errors import (
    NitroStackError,
    NitroStackForceInclusionError,
    NitroStackOutboxError,
    NitroStackRetryableTicketError,
)


class NitroStack:
    def __init__(
        self, chain_name: NitroStackChainName, account: Optional[LocalAccount] = None
    ) -> None:
        self.chain_name = chain_name
        self.l1_provider = get_web3(ChainName.ETH_SEPOLIA)
        self.l2_provider = get_web3(chain_name)
        self.account = account or get_account()

    def _get_sequencer_inbox(self) -> Contract:
        contracts = NITRO_STACK_ETHEREUM_CONTRACTS[self.chain_name]
        info = contracts.get("SEQUENCER_INBOX")

        contract = self.l1_provider.eth.contract(
            info["address"], abi=get_abi(info["ABI"])
        )

        return contract

    def _get_delayed_inbox_contract(self) -> Contract:
        contracts = NITRO_STACK_ETHEREUM_CONTRACTS[self.chain_name]
        info = contracts.get("DELAYED_INBOX")

        contract = self.l1_provider.eth.contract(
            info["address"], abi=get_abi(info["ABI"])
        )

        return contract

    def _get_bridge_contract(self) -> Contract:
        contracts = NITRO_STACK_ETHEREUM_CONTRACTS[self.chain_name]
        info = contracts.get("BRIDGE")

        contract = self.l1_provider.eth.contract(
            info["address"], abi=get_abi(info["ABI"])
        )

        return contract

    def _get_arb_retryable_tx_precompile(self) -> Contract:
        contracts = NITRO_STACK_L2_CONTRACTS[self.chain_name]
        info = contracts.get("ARB_RETRYABLE_TX")

        contract = self.l2_provider.eth.contract(
            info["address"], abi=get_abi(info["ABI"])
        )

        return contract

    def _get_arb_sys_precompile(self) -> Contract:
        contracts = NITRO_STACK_L2_CONTRACTS[self.chain_name]
        info = contracts.get("ARB_SYS")

        contract = self.l2_provider.eth.contract(
            info["address"], abi=get_abi(info["ABI"])
        )

        return contract

    def _get_node_interface(self) -> Contract:
        contracts = NITRO_STACK_L2_CONTRACTS[self.chain_name]

        info = contracts.get("NODE_INTERFACE")

        contract = self.l2_provider.eth.contract(
            info["address"],
            abi=get_abi(info["ABI"]),
        )

        return contract

    def _get_outbox_contract(self) -> Contract:
        contracts = NITRO_STACK_ETHEREUM_CONTRACTS[self.chain_name]

        info = contracts.get("OUTBOX")

        contract = self.l1_provider.eth.contract(
            info["address"],
            abi=get_abi(info["ABI"]),
        )

        return contract

    def depositEth(self, value: float) -> TxReceipt:
        delayed_inbox = self._get_delayed_inbox_contract()

        prep_txn = delayed_inbox.functions.depositEth()

        estimated_gas = prep_txn.estimate_gas(
            {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "value": Web3.to_wei(value, "ether"),
            }
        )

        txn_payload: TxParams = prep_txn.build_transaction(
            {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "value": Web3.to_wei(value, "ether"),
                "gas": add_gas_buffer(estimated_gas),
            }
        )

        try:
            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )
            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)

            return receipt
        except Exception as e:
            raise NitroStackError(f"`DepositEth` Transaction failed: {e}")

    def create_retryable_ticket(
        self,
        to: ChecksumAddress,
        l2_call_value_ether: float,
        data: HexBytes,
        override_gas_limit: Optional[int] = None,
        call_value_refund_address: Optional[ChecksumAddress] = None,
        excess_fee_refund_address: Optional[ChecksumAddress] = None,
    ) -> TxReceipt:
        if call_value_refund_address is None:
            call_value_refund_address = self.account.address

        if excess_fee_refund_address is None:
            excess_fee_refund_address = self.account.address

        gas_estimator = GasEstimator(
            self.chain_name,
            self.l1_provider,
            self.l2_provider,
        )

        l2_call_value = Web3.to_wei(l2_call_value_ether, "ether")

        gas_estimates: GasRelatedResponse = gas_estimator.estimate_all(
            {
                "to": to,
                "l2_call_value": l2_call_value,
                "sender": self.account.address,
                "call_value_refund_address": call_value_refund_address,
                "excess_fee_refund_address": excess_fee_refund_address,
                "data": data,
            }
        )

        params: RetryableTicketParams = {
            "to": to,
            "l2CallValue": l2_call_value,
            "maxSubmissionCost": gas_estimates.get("l1_submission_cost"),
            "excessFeeRefundAddress": excess_fee_refund_address,
            "callValueRefundAddress": call_value_refund_address,
            "gasLimit": gas_estimates.get("l2_gas_limit")
            if override_gas_limit is None
            else override_gas_limit,
            "maxFeePerGas": gas_estimates.get("max_fee_per_gas"),
            "data": data,
        }

        inbox = self._get_delayed_inbox_contract()

        retryable_ticket = inbox.functions.createRetryableTicket(
            params["to"],
            params["l2CallValue"],
            params["maxSubmissionCost"],
            params["excessFeeRefundAddress"],
            params["callValueRefundAddress"],
            params["gasLimit"],
            params["maxFeePerGas"],
            params["data"],
        )

        deposit = Wei(gas_estimates.get("deposit"))

        main_gas_estimates = retryable_ticket.estimate_gas(
            transaction={
                "from": self.account.address,
                "value": deposit,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
            }
        )

        txn_payload: TxParams = retryable_ticket.build_transaction(
            {
                "from": self.account.address,
                "value": deposit,
                "gas": add_gas_buffer(main_gas_estimates),
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
            }
        )

        try:
            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )
            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)

            return receipt
        except Exception as e:
            raise NitroStackError(f"`createRetryableTicket` transaction failed: {e}")

    def get_status(self, l1_txn_hash: HexBytes) -> TicketStatus:
        tx_receipt = self.l1_provider.eth.get_transaction_receipt(l1_txn_hash)

        receipt_status = tx_receipt["status"]

        receipt_block = tx_receipt["blockNumber"]
        current_block = self.l1_provider.eth.block_number

        TXN_SUCCESSFUL = 1

        if receipt_status != TXN_SUCCESSFUL:
            return TicketStatus.CREATION_FAILED

        confirmations = current_block - receipt_block

        # 32 slots to finality
        MINIMUM_CONFIRMATIONS = 64

        if confirmations <= MINIMUM_CONFIRMATIONS:
            return TicketStatus.NOT_YET_CREATED

        retryable_ticket_hash = self.get_retryable_ticket_id(l1_txn_hash)

        try:
            retryable_ticket_receipt = self.l2_provider.eth.get_transaction_receipt(
                retryable_ticket_hash
            )
        except Exception:
            return TicketStatus.NOT_YET_CREATED

        status = retryable_ticket_receipt["status"]
        if status != TXN_SUCCESSFUL:
            return TicketStatus.CREATION_FAILED

        def get_auto_redeem_txn() -> HexBytes | None:
            REDEEM_SCHEDULED_SIGNATURE = (
                "RedeemScheduled(bytes32,bytes32,uint64,uint64,address,uint256,uint256)"
            )
            REDEEM_SCHEDULED_HEX = HexBytes(
                Web3.keccak(text=REDEEM_SCHEDULED_SIGNATURE)
            ).to_0x_hex()

            logs = retryable_ticket_receipt.get("logs", [])

            for log in logs:
                topics = log.get("topics", [])

                if not topics:
                    continue
                log_topic = topics[0]
                log_topic_hex = HexBytes(log_topic).to_0x_hex()

                if log_topic_hex == REDEEM_SCHEDULED_HEX:
                    if len(topics) >= 3:
                        return topics[2]

            return None

        auto_redeem_txn = get_auto_redeem_txn()

        if auto_redeem_txn:
            try:
                redeem_receipt = self.l2_provider.eth.get_transaction_receipt(
                    auto_redeem_txn
                )
                if redeem_receipt["status"] == TXN_SUCCESSFUL:
                    return TicketStatus.REDEEMED
            except Exception:
                pass

        try:
            timeout = self.get_timeout_retryable_ticket(retryable_ticket_hash)

            if timeout > 0:
                return TicketStatus.FUNDS_DEPOSITED_ON_CHILD
        except Exception:
            pass

        # just throw an error in the end telling that either the txn has been redeemed or expired before redemption.
        #  TODO: add a way to effectively differentiate redeemed & expired tickets

        # The reason being it has either been **redeemed** or have **expired** its default validity a.k.a. RetryableLifetime (7 days).
        return TicketStatus.EXPIRED

    @staticmethod
    def decode_inbox_message_delivered_data(
        data: HexBytes,
    ) -> Tuple[RetryableTicketParams, int, int]:
        data_abi_types = [
            "uint256",  ## dest
            "uint256",  ## l2 call value
            "uint256",  ## msg val
            "uint256",  ## max submission
            "uint256",  ## excess fee refund addr
            "uint256",  ## call value refund addr
            "uint256",  ## max gas
            "uint256",  ## gas price bid
            "uint256",  ## data length
        ]

        decoded = abi.decode(types=data_abi_types, data=data, strict=False)

        call_value = decoded[2]
        calldata_length = decoded[8]

        if calldata_length > 0:
            calldata = HexBytes(data[-calldata_length:])
        else:
            calldata = HexBytes("0x")

        metadata: RetryableTicketParams = {
            "to": Web3.to_checksum_address(decoded[0]),
            "l2CallValue": decoded[1],
            "maxSubmissionCost": decoded[3],
            "excessFeeRefundAddress": Web3.to_checksum_address(decoded[4]),
            "callValueRefundAddress": Web3.to_checksum_address(decoded[5]),
            "gasLimit": decoded[6],
            "maxFeePerGas": decoded[7],
            "data": calldata,
        }

        return (metadata, calldata_length, call_value)

    @staticmethod
    def calculate_retryable_id(
        chain_id: int,
        call_value: int,
        from_: ChecksumAddress,
        metadata: RetryableTicketParams,
        message_number: int,
        l1_base_fee_per_gas: int,
    ) -> HexBytes:
        fields: List[HexBytes] = [
            # chain_id
            HexBytes(chain_id),
            # message_num
            HexBytes(message_number.to_bytes(32, byteorder="big")),
            # sender_address (as in MessageReceived() Event)
            HexBytes(from_),
            # baseFeeL1 (as in MessageReceived() Event)
            HexBytes(HexBytes(l1_base_fee_per_gas).lstrip(b"\x00")),
            # L1 Call Value
            HexBytes(HexBytes(call_value).lstrip(b"\x00")),
            # max fee per gas
            HexBytes(metadata.get("maxFeePerGas")),
            # gas limit
            HexBytes(metadata.get("gasLimit")),
            # To address (empty in case of contract creation)
            HexBytes(metadata.get("to"))
            if metadata.get("to") != ADDRESS_ZERO
            else HexBytes(b""),
            # L2 call value
            HexBytes(HexBytes(metadata.get("l2CallValue")).lstrip(b"\x00")),
            # call value refund address
            HexBytes(metadata.get("callValueRefundAddress")),
            # max submission cost
            HexBytes(HexBytes(metadata.get("maxSubmissionCost")).lstrip(b"\x00")),
            # excess fee refund address
            HexBytes(metadata.get("excessFeeRefundAddress")),
            # calldata
            HexBytes(metadata["data"]),
        ]

        rlp_encoded = rlp.encode(fields)

        typed_txn = HexBytes(b"\x69") + bytes(rlp_encoded)
        retryable_ticket_id = Web3.keccak(typed_txn)

        return HexBytes(retryable_ticket_id)

    def get_retryable_ticket_id(self, l1_txn_hash: HexBytes) -> HexBytes:
        rt_receipt = self.l1_provider.eth.get_transaction_receipt(l1_txn_hash)

        inbox = self._get_delayed_inbox_contract()
        bridge = self._get_bridge_contract()

        bridge_message_delivered_event = (
            bridge.events.MessageDelivered().process_receipt(rt_receipt, errors=DISCARD)
        )

        base_fee_l1 = bridge_message_delivered_event[0]["args"]["baseFeeL1"]
        sender = bridge_message_delivered_event[0]["args"]["sender"]

        inbox_msg_delivered_event = (
            inbox.events.InboxMessageDelivered().process_receipt(
                rt_receipt, errors=DISCARD
            )
        )

        if not inbox_msg_delivered_event or not len(inbox_msg_delivered_event) > 0:
            raise ValueError(
                f"`len(events) = {len(inbox_msg_delivered_event)}`. `txn_hash: {l1_txn_hash}`  does not emit `InboxMessageDelivered` event."
            )

        message_number: int = inbox_msg_delivered_event[0]["args"]["messageNum"]
        data: HexBytes = HexBytes(inbox_msg_delivered_event[0]["args"]["data"])

        (metadata, _, call_value) = self.decode_inbox_message_delivered_data(data)

        retryable_ticket_id = self.calculate_retryable_id(
            self.l2_provider.eth.chain_id,
            call_value,
            sender,
            metadata,
            message_number,
            base_fee_l1,
        )
        return HexBytes(retryable_ticket_id)

    def redeem_retryable_ticket(self, rt_txn_hash: HexBytes) -> TxReceipt:
        arb_retryable_tx = self._get_arb_retryable_tx_precompile()

        redeem = arb_retryable_tx.functions.redeem(rt_txn_hash)

        try:
            gas_estimate = redeem.estimate_gas({"from": self.account.address})

            txn_payload = redeem.build_transaction(
                {
                    "from": self.account.address,
                    "gas": add_gas_buffer(gas_estimate),
                    "nonce": self.l2_provider.eth.get_transaction_count(
                        self.account.address
                    ),
                }
            )

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l2_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            redeem_receipt = self.l2_provider.eth.wait_for_transaction_receipt(txn_hash)

            return redeem_receipt
        except Exception as e:
            raise NitroStackRetryableTicketError.from_contract_error(e)

    def cancel_retryable_ticket(self, rt_txn_hash: HexBytes) -> TxReceipt:
        arb_retryable_tx = self._get_arb_retryable_tx_precompile()

        cancel = arb_retryable_tx.functions.cancel(rt_txn_hash)

        try:
            gas_estimate = cancel.estimate_gas({"from": self.account.address})

            txn_payload = cancel.build_transaction(
                {
                    "from": self.account.address,
                    "gas": add_gas_buffer(gas_estimate),
                    "nonce": self.l2_provider.eth.get_transaction_count(
                        self.account.address
                    ),
                }
            )

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l2_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            redeem_receipt = self.l2_provider.eth.wait_for_transaction_receipt(txn_hash)

            return redeem_receipt
        except Exception as e:
            raise NitroStackRetryableTicketError.from_contract_error(e)

    def keep_alive_retryable_ticket(self, rt_txn_hash: HexBytes) -> TxReceipt:
        arb_retryable_tx = self._get_arb_retryable_tx_precompile()

        keep_alive = arb_retryable_tx.functions.keepalive(rt_txn_hash)

        try:
            gas_estimate = keep_alive.estimate_gas({"from": self.account.address})

            txn_payload = keep_alive.build_transaction(
                {
                    "from": self.account.address,
                    "gas": add_gas_buffer(gas_estimate),
                    "nonce": self.l2_provider.eth.get_transaction_count(
                        self.account.address
                    ),
                }
            )

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l2_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            redeem_receipt = self.l2_provider.eth.wait_for_transaction_receipt(txn_hash)

            return redeem_receipt
        except Exception as e:
            raise NitroStackRetryableTicketError.from_contract_error(e)

    def get_timeout_retryable_ticket(self, rt_txn_hash: HexBytes) -> int:
        arb_retryable_tx = self._get_arb_retryable_tx_precompile()

        try:
            timeout = arb_retryable_tx.functions.getTimeout(rt_txn_hash).call()
            return timeout
        except Exception as e:
            raise NitroStackRetryableTicketError.from_contract_error(e)

    def get_beneficiary_retryable_ticket(
        self, rt_txn_hash: HexBytes
    ) -> ChecksumAddress:
        arb_retryable_tx = self._get_arb_retryable_tx_precompile()

        try:
            beneficiary = arb_retryable_tx.functions.getBeneficiary(rt_txn_hash).call()
            return Web3.to_checksum_address(beneficiary)
        except Exception as e:
            raise NitroStackRetryableTicketError.from_contract_error(e)

    def perform_force_inclusion(self, l1_txn_hash: HexBytes) -> TxReceipt:
        rt_receipt = self.l1_provider.eth.get_transaction_receipt(l1_txn_hash)

        bridge = self._get_bridge_contract()
        sequencer_inbox = self._get_sequencer_inbox()

        bridge_message_delivered_event = (
            bridge.events.MessageDelivered().process_receipt(rt_receipt, errors=DISCARD)
        )

        message_number: int = bridge_message_delivered_event[0]["args"]["messageIndex"]
        kind: int = bridge_message_delivered_event[0]["args"]["kind"]
        block_number: int = rt_receipt["blockNumber"]
        timestamp: int = bridge_message_delivered_event[0]["args"]["timestamp"]
        base_fee_l1 = bridge_message_delivered_event[0]["args"]["baseFeeL1"]
        sender = Web3.to_checksum_address(
            bridge_message_delivered_event[0]["args"]["sender"]
        )
        message_data_hash = HexBytes(
            bridge_message_delivered_event[0]["args"]["messageDataHash"]
        )

        force_inclusion = sequencer_inbox.functions.forceInclusion(
            message_number,
            kind,
            (block_number, timestamp),
            base_fee_l1,
            sender,
            message_data_hash,
        )

        try:
            gas_estimates = force_inclusion.estimate_gas({"from": self.account.address})

            txn_payload = force_inclusion.build_transaction(
                {
                    "from": self.account.address,
                    "nonce": self.l1_provider.eth.get_transaction_count(
                        self.account.address,
                    ),
                    "gas": add_gas_buffer(gas_estimates),
                }
            )

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            redeem_receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)

            return redeem_receipt

        except Exception as e:
            raise NitroStackForceInclusionError.from_contract_error(e)
