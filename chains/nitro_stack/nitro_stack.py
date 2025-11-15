"""
Nitro Stack python implementation to send transaction via L1 -> L2. This module
provides an escape hatch for users to benefit from features that nitro stack provides.
"""

from typing import List, Optional, Tuple, cast
from web3 import Web3
from web3.constants import ADDRESS_ZERO
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
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
    NITRO_STACK_ETHEREUM,
    NITRO_STACK_ETHEREUM_CONTRACTS,
    NITRO_STACK_L2,
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
    """
    This class is to interact with Nitro Stack chains like
    Arbitrum One, Arbitrum Nova and Arbitrum Sepolia (Testnet)

    Parameters
    ----------
    `chain_name` : NitroStackChainName

    `account` : LocalAccount, optional

    MORE INFO
    ---------
    -
    """

    def __init__(
        self, chain_name: NitroStackChainName, account: Optional[LocalAccount] = None
    ) -> None:
        self.chain_name = chain_name
        self.l1_provider = get_web3(ChainName.ETH_SEPOLIA)
        self.l2_provider = get_web3(chain_name)
        self.account = account or get_account()

    def _get_l1_contract(self, contract: NITRO_STACK_ETHEREUM):
        """
        Retrieve the instantiated L1 contract related to Nitro Stack chain.

        Parameters
        ----------
        contract : NITRO_STACK_ETHEREUM

        Returns
        -------
        web3.contract.Contract
        """
        contracts = NITRO_STACK_ETHEREUM_CONTRACTS.get(self.chain_name)

        if not contracts:
            raise Exception("Invalid chain intitialized.")

        info = contracts.get(contract)

        if not info:
            raise Exception("Invalid contract name provided.")

        return self.l1_provider.eth.contract(
            address=info.get("address"), abi=get_abi(info.get("ABI"))
        )

    def _get_l2_contract(self, contract: NITRO_STACK_L2):
        """
        Retrieve the instantiated L2 contracts related to Nitro Stack chain.

        Parameters
        ----------
        contract : NITRO_STACK_L2

        Returns
        -------
        web3.contract.Contract
        """
        contracts = NITRO_STACK_L2_CONTRACTS.get(self.chain_name)

        if not contracts:
            raise Exception("Invalid chain intitialized.")

        info = contracts.get(contract)

        if not info:
            raise Exception("Invalid contract name provided.")

        return self.l2_provider.eth.contract(
            address=info.get("address"), abi=get_abi(info.get("ABI"))
        )

    def depositEth(self, value_ether: float) -> TxReceipt:
        """
        Deposits ETH directly to the sender's address on L2. User will send call_value
        to the delayed inbox contract on L1 (Ethereum) via `depositEth()`. It is of
        `L1 message kind: 12`.

        This is the most direct and easiest method to send ETH to signer's address. The
        time to deposit depends on Ethereum's finality.

        Parameters
        ----------
        `value_ether` : float
            It is to be provided in **ether** (not wei). It is prevent confusion and simplify
            experience.

        Returns
        -------
        `TxReceipt`
        """
        delayed_inbox = self._get_l1_contract(NITRO_STACK_ETHEREUM.DELAYED_INBOX)

        prep_txn = delayed_inbox.functions.depositEth()

        estimated_gas = prep_txn.estimate_gas(
            {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "value": Web3.to_wei(value_ether, "ether"),
            }
        )

        txn_payload: TxParams = prep_txn.build_transaction(
            {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "value": Web3.to_wei(value_ether, "ether"),
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
        """
        Retryable Ticket is a way to submit transactions on L2 via L1.
        This method would eventually submit a `createRetryableTicket()`
        via Delayed Inbox contract. Once again similar to `depositEth()`,
        ticket transaction only gets submitted once L1 transaction
        achieves finality. It is of `L1 message kind: 9`.

        Users can use retryable tickets to interact with any EOA or smart contracts.

        Parameters
        ----------
        `to` : ChecksumAddress
            The address you want to send your transaction on L2.

        `l2_call_value_ether` : float
            The call_value of the transaction on L2 (in **ether**).

        `data` : HexBytes
            The calldata of the transaction on L2 (in **ether**).

        `override_gas_limit` : Optional[int] = None
            override gas limit for purposeful manual redeem or
            manual tweak.

        `call_value_refund_address` : ChecksumAddress, optional
            Address to refund call_value in case the l2 transaction fails or
            is cancelled. Uses sender's address in case not provided.

        `excess_fee_refund_address` : ChecksumAddress, optional
            Address to refund excess gas limit provided to ensure successful
            inclusion of transaction in the block. Uses sender's address in
            case not provided.

        Returns
        -------
        `TxReceipt`
        """
        if call_value_refund_address is None:
            call_value_refund_address = self.account.address

        if excess_fee_refund_address is None:
            excess_fee_refund_address = self.account.address

        gas_estimator = GasEstimator(
            self.chain_name,
            self.l1_provider,
            self.l2_provider,
        )

        # convert ether to wei
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

        inbox = self._get_l1_contract(NITRO_STACK_ETHEREUM.DELAYED_INBOX)

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

        try:
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

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )
            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)

            return receipt
        except Exception as e:
            raise NitroStackError(f"`createRetryableTicket` transaction failed: {e}")

    def get_retryable_ticket_status(self, l1_txn_hash: HexBytes) -> TicketStatus:
        """
        Provides status of retryable tickets associated to the `createRetryableTicket()`
        transaction hash on L1. Usually the ticket transaction is only submitted on L2 once
        the L1 Retryable Ticket transaction achieves finality (2 epochs). Upto that point,
        the status would be `NOT_YET_CREATED`.

        Once the transaction is created, the method reads the logs to look for `RedeemScheduled`
        event emit. If emitted, the transaction is hence `REDEEMED` (via auto-redeem).

        If not, then the transaction has not received enough gas to execute it on L2,
        hence the user have to manually redeem the transaction via `redeem()` function
        in ARB_RETRYABLE_TX precompile. It is represented as `FUNDS_DEPOSITED_ON_CHILD` status.

        `CREATION_FAILED` happens in case the `createRetryableTicket` transaction
        itself fails or the ticket creation transaction fails (practically not possible).

        `EXPIRED` currently status represents both manually redeemed ticket and expired tickets (
        if not redeemed within their lifetime i.e. 7 days and can be extended via `keepalive()` in
        ARB_RETRYABLE_TX precompile).

        Checking manual-redeems are quite tricky as it requires to traverse each block and look
        for `RedeemScheduled` event that emits the retryable ticket transaction hash in its parameters.

        Parameters
        ----------
        `l1_txn_hash` : HexBytes
            `createRetryableTicket` transaction hash submitted on L1.

        Returns
        -------
        """
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
        """
        decodes abi encoded hexbytes

        Parameters
        ----------
        `data` : HexBytes

        Returns
        -------
        Tuple[RetryableTicketParams, calldata_length: int, call_value: int]
        """
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
            "to": Web3.to_checksum_address(decoded[0])
            if decoded[0] != 0
            else Web3.to_checksum_address("0x" + "00" * 20),
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
        """
        Helper method to calculate retryable ticket transaction hash that is created on L2
        once `createRetryableTicket()` transaction is finalized on L1. All the parameters
        are available in events emitted from `createRetryableTicket()` submitted on L1.

        Parameters
        ----------
        `chain_id` : int
        `call_value` : int
        `from_` : ChecksumAddress
        `metadata` : RetryableTicketParams
        `message_number` : int
        `l1_base_fee_per_gas` : int

        Returns
        -------
        `retryable_ticket_id` : HexBytes
        """
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
        """
        Provides retryable ticket id for a given `createRetryableTicket()` transaction
        hash submitted on L1.

        Parameters
        ----------
        `l1_txn_hash` : HexBytes

        Returns
        -------
        `retryable_ticket_id` : HexBytes
        """
        rt_receipt = self.l1_provider.eth.get_transaction_receipt(l1_txn_hash)

        inbox = self._get_l1_contract(NITRO_STACK_ETHEREUM.DELAYED_INBOX)
        bridge = self._get_l1_contract(NITRO_STACK_ETHEREUM.BRIDGE)

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
        """
        Manually redeem a retryable ticket in case the ticket has not redeemed automatically.
        The redeem happens via `redeem()` in ARB_RETRYABLE_TX precompile.

        Parameters
        ----------
        `rt_txn_hash` : HexBytes
            retryable ticket id

        Returns
        -------
        TxReceipt
        """
        arb_retryable_tx = self._get_l2_contract(NITRO_STACK_L2.ARB_RETRYABLE_TX)

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
            raise NitroStackRetryableTicketError.from_contract_error(
                arb_retryable_tx, e
            )

    def cancel_retryable_ticket(self, rt_txn_hash: HexBytes) -> TxReceipt:
        """
        Cancels a retryable ticket, permanently stopping its execution and releasing associated funds.

        Parameters
        ----------
        `rt_txn_hash` : HexBytes
            retryable ticket id

        Returns
        -------
        TxReceipt
        """
        arb_retryable_tx = self._get_l2_contract(NITRO_STACK_L2.ARB_RETRYABLE_TX)

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
            raise NitroStackRetryableTicketError.from_contract_error(
                arb_retryable_tx, e
            )

    def keep_alive_retryable_ticket(self, rt_txn_hash: HexBytes) -> TxReceipt:
        """
        Extends the lifetime of a retryable ticket by setting its expiration to the `current_timestamp + 7 days`.

        Parameters
        ----------
        `rt_txn_hash` : HexBytes
            retryable ticket id

        Returns
        -------
        TxReceipt
        """
        arb_retryable_tx = self._get_l2_contract(NITRO_STACK_L2.ARB_RETRYABLE_TX)

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
            raise NitroStackRetryableTicketError.from_contract_error(
                arb_retryable_tx, e
            )

    def get_timeout_retryable_ticket(self, rt_txn_hash: HexBytes) -> int:
        """
        Retrieves the expiry timestamp of the ticket.

        Parameters
        ----------
        `rt_txn_hash` : HexBytes
            retryable ticket id

        Returns
        -------
        `timestamp` : int
        """
        arb_retryable_tx = self._get_l2_contract(NITRO_STACK_L2.ARB_RETRYABLE_TX)

        try:
            timeout = arb_retryable_tx.functions.getTimeout(rt_txn_hash).call()
            return timeout
        except Exception as e:
            raise NitroStackRetryableTicketError.from_contract_error(
                arb_retryable_tx, e
            )

    def get_beneficiary_retryable_ticket(
        self, rt_txn_hash: HexBytes
    ) -> ChecksumAddress:
        """
        Retrieves the beneficiary address of a retryable ticket.

        Parameters
        ----------
        rt_txn_hash : HexBytes
            The transaction hash identifying the retryable ticket whose beneficiary is to be retrieved.

        Returns
        -------
        ChecksumAddress
        """
        arb_retryable_tx = self._get_l2_contract(NITRO_STACK_L2.ARB_RETRYABLE_TX)

        try:
            beneficiary = arb_retryable_tx.functions.getBeneficiary(rt_txn_hash).call()
            return Web3.to_checksum_address(beneficiary)
        except Exception as e:
            raise NitroStackRetryableTicketError.from_contract_error(
                arb_retryable_tx, e
            )

    def perform_force_inclusion(self, l1_txn_hash: HexBytes) -> TxReceipt:
        """
        Force inclusion is a censorship resistance feature in Arbitrum. It is for
        the times when sequencer censors or is unavailable. The users have the liberty
        to force include their transactions overriding the sequencer beyond a threshold
        time period post transaction submission. This timeout is dynamically adjusted
        via the Delay Buffer (initially up to ∼48 hours but effectively capped at
        24 hours under normal conditions), which shrinks during prolonged sequencer
        delays (down to ∼30 minutes on Arbitrum One) and replenishes slowly during
        reliable operation. As a result, users must initially wait at least 24 hours
        before forcing inclusion of delayed inbox transactions.

        Parameters
        ----------
        `l1_txn_hash` : Txn hash which executes `createRetryableTicket()`

        Returns
        -------
        TxReceipt
        """
        rt_receipt = self.l1_provider.eth.get_transaction_receipt(l1_txn_hash)

        bridge = self._get_l1_contract(NITRO_STACK_ETHEREUM.BRIDGE)
        sequencer_inbox = self._get_l1_contract(NITRO_STACK_ETHEREUM.SEQUENCER_INBOX)

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
            raise NitroStackForceInclusionError.from_contract_error(sequencer_inbox, e)

    def withdraw_eth(
        self,
        value_ether: float,
        dest_address: ChecksumAddress,
    ) -> TxReceipt:
        """
        Withdraw ETH from L2 -> L1 via escape hatch. It takes 7 days of challenge period for
        withdrawals to unlock. Canonical withdrawals are atleast two step process: Execute withdrawals
        on L2 -> wait for completion of challenge period -> Prove & Execute withdrawal on L1.

        This method helps execute ETH withdrawals.
        This method implements `withdrawEth()` in ARB_SYS precompile on L2.

        Parameters
        ----------
        `value_ether` : float
           The amount of ETH that is to be withdrawn (in ether).

        `dest_address` : ChecksumAddress

        Returns
        -------
        TxReceipt
        """
        arb_sys = self._get_l2_contract(NITRO_STACK_L2.ARB_SYS)

        value_wei = Web3.to_wei(value_ether, "ether")

        withdraw_eth = arb_sys.functions.withdrawEth(dest_address)

        try:
            gas_estimate = withdraw_eth.estimate_gas(
                {
                    "from": self.account.address,
                    "value": value_wei,
                }
            )

            txn_payload = withdraw_eth.build_transaction(
                {
                    "from": self.account.address,
                    "value": value_wei,
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

            receipt = self.l2_provider.eth.wait_for_transaction_receipt(txn_hash)

            return receipt

        except Exception as e:
            raise NitroStackError(str(e), e)

    def send_tx_to_l1(
        self,
        value_ether: float,
        dest_address: ChecksumAddress,
        data: HexBytes,
    ) -> TxReceipt:
        """
        Send message from L2 -> L1. According to solidity implementation, `withdraw_eth` also
        internal executes `sendTxToL1()` with empty calldata (0x). Like `withdraw_eth`, this
        method also is atleast two step process: Execute withdrawals on L2 -> wait
        for completion of challenge period -> Prove & Execute withdrawal on L1.

        This method implements `sendTxToL1()` in ARB_SYS precompile on L2.

        INFO: Token bridging happens through the calldata that encodes the information for the
        gateway to execute on L1.

        Parameters
        ----------
        `value_ether` : float
           The amount of ETH that is to be withdrawn (in ether).

        `dest_address` : ChecksumAddress

        `data` : HexBytes

        Returns
        -------
        TxReceipt
        """
        arb_sys = self._get_l2_contract(NITRO_STACK_L2.ARB_SYS)

        value_wei = Web3.to_wei(value_ether, "ether")

        send_tx_to_l1 = arb_sys.functions.sendTxToL1(dest_address, data)

        try:
            gas_estimate = send_tx_to_l1.estimate_gas(
                {
                    "from": self.account.address,
                    "value": value_wei,
                }
            )

            txn_payload = send_tx_to_l1.build_transaction(
                {
                    "from": self.account.address,
                    "value": value_wei,
                    "gas": add_gas_buffer(gas_estimate),
                }
            )

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            receipt = self.l2_provider.eth.wait_for_transaction_receipt(txn_hash)

            return receipt

        except Exception as e:
            raise NitroStackError(str(e), e)

    def parse_l2_to_l1_tx_event(self, l2_txn_hash: HexBytes) -> L2ToL1TxArgs:
        """
        Parses receipt that emits `L2ToL1Tx` event.

        Parameters
        ----------
        `l2_txn_hash` : HexBytes
            L2 txn hash that executes `withdrawEth` or `sendTxToL1`.

        Returns
        -------

        L2ToL1TxArgs
            {caller, destination, hash, position, arbBlockNum, ethBlockNum, timestamp, callvalue, data}
        """
        arb_sys = self._get_l2_contract(NITRO_STACK_L2.ARB_SYS)
        receipt = self.l2_provider.eth.get_transaction_receipt(l2_txn_hash)

        parsed_logs = arb_sys.events.L2ToL1Tx.process_receipt(receipt, errors=DISCARD)

        if not parsed_logs:
            raise NitroStackError(
                f"Not a valid Txn hash `{l2_txn_hash.to_0x_hex()}` as it does not emit L2ToL1Tx event."
            )

        args = parsed_logs[0].get("args").__dict__
        args = cast(L2ToL1TxArgs, args)

        return args

    def construct_outbox_proof(self, l2_txn_hash: HexBytes) -> OutboxProofResponse:
        """
        Construct outbox proof that is required to execute the transaction on L1 after the
        challenge period finishes (∼7 days).

        This method implements `constructOutboxProof` view function in Node Interface precompile.

        Parameters
        ----------
        `l2_txn_hash` : HexBytes
            L2 txn hash that executes `withdrawEth` or `sendTxToL1`.

        Returns
        -------
        OutboxProofResponse
            {send, root, proof}
        """
        node_interface = self._get_l2_contract(NITRO_STACK_L2.NODE_INTERFACE)
        arb_sys = self._get_l2_contract(NITRO_STACK_L2.ARB_SYS)

        merkle_tree_state = arb_sys.functions.sendMerkleTreeState().call()
        size = merkle_tree_state[0]

        l2_to_l1_args = self.parse_l2_to_l1_tx_event(l2_txn_hash)
        position = l2_to_l1_args["position"]

        result = node_interface.functions.constructOutboxProof(size, position).call()

        outbox_proof: OutboxProofResponse = {
            "send": HexBytes(result[0]),
            "root": HexBytes(result[1]),
            "proof": [HexBytes(p) for p in result[2]],
        }

        return outbox_proof

    def execution_transaction_on_l1(self, l2_txn_hash: HexBytes) -> TxReceipt:
        """
        For L2 -> L1 withdrawal (or message), messages are available
        in Outbox contract, ready to be executed. To finalize, users perform
        `executeTransaction()` function in Outbox contract after the
        challenge period finishes to claim the funds or message.

        Parameters
        ----------
        `l2_txn_hash` : HexBytes
            L2 txn hash that executes `withdrawEth` or `sendTxToL1`.

        Returns
        -------
        TxReceipt
        """
        outbox = self._get_l1_contract(NITRO_STACK_ETHEREUM.OUTBOX)
        l2_to_l1_args = self.parse_l2_to_l1_tx_event(l2_txn_hash)
        outbox_proof = self.construct_outbox_proof(l2_txn_hash)

        proof = outbox_proof["proof"]
        position = l2_to_l1_args["position"]
        l2_sender = l2_to_l1_args["caller"]
        to = l2_to_l1_args["destination"]
        l2_block = l2_to_l1_args["arbBlockNum"]
        l1_block = l2_to_l1_args["ethBlockNum"]
        timestamp = l2_to_l1_args["timestamp"]
        value = l2_to_l1_args["callvalue"]
        data = l2_to_l1_args["data"]

        try:
            execute_txn = outbox.functions.executeTransaction(
                proof,
                position,
                l2_sender,
                to,
                l2_block,
                l1_block,
                timestamp,
                value,
                data,
            )

            gas_estimate = execute_txn.estimate_gas({"from": l2_sender})

            txn_payload = execute_txn.build_transaction(
                {
                    "from": l2_sender,
                    "gas": gas_estimate,
                    "nonce": self.l1_provider.eth.get_transaction_count(
                        self.account.address
                    ),
                }
            )

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )
            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)

            return receipt

        except Exception as e:
            raise NitroStackOutboxError.from_contract_error_info(e)
