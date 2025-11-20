from datetime import datetime
from typing import Optional, cast

from hexbytes import HexBytes
from eth_typing import ChecksumAddress
from web3 import Web3
from web3.logs import DISCARD
from web3.types import TxParams, TxReceipt, Wei

from .types import QueueTransactionEvent, SentMessageEvent
from .custom_errors import EventParseError, ScrollError
from utils.chain import add_gas_buffer, get_account, get_abi
from utils.config import (
    SCROLL_STACK_ETHEREUM,
    SCROLL_STACK_ETHEREUM_CONTRACTS,
    ChainName,
    ScrollStackClassName,
)
from eth_account.signers.local import LocalAccount

from utils.providers import get_web3


class Scroll:
    """
    Scroll stack implementation to perform force inclustion and withdrawals (escape hatch).
    """

    def __init__(
        self,
        chain_name: ScrollStackClassName,
        account: Optional[LocalAccount] = None,
    ) -> None:
        self.chain_name = chain_name
        self.l1_provider = get_web3(ChainName.ETH_SEPOLIA)
        self.l2_provider = get_web3(chain_name)
        self.account = account or get_account()

    def _get_l1_contract(self, contract: SCROLL_STACK_ETHEREUM):
        """
        Retrieve the instantiated L1 contract related to OP-Stack chain.

        Parameters
        ----------
        contract : OP_STACK_ETHEREUM

        Returns
        -------
        web3.contract.Contract
        """
        contracts = SCROLL_STACK_ETHEREUM_CONTRACTS.get(self.chain_name)

        if not contracts:
            raise ValueError("Invalid chain intitialized.")

        info = contracts.get(contract)

        if not info:
            raise ValueError("Invalid contract name provided.")

        return self.l1_provider.eth.contract(
            address=info.get("address"), abi=get_abi(info.get("ABI"))
        )

    # 1 implement deposit eth & call ✅
    # 2 check for deposit eth & call ✅
    # 3 send some amount from address A to B via send_transaction ✅
    # 4 deploy a contract via send_transaction 🚢
    # 5 implement send_transaction_via_signature
    # 6 Do 3 & 4 again via signature function
    # 7 L1 -> L2 Messaging done!

    def deposit_eth_and_call(
        self,
        value_ether: float,
        gas_limit: int,
        destination_address: Optional[ChecksumAddress] = None,
        data: HexBytes = HexBytes(""),
    ) -> TxReceipt:
        value = Web3.to_wei(value_ether, "ether")

        l1_gateway = self._get_l1_contract(SCROLL_STACK_ETHEREUM.L1_GATEWAY_ROUTER)

        deposit_eth_and_call = l1_gateway.functions.depositETHAndCall(
            destination_address,
            value,
            data,
            gas_limit,
        )

        message_queue = self._get_l1_contract(SCROLL_STACK_ETHEREUM.L1_MESSAGE_QUEUE_V2)
        l2_base_fee: int = message_queue.functions.estimateL2BaseFee().call()

        value = Wei(value + l2_base_fee * gas_limit)

        try:
            params: TxParams = {
                "from": self.account.address,
                "value": value,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
            }
            gas_estimates = deposit_eth_and_call.estimate_gas(params)
            params["gas"] = add_gas_buffer(gas_estimates)
            tx_payload = deposit_eth_and_call.build_transaction(params)

            signed_txn = self.account.sign_transaction(cast(dict, tx_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)
            return receipt

        except Exception as e:
            raise ScrollError(str(e), e)

    def send_transaction(
        self,
        value_ether: float,
        destination_address: ChecksumAddress | None,
        data: HexBytes = HexBytes(""),
        gas_limit: Optional[int] = None,
    ) -> TxReceipt:
        enforced_tx_gateway = self._get_l1_contract(
            SCROLL_STACK_ETHEREUM.ENFORCED_TX_GATEWAY
        )

        value = Web3.to_wei(value_ether, "ether")

        message_queue = self._get_l1_contract(SCROLL_STACK_ETHEREUM.L1_MESSAGE_QUEUE_V2)

        l2_base_fee: int = message_queue.functions.estimateL2BaseFee().call()

        l2_estimate_gas_params: TxParams = {
            "value": value,
            "nonce": self.l1_provider.eth.get_transaction_count(self.account.address),
            "data": data,
        }

        if destination_address:
            l2_estimate_gas_params["to"] = destination_address

        if not gas_limit:
            try:
                l2_gas_limit = self.l2_provider.eth.estimate_gas(l2_estimate_gas_params)
            except Exception as e:
                raise ValueError(e)

            gas_limit = add_gas_buffer(l2_gas_limit)

        l1_value = Wei(value + l2_base_fee * gas_limit)

        send_transaction = enforced_tx_gateway.functions.sendTransaction(
            destination_address,
            value,
            gas_limit,
            data,
        )

        try:
            params: TxParams = {
                "from": self.account.address,
                "value": l1_value,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
            }
            gas_estimate = send_transaction.estimate_gas(params)

            params["gas"] = add_gas_buffer(gas_estimate)
            tx_payload = send_transaction.build_transaction(params)

            signed_txn = self.account.sign_transaction(cast(dict, tx_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)
            return receipt

        except Exception as e:
            raise ValueError(str(e))

    def parse_queue_transaction_event(
        self, l1_txn_hash: HexBytes
    ) -> QueueTransactionEvent:
        msg_queue = self._get_l1_contract(SCROLL_STACK_ETHEREUM.L1_MESSAGE_QUEUE_V2)
        receipt = self.l1_provider.eth.get_transaction_receipt(l1_txn_hash)

        events = msg_queue.events.QueueTransaction().process_receipt(
            receipt, errors=DISCARD
        )

        if not len(events) > 0:
            raise EventParseError(
                f"{l1_txn_hash} does not emit `QueueTransaction()` event"
            )

        event = events[0]["args"]

        parsed_event: QueueTransactionEvent = {
            "sender": Web3.to_checksum_address(event["sender"]),
            "target": Web3.to_checksum_address(event["target"]),
            "queueIndex": event["queueIndex"],
            "value": Wei(event["value"]),
            "gasLimit": event["gasLimit"],
            "data": HexBytes(event["data"]),
        }

        return parsed_event

    def parse_sent_message_event(self, l1_txn_hash: HexBytes):
        scroll_messenger = self._get_l1_contract(
            SCROLL_STACK_ETHEREUM.L1_SCROLL_MESSENGER
        )
        receipt = self.l1_provider.eth.get_transaction_receipt(l1_txn_hash)

        events = scroll_messenger.events.SentMessage().process_receipt(
            receipt, errors=DISCARD
        )

        if not len(events) > 0:
            raise EventParseError(f"{l1_txn_hash} does not emit `SentMessage()` event")

        event = events[0]["args"]

        parsed_event: SentMessageEvent = {
            "sender": Web3.to_checksum_address(event["sender"]),
            "target": Web3.to_checksum_address(event["target"]),
            "value": Wei(event["value"]),
            "messageNonce": event["messageNonce"],
            "gasLimit": event["gasLimit"],
            "message": HexBytes(event["message"]),
        }

        return parsed_event

    def replay_message(
        self,
        l1_txn_hash: HexBytes,
        new_gas_limit: int,
        refund_address: Optional[ChecksumAddress] = None,
    ) -> TxReceipt:
        sent_message_event_info = self.parse_sent_message_event(l1_txn_hash)

        l1_messenger = self._get_l1_contract(SCROLL_STACK_ETHEREUM.L1_SCROLL_MESSENGER)

        if not refund_address:
            refund_address = self.account.address

        replay_message = l1_messenger.functions.replayMessage(
            sent_message_event_info["sender"],
            sent_message_event_info["target"],
            sent_message_event_info["value"],
            sent_message_event_info["messageNonce"],
            sent_message_event_info["message"],
            new_gas_limit,
            refund_address,
        )

        message_queue = self._get_l1_contract(SCROLL_STACK_ETHEREUM.L1_MESSAGE_QUEUE_V2)

        l2_base_fee: int = message_queue.functions.estimateL2BaseFee().call()

        value = Wei(new_gas_limit * l2_base_fee)

        try:
            params: TxParams = {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "value": value,
            }
            gas_estimates = replay_message.estimate_gas(params)

            params["gas"] = add_gas_buffer(gas_estimates)
            txn_payload = replay_message.build_transaction(params)

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )
            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)

            return receipt

        except Exception as e:
            raise ScrollError(str(e), e)

    def compute_l2_txn_hash(self, l1_txn_hash: HexBytes) -> HexBytes:
        queue_txn_event = self.parse_queue_transaction_event(l1_txn_hash)

        message_queue_v2 = self._get_l1_contract(
            SCROLL_STACK_ETHEREUM.L1_MESSAGE_QUEUE_V2
        )
        l2_txn_hash = message_queue_v2.functions.computeTransactionHash(
            queue_txn_event["sender"],
            queue_txn_event["queueIndex"],
            queue_txn_event["value"],
            queue_txn_event["target"],
            queue_txn_event["gasLimit"],
            queue_txn_event["data"],
        ).call()

        return HexBytes(l2_txn_hash)

    def send_transaction_via_signature(
        self,
        value_ether: float,
        sender_address: ChecksumAddress,
        destination_address: ChecksumAddress,
        deadline: int,
        signature: HexBytes,
        gas_limit: Optional[int] = None,
        data: HexBytes = HexBytes(""),
        refund_address: Optional[ChecksumAddress] = None,
    ):
        enforced_tx_gateway = self._get_l1_contract(
            SCROLL_STACK_ETHEREUM.ENFORCED_TX_GATEWAY
        )

        value = Web3.to_wei(value_ether, "ether")

        message_queue = self._get_l1_contract(SCROLL_STACK_ETHEREUM.L1_MESSAGE_QUEUE_V2)
        l2_base_fee: int = message_queue.functions.estimateL2BaseFee().call()

        l2_estimate_gas_params: TxParams = {
            "to": destination_address,
            "value": value,
            "nonce": self.l1_provider.eth.get_transaction_count(self.account.address),
            "data": data,
        }

        if not gas_limit:
            try:
                l2_gas_limit = self.l2_provider.eth.estimate_gas(l2_estimate_gas_params)
            except Exception as e:
                raise ValueError(e)

            gas_limit = add_gas_buffer(l2_gas_limit)

        l1_value = Wei(value + l2_base_fee * gas_limit)

        if not refund_address:
            refund_address = self.account.address

        send_via_signature = enforced_tx_gateway.functions.sendTransaction(
            sender_address,
            destination_address,
            value,
            gas_limit,
            data,
            deadline,
            signature,
            refund_address,
        )

        try:
            params: TxParams = {
                "from": self.account.address,
                "value": l1_value,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
            }
            gas_estimate = send_via_signature.estimate_gas(params)

            params["gas"] = add_gas_buffer(gas_estimate)
            tx_payload = send_via_signature.build_transaction(params)

            signed_txn = self.account.sign_transaction(cast(dict, tx_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)
            return receipt

        except Exception as e:
            raise ValueError(str(e))

    def sign_typed_send_transaction(
        self,
        signer_account: LocalAccount,
        destination_address: ChecksumAddress,
        value: Wei,
        gas_limit: int,
        deadline: int,
        data: HexBytes,
    ) -> HexBytes:
        enforced_gateway = self._get_l1_contract(
            SCROLL_STACK_ETHEREUM.ENFORCED_TX_GATEWAY
        )

        eip712_domain = {
            "name": "EnforcedTxGateway",
            "version": "1",
            "chainId": self.l1_provider.eth.chain_id,
            "verifyingContract": enforced_gateway.address,
        }

        eip712_types = {
            "EnforcedTransaction": [
                {"name": "sender", "type": "address"},
                {"name": "target", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "gasLimit", "type": "uint256"},
                {"name": "data", "type": "bytes"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
        }

        nonce = enforced_gateway.functions.nonces(signer_account.address).call()

        message = {
            "sender": signer_account.address,
            "target": destination_address,
            "value": value,
            "gasLimit": gas_limit,
            "data": data,
            "nonce": nonce,
            "deadline": deadline,
        }

        signed_message = signer_account.sign_typed_data(
            domain_data=eip712_domain,
            message_types=eip712_types,
            message_data=message,
        )

        return signed_message.signature
