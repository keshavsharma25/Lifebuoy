from typing import Dict, Final, Optional, cast

import requests
from hexbytes import HexBytes
from eth_typing import ChecksumAddress
from web3 import Web3
from web3.logs import DISCARD
from web3.types import TxParams, TxReceipt, Wei

from .types import (
    ProofParams,
    QueueTransactionEvent,
    RelayMessageWithProofParams,
    SentMessageEvent,
)
from .custom_errors import (
    EventParseError,
    GasEstimationError,
    ScrollError,
    UnprovenError,
)
from utils.chain import add_gas_buffer, get_account, get_abi
from utils.config import (
    SCROLL_ETHEREUM,
    SCROLL_ETHEREUM_CONTRACTS,
    SCROLL_L2,
    SCROLL_L2_CONTRACTS,
    ChainName,
    ScrollChainName,
)
from eth_account.signers.local import LocalAccount

from utils.providers import get_web3


class Scroll:
    """
    Scroll stack implementation to perform force inclustion and withdrawals (escape hatch).
    """

    SCROLL_API_BASE_URL: Final[Dict[ScrollChainName, str]] = {
        ChainName.SCROLL_SEPOLIA: "https://sepolia-api-bridge-v2.scroll.io/api/",
        # ChainName.SCROLL_MAINNET: "https://mainnet-api-bridge-v2.scroll.io/api/"
    }

    def __init__(
        self,
        chain_name: ScrollChainName,
        account: Optional[LocalAccount] = None,
    ) -> None:
        self.chain_name = chain_name
        self.l1_provider = get_web3(ChainName.ETH_SEPOLIA)
        self.l2_provider = get_web3(chain_name)
        self.account = account or get_account()

    def _get_l1_contract(self, contract: SCROLL_ETHEREUM):
        """
        Retrieve the instantiated L1 contract related to OP-Stack chain.

        Parameters
        ----------
        contract : OP_STACK_ETHEREUM

        Returns
        -------
        web3.contract.Contract
        """
        contracts = SCROLL_ETHEREUM_CONTRACTS.get(
            cast(ScrollChainName, self.chain_name)
        )

        if not contracts:
            raise ValueError("Invalid chain intitialized.")

        info = contracts.get(contract)

        if not info:
            raise ValueError("Invalid contract name provided.")

        return self.l1_provider.eth.contract(
            address=info.get("address"), abi=get_abi(info.get("ABI"))
        )

    def _get_l2_contract(self, contract: SCROLL_L2):
        contracts = SCROLL_L2_CONTRACTS.get(cast(ScrollChainName, self.chain_name))

        if not contracts:
            raise ValueError("Invalid chain intitialized.")

        info = contracts.get(contract)

        if not info:
            raise ValueError("Invalid contract name provided.")

        return self.l2_provider.eth.contract(
            address=info.get("address"), abi=get_abi(info.get("ABI"))
        )

    def deposit_eth_and_call(
        self,
        value_ether: float,
        gas_limit: int,
        destination_address: Optional[ChecksumAddress] = None,
        data: HexBytes = HexBytes(""),
    ) -> TxReceipt:
        value = Web3.to_wei(value_ether, "ether")

        l1_gateway = self._get_l1_contract(SCROLL_ETHEREUM.L1_GATEWAY_ROUTER)

        deposit_eth_and_call = l1_gateway.functions.depositETHAndCall(
            destination_address,
            value,
            data,
            gas_limit,
        )

        message_queue = self._get_l1_contract(SCROLL_ETHEREUM.L1_MESSAGE_QUEUE_V2)
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
        destination_address: ChecksumAddress,
        data: HexBytes = HexBytes(""),
        gas_limit: Optional[int] = None,
    ) -> TxReceipt:
        enforced_tx_gateway = self._get_l1_contract(SCROLL_ETHEREUM.ENFORCED_TX_GATEWAY)

        value = Web3.to_wei(value_ether, "ether")

        message_queue = self._get_l1_contract(SCROLL_ETHEREUM.L1_MESSAGE_QUEUE_V2)

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
        msg_queue = self._get_l1_contract(SCROLL_ETHEREUM.L1_MESSAGE_QUEUE_V2)
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
        scroll_messenger = self._get_l1_contract(SCROLL_ETHEREUM.L1_SCROLL_MESSENGER)
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

        l1_messenger = self._get_l1_contract(SCROLL_ETHEREUM.L1_SCROLL_MESSENGER)

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

        message_queue = self._get_l1_contract(SCROLL_ETHEREUM.L1_MESSAGE_QUEUE_V2)

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

        message_queue_v2 = self._get_l1_contract(SCROLL_ETHEREUM.L1_MESSAGE_QUEUE_V2)
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
        enforced_tx_gateway = self._get_l1_contract(SCROLL_ETHEREUM.ENFORCED_TX_GATEWAY)

        value = Web3.to_wei(value_ether, "ether")

        message_queue = self._get_l1_contract(SCROLL_ETHEREUM.L1_MESSAGE_QUEUE_V2)
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
        enforced_gateway = self._get_l1_contract(SCROLL_ETHEREUM.ENFORCED_TX_GATEWAY)

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

    def is_L1_message_executed(self, l1_txn_hash: HexBytes) -> bool:
        l2_messenger = self._get_l2_contract(SCROLL_L2.L2_SCROLL_MESSENGER)
        boolean: bool = l2_messenger.functions.isL1MessageExecuted(l1_txn_hash).call()

        return boolean

    def withdraw_eth_and_call(
        self,
        destination_address: ChecksumAddress,
        value_ether: float,
        data: Optional[HexBytes] = HexBytes(""),
        gas_limit: Optional[int] = None,
    ) -> TxReceipt:
        value = Web3.to_wei(value_ether, "ether")
        l2_gateway = self._get_l2_contract(SCROLL_L2.L2_GATEWAY_ROUTER)

        if not gas_limit:
            try:
                l1_params: TxParams = {
                    "from": self.account.address,
                    "to": destination_address,
                    "nonce": self.l1_provider.eth.get_transaction_count(
                        self.account.address
                    ),
                    "value": value,
                }

                if data:
                    l1_params["data"] = data

                estimated_gas = self.l1_provider.eth.estimate_gas(l1_params)
                gas_limit = add_gas_buffer(estimated_gas)

            except Exception as e:
                GasEstimationError(str(e), e)

        withdraw_eth_and_call = l2_gateway.functions.withdrawETHAndCall(
            destination_address,
            value,
            data,
            gas_limit,
        )

        try:
            params: TxParams = {
                "from": self.account.address,
                "nonce": self.l2_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "value": value,
            }

            estimated_gas = withdraw_eth_and_call.estimate_gas(params)
            params["gas"] = estimated_gas

            tx_payload = withdraw_eth_and_call.build_transaction(params)

            signed_txn = self.account.sign_transaction(cast(dict, tx_payload))
            txn_hash = self.l2_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            receipt = self.l2_provider.eth.wait_for_transaction_receipt(txn_hash)
            return receipt

        except Exception as e:
            raise ScrollError(str(e), e)

    def get_withdrawal_params(
        self, l2_txn_hash: HexBytes
    ) -> RelayMessageWithProofParams:
        receipt = self.l2_provider.eth.get_transaction_receipt(l2_txn_hash)
        sender = receipt.get("from")

        base_url = self.SCROLL_API_BASE_URL.get(cast(ScrollChainName, self.chain_name))

        if not base_url:
            raise ScrollError("Invalid chain. Use only Scroll supported networks")

        endpoint = "l2/unclaimed/withdrawals"

        params = {
            "address": sender,
            "page": 1,
            "page_size": 10,
        }

        try:
            url = base_url + endpoint
            response = requests.get(url, params=params)

            response.raise_for_status()
            data = response.json()
            results = data.get("data").get("results")

            desired_result = None

            if not results:
                raise ValueError(
                    f"For given sender address ({sender}), there exists no unclaimed withdrawal txn"
                )

            for result in results:
                tx_hash = result.get("hash")

                if l2_txn_hash.to_0x_hex() == tx_hash:
                    desired_result = result
                    break

            if not desired_result:
                raise ValueError(
                    f"Provided withdrawal hash ({l2_txn_hash.to_0x_hex()}) not found in the unclaimed withdrawals"
                )

            claim_info = desired_result.get("claim_info")
            is_claim = claim_info.get("claimable")

            if not is_claim:
                raise UnprovenError("Batch is yet to proven")

            from_ = Web3.to_checksum_address(claim_info.get("from"))
            to = Web3.to_checksum_address(claim_info.get("to"))
            value = Wei(int(claim_info.get("value")))
            nonce = int(claim_info.get("nonce"))
            message = claim_info.get("message")
            proof = claim_info.get("proof")
            batch_index = int(proof.get("batch_index"))
            merkle_proof = proof.get("merkle_proof")

            parsed_proof: ProofParams = {
                "batchIndex": batch_index,
                "merkleProof": merkle_proof,
            }

            relay_params: RelayMessageWithProofParams = {
                "from_": from_,
                "to": to,
                "value": value,
                "nonce": nonce,
                "message": message,
                "proof": parsed_proof,
            }

            return relay_params

        except Exception as e:
            raise ScrollError(str(e), e)

    def relay_message_with_proof(self, l2_txn_hash: HexBytes) -> TxReceipt:
        l1_messenger = self._get_l1_contract(SCROLL_ETHEREUM.L1_SCROLL_MESSENGER)

        input_params = self.get_withdrawal_params(l2_txn_hash)

        from_ = input_params.get("from_")
        to = input_params.get("to")
        value = input_params.get("value")
        nonce = input_params.get("nonce")
        message = input_params.get("message")
        batch_index = input_params.get("proof").get("batchIndex")
        merkle_proof = input_params.get("proof").get("merkleProof")

        relay_message_with_proof = l1_messenger.functions.relayMessageWithProof(
            from_, to, value, nonce, message, (batch_index, merkle_proof)
        )

        try:
            params: TxParams = {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
            }

            gas_estimates = relay_message_with_proof.estimate_gas(params)
            params["gas"] = add_gas_buffer(gas_estimates)

            txn_payload = relay_message_with_proof.build_transaction(params)
            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)
            return receipt

        except Exception as e:
            raise ScrollError(str(e), e)
