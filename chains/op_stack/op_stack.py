"""
OP Stack implementation for forced transaction inclusion and withdrawals.

This module provides a composable class for interacting with OP Stack chains
(Optimism, Base, etc.) to perform forced deposits and withdrawals.
"""

from typing import List, Optional, cast

from eth_utils.conversions import to_bytes
from eth_utils.address import to_checksum_address
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3.eth import Contract
from eth_abi.abi import encode
from web3.types import BlockData, MerkleProof, TxParams, TxReceipt, Wei
from .op_types import (
    CheckWithdrawalResponse,
    GameSearchResult,
    WithdrawalParams,
    OutputRootProof,
)
from utils.chain import estimate_l2_gas, get_abi, get_account
from utils.config import (
    OP_STACK_L2_CONTRACTS,
    OP_STACK_ETHEREUM_CONTRACTS,
    ChainName,
    OPStackChainName,
)
from utils.providers import get_web3


class OPStackError(Exception):
    """Base Exception for OP Stack operations."""

    pass


class InvalidChainError(OPStackError):
    """Raised when an invalid chain is specified"""

    pass


class InvalidBlockNumber(OPStackError):
    """Raised when an invalid block number is specified"""

    pass


class OPStack:
    """
    This class is to interact with OP-Stack compatible chains
    like Optimism, Base, Unichain, etc.

    It should be used to perform deposit transactions from L1 → L2 (~15 minutes)
    and perform withdrawals from L2 → L1 (~7 days)
    """

    def __init__(
        self, chain_name: OPStackChainName, account: Optional[LocalAccount] = None
    ):
        self.chain_name = chain_name
        self.l1_provider = get_web3(ChainName.ETH_SEPOLIA)
        self.l2_provider = get_web3(chain_name)
        self.account = account or get_account()

    def portal_contract(self) -> Contract:
        """Get the OptimismPortal2 L1 contract instance."""
        contracts = OP_STACK_ETHEREUM_CONTRACTS.get(self.chain_name)

        if not contracts:
            raise InvalidChainError("Invalid chain intitialized.")

        info = contracts.get("OPTIMISM_PORTAL")

        return self.l1_provider.eth.contract(
            address=info.get("address"), abi=get_abi(info.get("ABI"))
        )

    def message_passer_contract(self) -> Contract:
        """Get the L2toL1MessagePasser L2 contract address"""
        contracts = OP_STACK_L2_CONTRACTS.get(self.chain_name)

        if not contracts:
            raise InvalidChainError("Invalid chain intitialized.")

        info = contracts.get("L2_TO_L1_MESSAGE_PASSER")

        return self.l1_provider.eth.contract(
            address=info.get("address"),
            abi=get_abi(info.get("ABI")),
        )

    def dispute_game_factory(self) -> Contract:
        """Get the Dispute Game Factory L1 contract address"""
        contracts = OP_STACK_ETHEREUM_CONTRACTS.get(self.chain_name)

        if not contracts:
            raise InvalidChainError("Invalid chain intitialized.")

        info = contracts.get("DISPUTE_GAME_FACTORY")

        return self.l1_provider.eth.contract(
            address=info.get("address"),
            abi=get_abi(info.get("ABI")),
        )

    def deposit_transaction(
        self,
        to: ChecksumAddress | None,
        value: float,
        is_creation: bool,
        data: bytes,
    ) -> TxReceipt:
        contract = self.portal_contract()
        value = self.l1_provider.to_wei(value, "ether")

        gas_limit = estimate_l2_gas(
            self.l2_provider, to, self.account.address, value, data
        )

        txn = contract.functions.depositTransaction(
            to,
            value,
            gas_limit,
            is_creation,
            data,
        )

        estimated_gas = self.l1_provider.eth.estimate_gas(
            {
                "from": self.account.address,
                "to": contract.address,
                "value": value,
                "data": txn._encode_transaction_data(),
            }
        )

        txn_payload: TxParams = txn.build_transaction(
            {
                "from": self.account.address,
                "value": Wei(value),
                "gas": int(estimated_gas * 1.3 + 20_000),
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "chainId": self.l1_provider.eth.chain_id,
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
            raise OPStackError(f"Deposit Transaction failed: {e}")

    def deposit_eth(self, to: ChecksumAddress, value: float) -> TxReceipt:
        is_creation = False
        data = b""

        return self.deposit_transaction(to, value, is_creation, data)

    def initiate_withdrawal(
        self,
        target_address: ChecksumAddress,
        withdraw_value: float,
        gas_limit: int,
        data: bytes = b"",
    ):
        mp_contract = self.message_passer_contract()

        value = self.l2_provider.to_wei(withdraw_value, "ether")

        msg_passer_txn = mp_contract.functions.initiateWithdrawal(
            target_address,
            gas_limit,
            data,
        )

        gas_estimate = estimate_l2_gas(
            self.l2_provider,
            mp_contract.address,
            self.account.address,
            value,
            data,
        )

        txn_payload: TxParams = msg_passer_txn.build_transaction(
            {
                "from": self.account.address,
                "value": value,
                "gas": int(gas_estimate * 1.3 + 20_000),
                "nonce": self.l2_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "chainId": self.l2_provider.eth.chain_id,
            }
        )

        signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
        txn_hash = self.l2_provider.eth.send_raw_transaction(signed_txn.raw_transaction)

        withdraw_receipt = self.l2_provider.eth.wait_for_transaction_receipt(txn_hash)

        return withdraw_receipt

    def _parse_withdrawal_params(self, txn_hash: HexBytes) -> WithdrawalParams:
        withdraw_receipt = self.l2_provider.eth.get_transaction_receipt(txn_hash)

        if not withdraw_receipt:
            raise ValueError(
                f"Invalid receipt! Check if the txn_hash: {txn_hash} is correct."
            )

        events = (
            self.message_passer_contract()
            .events.MessagePassed()
            .process_receipt(withdraw_receipt)
        )

        if not events or not len(events) > 0:
            raise ValueError(
                f"`len(events) = {len(events)}`. `txn_hash` does not emit `MessagePassed` event."
            )

        event = events[0]

        parsed: WithdrawalParams = {
            "nonce": event.get("args").get("nonce"),
            "sender": event.get("args").get("sender"),
            "target": event.get("args").get("target"),
            "value": event.get("args").get("value"),
            "gas_limit": event.get("args").get("gasLimit"),
            "data": event.get("args").get("data"),
        }

        return parsed

    def _parse_withdrawal_hash(self, txn_hash: HexBytes) -> HexBytes:
        withdraw_receipt = self.l2_provider.eth.get_transaction_receipt(txn_hash)

        if not withdraw_receipt:
            raise ValueError(
                f"Invalid receipt! Check if the txn_hash: {txn_hash} is correct."
            )

        events = (
            self.message_passer_contract()
            .events.MessagePassed()
            .process_receipt(withdraw_receipt)
        )

        if not events or not len(events) > 0:
            raise ValueError(
                f"`len(events) = {len(events)}`. `txn_hash` does not emit `MessagePassed` event."
            )

        event = events[0]

        withdrawal_hash = HexBytes(event.get("args").get("withdrawalHash"))

        return withdrawal_hash

    def _verify_withdrawal_hash(
        self, withdrawal_params: WithdrawalParams, withdrawal_hash: HexBytes
    ) -> bool:
        # compute withdrawal hash from withdrawal types & params
        computed_hash = self.l1_provider.keccak(
            encode(
                ["uint256", "address", "address", "uint256", "uint256", "bytes"],
                list(withdrawal_params.values()),
            )
        )

        return withdrawal_hash.hex() == computed_hash.hex()

    def _get_latest_game_result(self, game_id: int | None = None) -> GameSearchResult:
        dispute_game_factory = self.dispute_game_factory()
        game_count = dispute_game_factory.functions.gameCount().call()
        respected_game_type = (
            self.portal_contract().functions.respectedGameType().call()
        )

        if game_id is None:
            latest_games = dispute_game_factory.functions.findLatestGames(
                respected_game_type,
                game_count - 1,
                1,
            ).call()
        else:
            latest_games = dispute_game_factory.functions.findLatestGames(
                respected_game_type,
                game_id,
                1,
            ).call()

        if not latest_games or not len(latest_games) > 0:
            raise ValueError(
                f"`len(latest_games) = {len(latest_games)}. Check dispute game for a valid game_id."
            )

        latest_game = latest_games[0]

        if not latest_game or not len(latest_game) == 5:
            raise ValueError(
                "`Game` must return a tuple of size 5. Invalid dispute game."
            )

        game_result: GameSearchResult = {
            "index": latest_game[0],
            "metadata": latest_game[1],
            "timestamp": latest_game[2],
            "root_claim": latest_game[3],
            "extra_data": latest_game[4],
        }

        return game_result

    def _get_game_l2_block(self, game_id: int | None = None) -> BlockData:
        game_result = self._get_latest_game_result(game_id)

        extra_data = game_result.get("extra_data")
        l2_game_block_number = int.from_bytes(extra_data[:32], "big")

        l2_game_header: BlockData = self.l2_provider.eth.get_block(l2_game_block_number)

        return l2_game_header

    def _get_storage_slot(self, withdrawal_hash: HexBytes) -> str:
        storage_slot = self.l1_provider.keccak(
            withdrawal_hash + (0).to_bytes(32, byteorder="big")
        )

        return storage_slot.hex()

    def _get_proof(self, withdraw_txn_hash: HexBytes) -> MerkleProof:
        withdrawal_block = self.l2_provider.eth.get_transaction_receipt(
            withdraw_txn_hash
        )
        withdrawal_hash = self._parse_withdrawal_hash(withdraw_txn_hash)
        withdrawal_block_no = withdrawal_block.get("blockNumber")

        storage_slot = self._get_storage_slot(withdrawal_hash)

        proof: MerkleProof = self.l2_provider.eth.get_proof(
            self.message_passer_contract().address,
            [storage_slot],  # type: ignore[reportCallIssue]
            int(withdrawal_block_no),
        )

        return proof

    def _get_output_root_proof(
        self,
        withdraw_txn_hash: HexBytes,
        game_id: int | None = None,
    ) -> OutputRootProof:
        l2_game_header = self._get_game_l2_block(game_id)

        state_root = l2_game_header.get("stateRoot")
        block_hash = l2_game_header.get("hash")

        proof = self._get_proof(withdraw_txn_hash)
        storage_hash = proof.get("storageHash")

        if not state_root:
            raise ValueError("Error finding `stateRoot` in `BlockData`")

        if not block_hash:
            raise ValueError("Error finding `hash` in `BlockData`")

        output_root_proof: OutputRootProof = {
            "version": (0).to_bytes(32, byteorder="big"),
            "state_root": state_root.__bytes__(),
            "message_passer_storage_root": storage_hash.__bytes__(),
            "latest_block_hash": block_hash.__bytes__(),
        }

        return output_root_proof

    def _get_withdrawal_proof(self, withdraw_txn_hash: HexBytes) -> List[bytes]:
        proof = self._get_proof(withdraw_txn_hash)

        if not proof:
            raise ValueError(f"get_proof returned type {type(proof)}")

        storage_proofs = proof.get("storageProof")

        if not storage_proofs or len(storage_proofs) == 0:
            raise ValueError("No storage proofs returned")

        storage_proof = storage_proofs[0]

        withdrawal_proof = [
            to_bytes(hexstr=node) if isinstance(node, str) else node
            for node in storage_proof["proof"]
        ]

        return withdrawal_proof

    def _verify_root_claim(
        self, withdraw_txn_hash: HexBytes, game_id: int | None = None
    ):
        output_root_proof = self._get_output_root_proof(withdraw_txn_hash, game_id)
        game_result = self._get_latest_game_result(game_id)

        computed_claim = self.l1_provider.keccak(
            encode(
                ["bytes32", "bytes32", "bytes32", "bytes32"],
                list(output_root_proof.values()),
            )
        ).hex()

        root_claim = game_result["root_claim"].hex()

        assert computed_claim == root_claim, (
            f"Claim doesn't match. `computed_claim:{computed_claim} != root_claim: {root_claim}`"
        )

    def prove_withdrawal_transaction(self, withdraw_txn_hash: HexBytes) -> TxReceipt:
        withdrawal_params = self._parse_withdrawal_params(withdraw_txn_hash)
        game_result = self._get_latest_game_result()
        dispute_game_index = game_result.get("index")
        output_root_proof = self._get_output_root_proof(withdraw_txn_hash)
        withdrawal_proof = self._get_withdrawal_proof(withdraw_txn_hash)

        withdrawal_block = self.l2_provider.eth.get_transaction_receipt(
            withdraw_txn_hash
        )
        withdrawal_block_no = withdrawal_block.get("blockNumber")

        game_l2_block_header = self._get_game_l2_block()
        game_l2_block_number = game_l2_block_header.get("number")

        if game_l2_block_number is None:
            raise InvalidBlockNumber(
                f"invalid respective dispute game L2 block number provided. Check game index: `{dispute_game_index}`"
            )

        assert game_l2_block_number > withdrawal_block_no, (
            f"Game block `{game_l2_block_number}` must be > Withdrawal block `{withdrawal_block_no}`. ⚠️NOTE: Try again when new dispute game contracts created are greater than the block that contains your withdrawal txn."
        )

        self._verify_root_claim(withdraw_txn_hash)

        prove_withdrawal_transaction = (
            self.portal_contract().functions.proveWithdrawalTransaction(
                list(withdrawal_params.values()),
                dispute_game_index,
                list(output_root_proof.values()),
                withdrawal_proof,
            )
        )

        gas_estimate = prove_withdrawal_transaction.estimate_gas(
            {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "chainId": self.l1_provider.eth.chain_id,
            }
        )

        txn_payload = prove_withdrawal_transaction.build_transaction(
            {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "chainId": self.l1_provider.eth.chain_id,
                "gas": int(gas_estimate * 1.3 + 20_000),
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
            raise OPStackError(f"Prove withdrawal failed: {e}")

    def finalize_withdrawal_transaction_externalproof(
        self,
        withdraw_txn_hash: HexBytes,
        external_prover_address: ChecksumAddress,
    ) -> TxReceipt:
        withdrawal_hash = self._parse_withdrawal_hash(withdraw_txn_hash)

        assert self.is_withdrawal_enabled(withdrawal_hash), (
            f"Withdrawals yet to be enabled for `withdrawalHash`: {withdrawal_hash}"
        )

        withdrawal_params = self._parse_withdrawal_params(withdraw_txn_hash)

        finalize_withdrawal_transaction = (
            self.portal_contract().functions.finalizeWithdrawalTransactionExternalProof(
                withdrawal_params,
                external_prover_address,
            )
        )

        gas_estimate = finalize_withdrawal_transaction.estimate_gas(
            {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "chainId": self.l1_provider.eth.chain_id,
            }
        )

        txn_payload = finalize_withdrawal_transaction.build_transaction(
            {
                "from": self.account.address,
                "nonce": self.l1_provider.eth.get_transaction_count(
                    self.account.address
                ),
                "chainId": self.l1_provider.eth.chain_id,
                "gas": int(gas_estimate * 1.3 + 20_000),
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
            raise OPStackError(f"Prove withdrawal failed: {e}")

    def check_withdrawal_status(
        self, withdrawal_hash: HexBytes, proof_submitter: ChecksumAddress
    ) -> CheckWithdrawalResponse:
        portal = self.portal_contract()

        finalized_withdrawals: bool = portal.functions.finalizedWithdrawals(
            withdrawal_hash
        ).call()
        proven_withdrawal = portal.functions.provenWithdrawals(
            withdrawal_hash, proof_submitter
        ).call()

        if (
            not proven_withdrawal
            or len(proven_withdrawal) != 2
            or proven_withdrawal[0] == to_checksum_address("00" * 20)
            or proven_withdrawal[1] == 0
        ):
            raise ValueError(
                f"invalid proven withdrawal for withdrawal hash: {withdrawal_hash.to_0x_hex()}"
            )

        response: CheckWithdrawalResponse = {
            "is_withdrawal_enabled": finalized_withdrawals,
            "fault_dispute_game_address": to_checksum_address(proven_withdrawal[0]),
            "timestamp": proven_withdrawal[1],
        }

        return response

    def is_withdrawal_enabled(self, withdrawal_hash: HexBytes) -> bool:
        portal = self.portal_contract()

        finalized_withdrawals = portal.functions.finalizedWithdrawals(
            withdrawal_hash
        ).call()

        return finalized_withdrawals
