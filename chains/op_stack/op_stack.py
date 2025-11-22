"""
OP Stack implementation for forced transaction inclusion and withdrawals (as an escape hatch).

This module provides a composable class for interacting with OP Stack chains
(Optimism, Base, etc.) to perform forced deposits and withdrawals.
"""

from typing import List, Optional, cast

from eth_utils.conversions import to_bytes
from eth_utils.address import to_checksum_address
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3 import Web3
from eth_abi.abi import encode
from web3.types import BlockData, MerkleProof, TxParams, TxReceipt, Wei
from .types import (
    ProvenWithdrawalResponse,
    GameSearchResult,
    WithdrawalParams,
    OutputRootProof,
)
from utils.chain import add_gas_buffer, estimate_l2_gas, get_abi, get_account
from utils.config import (
    ABI_FAULT_DISPUTE_GAME,
    OP_STACK_ETHEREUM,
    OP_STACK_L2,
    OP_STACK_L2_CONTRACTS,
    OP_STACK_ETHEREUM_CONTRACTS,
    ChainName,
    OPStackChainName,
)
from utils.providers import get_web3
from .custom_errors import (
    OPStackError,
    OPPortalInvalidProofTimstamp,
    OPPortalInvalidRootClaim,
    OPPortalUnproven,
    OPPortalProofNotOldEnough,
    InvalidBlockNumber,
    InvalidChainError,
)


class OPStack:
    """
    This class is to interact with OP-Stack compatible chains
    like Optimism, Base, Unichain, etc.

    Parameters
    ----------
    chain_name: OPStackChainName
        Canonical identifier of the OP-Stack chain to connect to.

    account: LocalAccount, optional
        Local private-key account used for signing transactions.
        If omitted, a local account would be instantiated in case you provided your
        PRIVATE-KEY in `.env`

    MORE INFO
    ----------
    In principle, L1 -> L2 messaging is traversed via Optimsim Portal2 contract that is responsible
    for ETH deposits and transaction deposits via `depositETH()` and `depositTransaction()`
    respectively. The purpose is to force include transactions in case, sequencer is supressing
    your submitted transactions on L2.

    Force included transactions are executed every first block of an L2 epoch (all the blocks proposed
    by the sequencer is one ethereum slot i.e. 12 seconds) upon achieving finalization on Ethereum (2 epoch).

    Whereas, for the L2 -> L1 message (ETH withdrawals primarily), you initiate withdrawals
    using L2toL1MessagePasser contract via `initiateWithdrawal()`. Upon successful initiation,
    the next task is to prove if the withdrawal was successful.

    Via `proveWithdrawalTransaction` in Optimism Portal2 contract on Ethereum, the user has to prove that
    the transaction was included in the dispute game. Dispute games are created in certain
    intervals and account for all the rollup state prior to a threshold block, the rollup considers
    finalized wrt Ethereum (hence a noticeable lag exists between the current block and recently
    deployed dispute game threshold block). Once the merkle proof that relates to your initiateWithdrawal
    txn has been proved, we proceed into a 7-day withdrawal waiting period.

    Upon completion of 7-day withdrawal period, if the dispute game in uncontested (defender wins),
    the user can withdraw their initiated withdrawals using Optimism Portal2 contract via
    `finalizeWithdrawalTransactionExternalProof()` or `finalizeWithdrawalTransaction()`.

    Upon successful execution of the transaction the withdrawal process is hence completed.

    Hence, this class should be used to perform deposit transactions or deposit ETH
    from L1 → L2 (~15 minutes) and perform withdrawals from L2 → L1 (~7 days).

    """

    def __init__(
        self,
        chain_name: OPStackChainName,
        account: Optional[LocalAccount] = None,
    ):
        self.chain_name = chain_name
        self.l1_provider = get_web3(ChainName.ETH_SEPOLIA)
        self.l2_provider = get_web3(chain_name)
        self.account = account or get_account()

    def _get_l1_contract(self, contract: OP_STACK_ETHEREUM):
        """
        Retrieve the instantiated L1 contract related to OP-Stack chain.

        Parameters
        ----------
        contract : OP_STACK_ETHEREUM

        Returns
        -------
        web3.contract.Contract
        """
        contracts = OP_STACK_ETHEREUM_CONTRACTS.get(
            cast(OPStackChainName, self.chain_name)
        )

        if not contracts:
            raise InvalidChainError("Invalid chain intitialized.")

        info = contracts.get(contract)

        if not info:
            raise InvalidChainError("Invalid contract name provided.")

        return self.l1_provider.eth.contract(
            address=info.get("address"), abi=get_abi(info.get("ABI"))
        )

    def _get_l2_contract(self, contract: OP_STACK_L2):
        """
        Retrieve the instantiated L2 contracts related to OP-Stack chain.

        Parameters
        ----------
        contract : OP_STACK_L2

        Returns
        -------
        web3.contract.Contract
        """
        contracts = OP_STACK_L2_CONTRACTS.get(cast(OPStackChainName, self.chain_name))

        if not contracts:
            raise InvalidChainError("Invalid chain intitialized.")

        info = contracts.get(contract)

        if not info:
            raise InvalidChainError("Invalid contract name provided.")

        return self.l2_provider.eth.contract(
            address=info.get("address"), abi=get_abi(info.get("ABI"))
        )

    def deposit_transaction(
        self,
        to: ChecksumAddress | None,
        value: float,
        is_creation: bool,
        data: bytes,
    ) -> TxReceipt:
        """
        Send a `depositTransaction` to the L2 via Optimism portal. Via this
        function, users can directly submit transactions on the L2 via L1. The
        `data` parameter is L2 calldata that the user sends to perform it on
        L2. The time depends on the L1 finality (~2 L1 epoch). These transactions
        override the sequencer, as the sequencer are compelled to include them
        in the first block of every L2 epoch (~12 seconds).


        Parameters
        ----------
        to : ChecksumAddress | None
            L2 recipient address.  Set to ``None`` when ``is_creation=True``.

        value : float
            Amount of ETH (in **ether**, not wei) to deposit.

        is_creation : bool
            ``True`` if this is a contract-creation deposit; ``False`` for a
            message call.

        data : bytes
            Calldata (or init-code if ``is_creation``) to forward to L2.

        Returns
        -------
        TxReceipt
            Web3 transaction receipt for the **L1** transaction that executed
            the portal deposit.
        """
        contract = self._get_l1_contract(OP_STACK_ETHEREUM.OPTIMISM_PORTAL)
        value = Web3.to_wei(value, "ether")

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
                "gas": add_gas_buffer(estimated_gas),
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
        """
        Deposit native ETH from L1 to L2. Optimism Portal2 contract also
        wraps `depositTransaction` function to perform ETH deposits on L2.

        This is a convenience wrapper around `deposit_transaction`
        that sets ``is_creation=False`` and ``data=b""`` automatically.

        Parameters
        ----------
        to : ChecksumAddress
            L2 address that will receive the deposited ETH.

        value : float
            Amount of ETH (in **ether**, not wei) to deposit.

        Returns
        -------
        TxReceipt
            Web3 transaction receipt for the L1 portal-deposit transaction.

        Examples
        --------
        >>> receipt = client.deposit_eth("0xAbC...", 0.5)
        >>> assert receipt.status == 1
        """
        is_creation = False
        data = b""

        return self.deposit_transaction(to, value, is_creation, data)

    def initiate_withdrawal(
        self,
        target_address: ChecksumAddress,
        withdraw_value: float,
        gas_limit: int,
        data: bytes = b"",
    ) -> TxReceipt:
        """
        Initiate a withdrawal of ETH (or a message call) from L2 -> L1.

        The function sends a transaction on L2 that burns the requested amount
        of ETH and emits the withdrawal hash that must later be proven and
        finalized on L1 after the fault-proof window (≥ 7 days).

        Parameters
        ----------
        target_address : ChecksumAddress
            L1 address that will ultimately receive the withdrawn ETH (or
            the target of the arbitrary message if ``data`` is non-empty).

        withdraw_value : float
            Amount of ETH (in **ether**, not wei) to withdraw.

        gas_limit : int
            Gas limit reserved for executing the message on L1.

        data : bytes, optional
            Additional calldata forwarded to ``target_address`` on L1.
            Defaults to ``b""`` for a simple ETH transfer.

        Returns
        -------
        TxReceipt
        """
        mp_contract = self._get_l2_contract(OP_STACK_L2.L2_TO_L1_MESSAGE_PASSER)

        value = Web3.to_wei(withdraw_value, "ether")

        msg_passer_txn = mp_contract.functions.initiateWithdrawal(
            target_address,
            gas_limit,
            data,
        )

        try:
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
                    "gas": gas_estimate,
                    "nonce": self.l2_provider.eth.get_transaction_count(
                        self.account.address
                    ),
                    "chainId": self.l2_provider.eth.chain_id,
                }
            )

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l2_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )

            withdraw_receipt = self.l2_provider.eth.wait_for_transaction_receipt(
                txn_hash
            )

            return withdraw_receipt
        except Exception as e:
            raise OPStackError(e)

    def parse_withdrawal_params(self, init_wd_txn_hash: HexBytes) -> WithdrawalParams:
        """
        Extract the canonical `WithdrawalParams` struct emitted by a L2 `initiateWithdrawal`
        transaction.

        Parameters
        ----------
        init_wd_txn_hash : HexBytes
            Transaction hash  of an L2 transaction where the user executed `initiateWithdrawal`
            that emits the ``MessagePassed`` event.

        Returns
        -------
        WithdrawalParams
            Named tuple containing the fields required to later prove and
            finalize the withdrawal on L1:

            * ``nonce`` – unique withdrawal nonce emitted in the event
            * ``sender`` – L2 address that initiated the withdrawal
            * ``target`` – L1 address that will receive the withdrawal
            * ``value`` – amount of ETH (in **wei**) being withdrawn
            * ``gasLimit`` – gas limit reserved for L1 execution
            * ``data`` – calldata forwarded to the target on L1
        """
        withdraw_receipt = self.l2_provider.eth.get_transaction_receipt(
            init_wd_txn_hash
        )

        if not withdraw_receipt:
            raise ValueError(
                f"Invalid receipt! Check if the txn_hash: {init_wd_txn_hash} is correct."
            )

        events = (
            self._get_l2_contract(OP_STACK_L2.L2_TO_L1_MESSAGE_PASSER)
            .events.MessagePassed()
            .process_receipt(withdraw_receipt)
        )

        if not events or not len(events) > 0:
            raise ValueError(
                f"`len(events) = {len(events)}`. `txn_hash` does not emit `MessagePassed` event."
            )

        event = events[0]

        parsed: WithdrawalParams = WithdrawalParams(
            nonce=event.get("args").get("nonce"),
            sender=event.get("args").get("sender"),
            target=event.get("args").get("target"),
            value=event.get("args").get("value"),
            gasLimit=event.get("args").get("gasLimit"),
            data=event.get("args").get("data"),
        )

        return parsed

    def parse_withdrawal_hash(self, init_wd_txn_hash: HexBytes) -> HexBytes:
        """
        Retrieve the canonical withdrawal hash from an L2-initiated withdrawal.

        The withdrawal hash is emitted in the ``MessagePassed`` event and is
        required to prove and finalize the withdrawal on L1.

        Parameters
        ----------
        init_wd_txn_hash : HexBytes
            Transaction hash (or full receipt) of the L2 transaction that
            initiated the withdrawal.

        Returns
        -------
        HexBytes
            32-byte withdrawal hash produced by the OP-Stack protocol.
        """
        withdraw_receipt = self.l2_provider.eth.get_transaction_receipt(
            init_wd_txn_hash
        )

        if not withdraw_receipt:
            raise ValueError(
                f"Invalid receipt! Check if the txn_hash: {init_wd_txn_hash} is correct."
            )

        events = (
            self._get_l2_contract(OP_STACK_L2.L2_TO_L1_MESSAGE_PASSER)
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
        """
        Check that a given `WithdrawalParams` produces the expected 32-byte
        withdrawal hash.

        The function re-computes the hash and compares it to the supplied hash.

        Parameters
        ----------
        withdrawal_params : WithdrawalParams
            Struct containing the six fields that define the withdrawal.

        withdrawal_hash : HexBytes
            32-byte withdrawal hash returned by `parse_withdrawal_hash(init_wd_txn_hash)`.

        Returns
        -------
        bool
            ``True`` if the locally computed hash equals ``withdrawal_hash``,
            ``False`` otherwise.
        """
        # compute withdrawal hash from withdrawal types & params
        computed_hash = Web3.keccak(
            encode(
                ["uint256", "address", "address", "uint256", "uint256", "bytes"],
                withdrawal_params,
            )
        )

        return withdrawal_hash.hex() == computed_hash.hex()

    def _get_latest_game_result(self, game_id: int | None = None) -> GameSearchResult:
        """
        Locate the most recent fault-dispute game that can be used to prove
        the L2 output root containing a withdrawal.

        Parameters
        ----------
        game_id : int | None, optional

        Returns
        -------
        GameSearchResult
        """
        dispute_game_factory = self._get_l1_contract(
            OP_STACK_ETHEREUM.DISPUTE_GAME_FACTORY
        )
        portal = self._get_l1_contract(OP_STACK_ETHEREUM.OPTIMISM_PORTAL)

        game_count = dispute_game_factory.functions.gameCount().call()
        respected_game_type = portal.functions.respectedGameType().call()

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
        """
        Retrieve the authoritative L2 block that a dispute game (fault proof) attests to.

        The returned result contains the block header required to generate or
        verify any withdrawal proof against that game.

        Parameters
        ----------
        game_id : int | None, optional

        Returns
        -------
        web3.types.BlockData
        """
        game_result = self._get_latest_game_result(game_id)

        extra_data = game_result.get("extra_data")
        l2_game_block_number = int.from_bytes(extra_data[:32], "big")

        l2_game_header: BlockData = self.l2_provider.eth.get_block(l2_game_block_number)

        return l2_game_header

    def _get_storage_slot(self, withdrawal_hash: HexBytes) -> str:
        """
        Compute the EVM storage slot in the `L2ToL1MessagePasser`
        that records whether a given withdrawal has been proven.

        The slot index is derived as
        `keccak256(withdrawal_hash + 0x00...0)` according to the
        OP-Stack specification.

        Parameters
        ----------
        withdrawal_hash : HexBytes
            32-byte withdrawal hash returned by `parse_withdrawal_hash(init_wd_txn_hash)`.

        Returns
        -------
        storag_slot_index: str
        """
        # The withdrawals mapping is the 0th storage slot in the L2ToL1MessagePasser contract.
        # To determine the storage slot, use keccak256(withdrawalHash + 0x00....00)
        # ref: https://specs.optimism.io/fault-proof/stage-one/optimism-portal.html#block-output
        storage_slot = Web3.keccak(withdrawal_hash + (0).to_bytes(32, byteorder="big"))

        return storage_slot.hex()

    def _get_proof(self, init_wd_tx_hash: HexBytes) -> MerkleProof:
        """
        Generate the Merkle Patricia proof that a given withdrawal
        is included in the L2ToL1MessagePasser’s storage root.

        The proof is generated against the L2 block committed by the
        dispute game that will later be used to prove the withdrawal.

        Parameters
        ----------
        init_wd_tx_hash : HexBytes
            Transaction hash (or full receipt) of the L2 transaction that
            initiated the withdrawal.

        Returns
        -------
        MerkleProof (web3.types)
        """
        withdrawal_receipt = self.l2_provider.eth.get_transaction_receipt(
            init_wd_tx_hash
        )
        withdrawal_hash = self.parse_withdrawal_hash(init_wd_tx_hash)
        withdrawal_block_no = withdrawal_receipt.get("blockNumber")

        storage_slot = self._get_storage_slot(withdrawal_hash)

        proof: MerkleProof = self.l2_provider.eth.get_proof(
            self._get_l2_contract(OP_STACK_L2.L2_TO_L1_MESSAGE_PASSER).address,
            [storage_slot],  # type: ignore[reportCallIssue]
            int(withdrawal_block_no),
        )

        return proof

    def _get_output_root_proof(
        self,
        init_wd_tx_hash: HexBytes,
        game_id: int | None = None,
    ) -> OutputRootProof:
        """
        Build the `OutputRootProof` struct required to finalize a withdrawal
        on the L1 `OptimismPortal`.

        The proof contains the minimal cryptographic data needed to convince
        the portal that the disputed L2 block is correct **and** that the
        withdrawal in question was indeed recorded in that block.

        Parameters
        ----------
        init_wd_tx_hash : HexBytes
            Transaction hash (or receipt) of the L2 withdrawal-initiating
            transaction—used to locate the block and the withdrawal slot.

        game_id : int | None, optional
            Specific dispute-game identifier whose committed output root
            should be used.  When omitted, the latest resolved game is
            selected automatically.

        Returns
        -------
        OutputRootProof
        """
        l2_game_header = self._get_game_l2_block(game_id)

        state_root = l2_game_header.get("stateRoot")
        block_hash = l2_game_header.get("hash")

        proof = self._get_proof(init_wd_tx_hash)
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

    def _get_withdrawal_proof(self, init_wd_tx_hash: HexBytes) -> List[bytes]:
        """
        Build the RLP-encoded Merkle proof (as a list of 32-byte nodes)
        demonstrating that a given withdrawal is present in the
        `L2ToL1MessagePasser` storage trie of the disputed L2 block.

        The returned proof is one of the four components required by the
        `OptimismPortal` when calling `proveWithdrawalTransaction`.

        Parameters
        ----------
        init_wd_tx_hash : HexBytes
            Transaction hash (or receipt) of the L2 transaction that
            initiated the withdrawal.

        Returns
        -------
        List[bytes]
            Ordered list of RLP-encoded trie nodes forming the Merkle path
            from the storage slot to the state root.  Each entry is exactly
            32 bytes except for the leaf, which may be longer if it
            contains the RLP-encoded storage value.

        """
        proof = self._get_proof(init_wd_tx_hash)

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

    def _verify_root_claim(self, init_wd_tx_hash: HexBytes, game_id: int | None = None):
        """
        Ensure the root claim committed by a dispute game is compatible
        with the L2 block that contains the given withdrawal.

        The check is performed by:

        1. Locating the L2 block that emitted the withdrawal.
        2. Computing the expected output root for that block.
        3. Comparing it to the root claim stored in the dispute game.

        If the two roots do not match, the withdrawal cannot be proven
        against this game and the method raises.

        Parameters
        ----------
        `init_wd_tx_hash` : HexBytes
            Transaction hash (or receipt) of the L2 withdrawal-initiating
            transaction.

        `game_id` : int | None, optional
            Identifier of the dispute game to test.  If omitted, the latest
            resolved game is used.

        """
        output_root_proof = self._get_output_root_proof(init_wd_tx_hash, game_id)
        game_result = self._get_latest_game_result(game_id)

        computed_claim = Web3.keccak(
            encode(
                ["bytes32", "bytes32", "bytes32", "bytes32"],
                list(output_root_proof.values()),
            )
        ).hex()

        root_claim = game_result["root_claim"].hex()

        assert computed_claim == root_claim, (
            f"Claim doesn't match. `computed_claim:{computed_claim} != root_claim: {root_claim}`"
        )

    def prove_withdrawal_transaction(self, init_wd_tx_hash: HexBytes) -> TxReceipt:
        """
        Submit the on-chain proof that demonstrates an initiated L2
        withdrawal is valid and is included in the L2 state committed by
        the corresponding dispute game.

        This is the *first* of the two mandatory on-chain steps to complete
        a withdrawal; the second step is `finalize_withdrawal_transaction`.

        Note: Wait for the challenge period to complete after this step

        Parameters
        ----------
        init_wd_tx_hash : HexBytes
            Transaction hash () of the L2 transaction that
            initiated the withdrawal.

        Returns
        -------
        TxReceipt
        """
        # param 1
        withdrawal_params = self.parse_withdrawal_params(init_wd_tx_hash)

        # param 2
        game_result = self._get_latest_game_result()
        dispute_game_index = game_result.get("index")

        # param 3
        output_root_proof = self._get_output_root_proof(init_wd_tx_hash)

        # param 4
        withdrawal_proof = self._get_withdrawal_proof(init_wd_tx_hash)

        withdrawal_block = self.l2_provider.eth.get_transaction_receipt(init_wd_tx_hash)
        withdrawal_block_no = withdrawal_block.get("blockNumber")

        # Check if  dispute game created upto block no. x > initiate_withdrawal_txn block no.
        # In case false, assertion failed
        game_l2_block_header = self._get_game_l2_block()
        game_l2_block_number = game_l2_block_header.get("number")

        if game_l2_block_number is None:
            raise InvalidBlockNumber(
                f"invalid respective dispute game L2 block number provided. Check game index: `{dispute_game_index}`"
            )

        assert game_l2_block_number > withdrawal_block_no, (
            f"Game block `{game_l2_block_number}` must be > Withdrawal block `{withdrawal_block_no}`. ⚠️NOTE: Try again when new dispute game contracts created are greater than the block that contains your withdrawal txn."
        )

        # verify root as well for sanity check
        self._verify_root_claim(init_wd_tx_hash)

        portal = self._get_l1_contract(OP_STACK_ETHEREUM.OPTIMISM_PORTAL)

        prove_withdrawal_transaction = portal.functions.proveWithdrawalTransaction(
            withdrawal_params,
            dispute_game_index,
            list(output_root_proof.values()),
            withdrawal_proof,
        )

        try:
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
                    "gas": add_gas_buffer(gas_estimate),
                }
            )

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
        init_wd_tx_hash: HexBytes,
        external_prover_address: Optional[ChecksumAddress],
    ) -> TxReceipt:
        """
        Finalize a proven L2 withdrawal using the OptimismPortal, optionally
        delegating the proof step to an external prover contract.

        Parameters
        ----------
        init_wd_tx_hash : HexBytes
            Transaction hash (or receipt) of the L2 withdrawal-initiating
            transaction—used to look up the canonical `WithdrawalParams`
            and verify the withdrawal has already been proven on L1.

        external_prover_address : ChecksumAddress | None
            Address that previously submitted the output-root
            proof on behalf of this withdrawal.

        Returns
        -------
        TxReceipt
        """

        if external_prover_address is None:
            external_prover_address = self.account.address

        withdrawal_hash = self.parse_withdrawal_hash(init_wd_tx_hash)

        assert not self.is_finalized_withdrawal(withdrawal_hash), (
            f"Associated withdrawal hash ({withdrawal_hash.to_0x_hex()}) has already been finalized"
        )

        assert self.is_withdrawal_enabled(withdrawal_hash, external_prover_address), (
            f"Withdrawals yet to be enabled for `withdrawalHash`: {withdrawal_hash.to_0x_hex()}"
        )

        portal = self._get_l1_contract(OP_STACK_ETHEREUM.OPTIMISM_PORTAL)

        withdrawal_params = self.parse_withdrawal_params(init_wd_tx_hash)

        finalize_withdrawal_transaction = (
            portal.functions.finalizeWithdrawalTransactionExternalProof(
                withdrawal_params,
                external_prover_address,
            )
        )

        try:
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
                    "gas": add_gas_buffer(gas_estimate),
                }
            )

            signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
            txn_hash = self.l1_provider.eth.send_raw_transaction(
                signed_txn.raw_transaction
            )
            receipt = self.l1_provider.eth.wait_for_transaction_receipt(txn_hash)

            return receipt
        except Exception as e:
            raise OPStackError(f"Prove withdrawal failed: {e}")

    def get_proven_withdrawal_info(
        self,
        withdrawal_hash: HexBytes,
        external_prover_address: ChecksumAddress,
    ) -> ProvenWithdrawalResponse:
        """
        Retrieve on-chain metadata for a withdrawal to check if the withdrawal
        has already been proven on the L1 `OptimismPortal`.

        Parameters
        ----------
        withdrawal_hash : HexBytes
            32-byte withdrawal hash returned by `parse_withdrawal_hash(init_wd_txn_hash)`.

        external_prover_address : ChecksumAddress
            Address of the contract (or the zero address) that submitted
            the proof.  Use the zero address (`0x000...000`) when the proof
            was submitted directly by an EOA.

        Returns
        -------
        ProvenWithdrawalResponse
        """
        portal = self._get_l1_contract(OP_STACK_ETHEREUM.OPTIMISM_PORTAL)

        proven_withdrawal = portal.functions.provenWithdrawals(
            withdrawal_hash, external_prover_address
        ).call()

        response: ProvenWithdrawalResponse = {
            "fault_dispute_game_address": to_checksum_address(proven_withdrawal[0]),
            "timestamp": proven_withdrawal[1],
        }

        return response

    def is_withdrawal_enabled(
        self,
        withdrawal_hash: HexBytes,
        external_prover_address: ChecksumAddress,
    ) -> bool:
        """
        Check whether a proven withdrawal can **now** be finalized on L1.
        Python implementation of `checkWithdrawal` function in Optimism Portal2
        contract.

        Parameters
        ----------
        withdrawal_hash : HexBytes
            32-byte withdrawal hash returned by `parse_withdrawal_hash(init_wd_txn_hash)`.

        external_prover_address : ChecksumAddress
            Address of the contract (or the zero address) that originally
            submitted the proof.

        Returns
        -------
        bool
        """
        portal = self._get_l1_contract(OP_STACK_ETHEREUM.OPTIMISM_PORTAL)

        withdrawal_info = self.get_proven_withdrawal_info(
            withdrawal_hash, external_prover_address
        )

        dispute_game_address = withdrawal_info["fault_dispute_game_address"]
        timestamp = withdrawal_info["timestamp"]

        if timestamp == 0:
            raise OPPortalUnproven(
                f"Timestamp is {timestamp} for the provided {withdrawal_hash.to_0x_hex()}"
            )

        dispute_game_contract = self.l1_provider.eth.contract(
            dispute_game_address, abi=get_abi(ABI_FAULT_DISPUTE_GAME)
        )
        dispute_created_timestamp = dispute_game_contract.functions.createdAt().call()

        proof_maturity_delay_seconds = (
            portal.functions.proofMaturityDelaySeconds().call()
        )

        latest_block = self.l1_provider.eth.get_block("latest")

        anchor_state_registry_contract = self._get_l1_contract(
            OP_STACK_ETHEREUM.ANCHOR_STATE_REGISTRY
        )

        is_game_claim_valid = anchor_state_registry_contract.functions.isGameClaimValid(
            dispute_game_address
        )

        if timestamp <= dispute_created_timestamp:
            raise OPPortalInvalidProofTimstamp(
                f"Proof Timstamp:{timestamp} > asscociated Dispute Game Timstamp: {dispute_created_timestamp}"
            )

        if latest_block is None:
            raise ValueError("Can't fetch latest block")

        latest_block_timestamp = latest_block.get("timestamp")

        if latest_block_timestamp is None:
            raise ValueError("Can't fetch timestamp for latest block")

        if latest_block_timestamp - timestamp <= proof_maturity_delay_seconds:
            raise OPPortalProofNotOldEnough(
                f"The deadline hasn't reached yet. Check again after timestamp: {timestamp + proof_maturity_delay_seconds}"
            )

        if not is_game_claim_valid:
            raise OPPortalInvalidRootClaim(
                "The root claim initially submitted has been deemed invalid"
            )

        return True

    def is_finalized_withdrawal(self, withdrawal_hash: HexBytes) -> bool:
        """
        Check whether a withdrawal has already been finalized on L1.
        In simpler words, this method checks if the user has already completed the
        whole withdrawal process.


        Parameters
        ----------
        withdrawal_hash : HexBytes
            32-byte withdrawal hash returned by `parse_withdrawal_hash(init_wd_txn_hash)`.

        Returns
        -------
        bool
        """
        portal = self._get_l1_contract(OP_STACK_ETHEREUM.OPTIMISM_PORTAL)

        return portal.functions.finalizedWithdrawals(withdrawal_hash).call()
