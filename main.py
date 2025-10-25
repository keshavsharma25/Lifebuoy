from typing import TypedDict, cast
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from eth_utils.conversions import to_bytes, to_hex
from hexbytes import HexBytes
from web3 import Web3
from eth_abi.abi import encode

from web3.eth import Contract
from web3.types import BlockData, MerkleProof, TxParams
from utils.chain import estimate_l2_gas, get_abi, get_account
from utils.config import (
    OP_STACK_L2_CONTRACTS,
    OP_STACK_SEPOLIA_CONTRACTS,
    ChainName,
)
from utils.providers import get_web3


class GameSearchResult(TypedDict):
    index: int
    metadata: bytes
    timestamp: int
    claim: bytes
    extra_data: bytes


class WithdrawalParams(TypedDict):
    nonce: int
    sender: ChecksumAddress
    target: ChecksumAddress
    value: int
    gas_limit: int
    data: bytes


class WithdrawalEvent(TypedDict):
    withdrawal_params: WithdrawalParams
    withdrawal_hash: bytes


class OutputRootProof(TypedDict):
    version: bytes
    state_root: bytes
    message_passer_storage_root: bytes
    latest_block_hash: bytes


def initiate_withdrawal(
    l2p: Web3, account: LocalAccount, mp_contract: ChecksumAddress, abi
):
    msg_passer = l2p.eth.contract(
        mp_contract,
        abi=abi,
    )

    mp_gas_limit = 21000
    mp_data = b""

    withdraw_value = l2p.to_wei("0.001", "ether")

    msg_passer_txn = msg_passer.functions.initiateWithdrawal(
        account.address,
        mp_gas_limit,
        mp_data,
    )

    gas_estimate = estimate_l2_gas(
        l2p,
        mp_contract,
        account.address,
        withdraw_value,
        mp_data,
    )

    txn_payload: TxParams = msg_passer_txn.build_transaction(
        {
            "from": account.address,
            "value": withdraw_value,
            "gas": gas_estimate,
            "nonce": l2p.eth.get_transaction_count(account.address),
            "chainId": l2p.eth.chain_id,
        }
    )

    signed_txn = account.sign_transaction(cast(dict, txn_payload))
    txn_hash = l2p.eth.send_raw_transaction(signed_txn.raw_transaction)

    print("-" * 75)
    print(f"Txn Receipt: {l2p.to_hex(txn_hash)}")
    print("-" * 75)

    withdraw_receipt = l2p.eth.wait_for_transaction_receipt(txn_hash)

    return withdraw_receipt


def parse_message_passed(
    l2p: Web3, msg_passer_contract: Contract, txn_hash: HexBytes
) -> WithdrawalEvent:
    withdraw_receipt = l2p.eth.get_transaction_receipt(txn_hash)

    if not withdraw_receipt:
        raise ValueError(
            f"Invalid receipt! Check if the txn_hash: {txn_hash} is correct."
        )

    events = msg_passer_contract.events.MessagePassed().process_receipt(
        withdraw_receipt
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

    withdrawal_hash = event.get("args").get("withdrawalHash")

    return {"withdrawal_params": parsed, "withdrawal_hash": withdrawal_hash}


def verify_withdrawal_hash(
    withdrawal_params: WithdrawalParams, withdrawal_hash: bytes, l1p: Web3
) -> bool:
    # compute withdrawal hash from withdrawal types & params
    computed_hash = to_hex(
        l1p.keccak(
            encode(
                ["uint256", "address", "address", "uint256", "uint256", "bytes"],
                list(withdrawal_params.values()),
            )
        )
    )

    return to_hex(withdrawal_hash) == computed_hash


def get_latest_game_result(
    dispute_game_factory_contract: Contract,
    op_portal_contract: Contract,
    game_id: int | None = None,
) -> GameSearchResult:
    game_count = dispute_game_factory_contract.functions.gameCount().call()
    respected_game_type = op_portal_contract.functions.respectedGameType().call()

    if game_id is None:
        latest_games = dispute_game_factory_contract.functions.findLatestGames(
            respected_game_type,
            game_count - 1,
            1,
        ).call()
    else:
        latest_games = dispute_game_factory_contract.functions.findLatestGames(
            respected_game_type,
            game_id,
            1,
        ).call()

    if not latest_games or not len(latest_games) > 0:
        raise ValueError(
            f"`len(latest_games) = {len(latest_games)}. Check dispute game for a valid game_id."
        )

    latest_game = latest_games[0]

    game_result: GameSearchResult = {
        "index": latest_game[0],
        "metadata": latest_game[1],
        "timestamp": latest_game[2],
        "claim": latest_game[3],
        "extra_data": latest_game[4],
    }

    return game_result


def get_storage_slot(withdrawal_hash: bytes, slot_number: int, l1p: Web3) -> str:
    storage_slot = l1p.keccak(
        withdrawal_hash + slot_number.to_bytes(32, byteorder="big")
    )

    return storage_slot.hex()


def main():
    l1p = get_web3(ChainName.ETH_SEPOLIA)
    l2p = get_web3(ChainName.OP_SEPOLIA)

    account = get_account()

    #### L2ToL1MessagePasser Contract ####
    mp_contract_info = OP_STACK_L2_CONTRACTS[ChainName.OP_SEPOLIA][
        "L2_TO_L1_MESSAGE_PASSER"
    ]

    mp_contract = l2p.eth.contract(
        mp_contract_info.get("address"), abi=get_abi(mp_contract_info.get("ABI"))
    )

    #### DISPUTE GAME FACTORY CONTRACT ####
    dispute_game_factory_info = OP_STACK_SEPOLIA_CONTRACTS[ChainName.OP_SEPOLIA][
        "DISPUTE_GAME_FACTORY"
    ]

    dispute_game_factory = l1p.eth.contract(
        dispute_game_factory_info.get("address"),
        abi=get_abi(dispute_game_factory_info.get("ABI")),
    )

    #### OPTIMISM PORTAL CONTRACT ####
    op_portal_info = OP_STACK_SEPOLIA_CONTRACTS[ChainName.OP_SEPOLIA]["OPTIMISM_PORTAL"]

    op_portal = l1p.eth.contract(
        op_portal_info.get("address"), abi=get_abi(op_portal_info.get("ABI"))
    )

    # STEP 1

    # withdraw_receipt = initiate_withdrawal(
    #     l2p,
    #     account,
    #     mp_contract_info["address"],
    #     get_abi(mp_contract_info["ABI"]),
    # )

    # withdraw_receipt = l2p.eth.get_transaction_receipt(
    #     HexBytes("0x68b3bc91f380a7cbd1c83f6d8c129b293b05148865976964ca6649a65ec305c5")
    # )  # associated game is 55149

    txn_hash = HexBytes(
        "0x230e0cad37990c92bbd54332ae2ecd28a2c8ff9dbaef846871eff5628ad18b00"
    )

    withdraw_receipt = l2p.eth.get_transaction_receipt(txn_hash)

    withdrawal_block_number = withdraw_receipt.get("blockNumber")
    withdrawal_block_header = l2p.eth.get_block(withdrawal_block_number)

    # STEP_2

    parsed_event = parse_message_passed(
        l2p, mp_contract, withdraw_receipt["transactionHash"]
    )
    parsed_withdrawal_params = parsed_event.get("withdrawal_params")

    # STEP 3

    withdrawal_hash = parsed_event.get("withdrawal_hash")
    assert verify_withdrawal_hash(parsed_withdrawal_params, withdrawal_hash, l1p), (
        "`computed hash != withdrawal hash`. Verify if withdrawal params are correct."
    )

    # STEP 4

    game_result = get_latest_game_result(dispute_game_factory, op_portal)

    extra_data = game_result.get("extra_data")

    print(game_result.get("index"))
    print(extra_data.hex())

    print(extra_data[:32].hex())

    l2_game_block_number = int.from_bytes(extra_data[:32], "big")

    assert l2_game_block_number > withdrawal_block_number, (
        f"Game block `{l2_game_block_number}` must be > Withdrawal block `{withdrawal_block_number}`"
    )

    l2_game_header: BlockData = l2p.eth.get_block(l2_game_block_number)

    # encode and assert

    storage_slot = get_storage_slot(withdrawal_hash, 0, l1p)

    proof: MerkleProof = l2p.eth.get_proof(
        mp_contract_info["address"],
        [storage_slot],  # type: ignore[reportCallIssue]
        int(withdrawal_block_number),
    )

    if not proof:
        raise ValueError(f"get_proof returned type {type(proof)}")

    storage_proofs = proof.get("storageProof")

    if not storage_proofs or len(storage_proofs) == 0:
        raise ValueError("No storage proofs returned")

    storage_proof = storage_proofs[0]

    # proveWithdrawalTransaction params

    # Param1:`Withdrawal Txn` - parsed_withdrawal_txn
    withdrawal_txn_tuple = tuple(parsed_withdrawal_params.values())

    # Param2:`disputeGameIndex` - game_result["index"]
    dispute_game_index = game_result["index"]

    state_root = l2_game_header.get("stateRoot")
    storage_hash = proof.get("storageHash")

    withdrawals_root = withdrawal_block_header.get("withdrawalsRoot")
    if not withdrawals_root:
        raise ValueError("WithdrawalsRoot doesn't exists in `withdrawal_block_header`")

    assert storage_hash == withdrawals_root

    block_hash = l2_game_header.get("hash")

    if not state_root:
        raise ValueError("Error finding `stateRoot` in `BlockData`")

    if not block_hash:
        raise ValueError("Error finding `hash` in `BlockData`")

    # Param3: OutputRootProof
    output_root_proof = {
        "version": (0).to_bytes(32, byteorder="big"),
        "stateRoot": state_root.__bytes__(),
        "messagePasserStorageRoot": storage_hash.__bytes__(),
        "latestBlockhash": block_hash.__bytes__(),
    }

    output_root_proof_tuple = tuple(output_root_proof.values())

    # Param4: Withdrawal_Proof
    withdrawal_proof = [
        to_bytes(hexstr=node) if isinstance(node, str) else node
        for node in storage_proof["proof"]
    ]

    computed_root = l1p.keccak(
        encode(["bytes32", "bytes32", "bytes32", "bytes32"], output_root_proof_tuple)
    ).hex()
    root_claim = game_result["claim"].hex()

    print(f"Withdrawal block: {withdrawal_block_number}")
    print(f"Game block: {l2_game_block_number}")
    print(f"Calculated output root: {computed_root}")
    print(f"Game claim: {root_claim}")
    assert root_claim == computed_root, "Invalid root claim compared!!!"

    # <Function proveWithdrawalTransaction((uint256,address,address,uint256,uint256,bytes),uint256,(bytes32,bytes32,bytes32,bytes32),bytes[])>
    prove_withdrawal_transaction = op_portal.functions.proveWithdrawalTransaction(
        withdrawal_txn_tuple,
        dispute_game_index,
        output_root_proof_tuple,
        withdrawal_proof,
    )

    gas_estimate = prove_withdrawal_transaction.estimate_gas(
        {
            "from": account.address,
            "nonce": l1p.eth.get_transaction_count(account.address),
            "chainId": l1p.eth.chain_id,
        }
    )

    txn_payload = prove_withdrawal_transaction.build_transaction(
        {
            "from": account.address,
            "nonce": l1p.eth.get_transaction_count(account.address),
            "chainId": l1p.eth.chain_id,
            "gas": int(gas_estimate * 1.2),
        }
    )

    signed_txn = account.sign_transaction(cast(dict, txn_payload))
    txn_hash = l1p.eth.send_raw_transaction(signed_txn.raw_transaction)
    receipt = l1p.eth.wait_for_transaction_receipt(txn_hash)

    print(receipt)


if __name__ == "__main__":
    main()
