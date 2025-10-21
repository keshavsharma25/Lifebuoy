from typing import cast
from eth_account.signers.local import LocalAccount
from eth_typing import BlockNumber, ChecksumAddress
from eth_utils.conversions import to_hex
from hexbytes import HexBytes
from web3 import Web3
import json

from web3.types import TxParams
from utils.chain import estimate_l2_gas, get_account
from utils.config import ChainName
from utils.providers import get_web3


def initiate_withdrawal(l2p: Web3, account: LocalAccount, mp_contract: ChecksumAddress):
    with open("chains/op_stack/ABI/L2ToL1MessagePasser.json", "r") as data:
        abi = json.load(data)

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


def find_dispute_game_for_withdrawal(l1p: Web3, withdrawal_block: BlockNumber):
    pass


def prove_withdraw():
    pass


def main():
    # 1. Get withdrawal receipt on L2 ✅
    # 2. Parse MessagePassed event → Get WithdrawalTransaction fields ✅
    # 3. Calculate withdrawal hash from event data ✅
    # 4. Find dispute game covering your L2 block → Get disputeGameIndex
    # 5. Get dispute game's L2 block number from extraData
    # 6. Call eth_getProof on L2 for L2ToL1MessagePasser
    # 7. Extract storageHash → messagePasserStorageRoot
    # 8. Extract storageProof → withdrawalProof
    # 9. Get L2 block hash at dispute game block → latestBlockhash
    # 10. Get stateRoot from dispute game's rootClaim
    # 11. Assemble all parameters and call proveWithdrawalTransaction()

    l1p = get_web3(ChainName.ETH_SEPOLIA)
    l2p = get_web3(ChainName.OP_SEPOLIA)

    account = get_account()

    L2_TO_L1_MESSAGE_PASSER_CONTRACT_ADDRESS = l2p.to_checksum_address(
        "0x4200000000000000000000000000000000000016"
    )

    DISPUTE_GAME_FACTORY_CONTRACT_ADDRESS = l1p.to_checksum_address(
        "0x05F9613aDB30026FFd634f38e5C4dFd30a197Fa1"
    )

    # STEP 1
    # withdraw_receipt = initiate_withdrawal(
    #     l2p, account, L2_TO_L1_MESSAGE_PASSER_CONTRACT_ADDRESS
    # )

    withdraw_receipt = l2p.eth.get_transaction_receipt(
        HexBytes("0x549a2f761009ad540674d23db0d205b3fbbc96f67f1b6146b41d603e82b2845f")
    )

    # withdraw_block = withdraw_receipt.get("blockNumber")

    with open("chains/op_stack/ABI/L2ToL1MessagePasser.json", "r") as data:
        abi = json.load(data)

    contract = l2p.eth.contract(
        L2_TO_L1_MESSAGE_PASSER_CONTRACT_ADDRESS,
        abi=abi,
    )

    decoded = contract.events.MessagePassed().process_receipt(withdraw_receipt)[0]

    withdrawal_hash = to_hex(decoded["args"]["withdrawalHash"])


if __name__ == "__main__":
    main()
