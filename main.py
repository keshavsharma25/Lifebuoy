from typing import cast
from eth_account.signers.local import LocalAccount
from pprint import pprint
from web3 import Account
from chains.op_stack.op_sepolia import OP_Sepolia
from dotenv import load_dotenv
import os


def main():
    load_dotenv()

    op_sepolia = OP_Sepolia()

    pvt_key = os.getenv("PRIVATE_KEY")

    if not pvt_key:
        raise ValueError("PRIVATE_KEY not set in .env...")

    account: LocalAccount = Account.from_key(pvt_key)

    contract = op_sepolia.get_l1_contract()

    address = account.address
    value = op_sepolia.l1p.to_wei(0.01, "ether")
    gas_limit = op_sepolia.l2p.to_wei(0.01, "gwei")
    is_creation = False
    data = op_sepolia.l1p.to_bytes(b"")

    txn = contract.functions.depositTransaction(
        address,
        value,
        gas_limit,
        is_creation,
        data,
    )

    estimated_gas = op_sepolia.l1p.eth.estimate_gas(
        {
            "from": account.address,
            "to": contract.address,
            "value": value,
            "data": txn._encode_transaction_data(),
        }
    )

    txn_payload = txn.build_transaction(
        {
            "from": account.address,
            "chainId": op_sepolia.l1p.eth.chain_id,
            "gas": estimated_gas,
            "value": value,
            "nonce": op_sepolia.l1p.eth.get_transaction_count(account.address),
        }
    )

    pprint(txn_payload)

    print("=" * 20)

    print("Sending Txn....")

    print("=" * 20)

    signed_txn = account.sign_transaction(cast(dict, txn_payload))
    txn_hash = op_sepolia.l1p.eth.send_raw_transaction(signed_txn.raw_transaction)

    print("=" * 20)
    print(f"Txn hash: {txn_hash.hex()}")
    print("=" * 20)

    receipt = op_sepolia.l1p.eth.wait_for_transaction_receipt(txn_hash)

    if receipt["status"] == 1:
        print("✅ Transaction successful!")
        print(f"Block: {receipt['blockNumber']}")
        print(f"Gas used: {receipt['gasUsed']}")

        print("=" * 20)
    else:
        print("❌ Transaction failed!")

        return receipt


if __name__ == "__main__":
    main()
