from typing import cast
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from web3 import Web3
from utils import get_web3
from utils.config import OP_STACK_SEPOLIA_CONTRACTS, LocalAcc
from utils.providers import ChainName
import json
from web3.types import TxParams, Wei
from utils.chain import estimate_l2_gas


class Base_Sepolia:
    def __init__(self) -> None:
        self.l1p = get_web3(ChainName.ETH_SEPOLIA)
        self.l2p = get_web3(ChainName.BASE_SEPOLIA)
        self.account: LocalAccount = LocalAcc().get_account()

    def get_abi(self):
        with open("chains/op_stack/ABI/OptimismPortal2.json", "r") as file:
            abi = json.load(file)
        return abi

    def get_l1_contract(self):
        return self.l1p.eth.contract(
            address=Web3.to_checksum_address(
                OP_STACK_SEPOLIA_CONTRACTS[ChainName.BASE_SEPOLIA]
            ),
            abi=self.get_abi(),
        )

    def deposit_eth(self, to: ChecksumAddress, value: float):
        is_creation = False
        data = b""

        return self.deposit_transaction(to, value, is_creation, data)

    def deposit_transaction(
        self,
        to: ChecksumAddress | None,
        value: float,
        is_creation: bool,
        data: bytes,
    ):
        contract = self.get_l1_contract()
        value = self.l1p.to_wei(value, "ether")

        gas_limit = estimate_l2_gas(self.l2p, to, self.account.address, value, data)

        txn = contract.functions.depositTransaction(
            to,
            value,
            gas_limit,
            is_creation,
            data,
        )

        estimated_gas = self.l1p.eth.estimate_gas(
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
                "gas": estimated_gas,
                "nonce": self.l1p.eth.get_transaction_count(self.account.address),
                "chainId": self.l1p.eth.chain_id,
            }
        )

        signed_txn = self.account.sign_transaction(cast(dict, txn_payload))
        txn_hash = self.l1p.eth.send_raw_transaction(signed_txn.raw_transaction)
        receipt = self.l1p.eth.wait_for_transaction_receipt(txn_hash)

        return cast(dict, receipt)

    def force_withdraw(self):
        pass
