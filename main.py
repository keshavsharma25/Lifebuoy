from web3 import Web3
import json
from chains.op_stack.op_sepolia import OP_Sepolia


def main():
    op_sepolia = OP_Sepolia()
    l2p = op_sepolia.l2p

    #### deposit ETH ####

    receipt = op_sepolia.deposit_eth(op_sepolia.account.address, 0.01)
    print(receipt)

    #### deposit transactions ####

    contract_address = Web3.to_checksum_address(
        "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"
    )

    addr_2 = Web3.to_checksum_address("0x15dbD2206F4aa38E7e6D11454270E00FB3568F1c")

    with open("tests/op_stack/mocks/usdc_op_sepolia.json", "r") as file:
        abi = json.load(file)

    contract = l2p.eth.contract(address=contract_address, abi=abi)

    calldata = contract.functions.transfer(addr_2, 1000000)._encode_transaction_data()

    receipt = op_sepolia.deposit_transaction(
        to=contract_address, value=0, is_creation=False, data=calldata
    )

    print(receipt)


if __name__ == "__main__":
    main()
