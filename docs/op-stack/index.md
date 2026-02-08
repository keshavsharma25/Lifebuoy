# OP Stack

OP Stack is one of the most successful open source modular frameworks built
by Optimism to help scale Ethereum. After a lot of research and iterations
with OVM (Optimism Virtual Machine), the organization eventually created
the most adopted stack in the rollup ecosystem as of today.

[Announced](https://www.optimism.io/blog/introducing-the-op-stack) in 2022, Optimism Foundation's OP Mainnet transitioned
from OVM (EVM-in-EVM) implementation to the OP Stack via
[Bedrock upgrade](https://www.optimism.io/blog/introducing-bedrock) in June, 2023. This upgrade was one of the most
anticipated milestones for the foundation and a quintessential framework for
others to deploy their own customized rollups.

The vision of Superchain envisioned by Optimism with this rollup stack has
been quite successful. The likes of Base (Coinbase), Unichain (Uniswap),
Ink (Kraken Exchange), World Chain (world.org), and Soneium (Sony) all using
their stack.

OP Stack offers alot of features out of the box:

- Full EVM [Equivalence](https://medium.com/ethereum-optimism/introducing-evm-equivalence-5c2021deb306).
- Permissionless fault proof system via [Cannon](https://www.optimism.io/blog/permissionless-fault-proofs-and-stage-1-arrive-to-the-op-stack).
- Modular architecture for customizable rollups under the same umbrella known
as [Superchain](https://docs.optimism.io/superchain/introduction/superchain-explainer) (for composable interoperabitiliy).
- A [trust-minimized bridging and cross-chain messaging](https://specs.optimism.io/protocol/bridges.html) for secure and seamless
interaction between L1, L2, and interconnect chains in the Superchain.
- Optimal data compression to reduce gas costs while publishing L2 data on L1
via blobs post-Dencun in March, 2024.
- Low transaction fees.
- Liberty to [force-include](https://docs.optimism.io/op-stack/bridging/deposit-flow#denial-of-service-dos-prevention) transactions which overrides the sequencer in case
sequencer is down or is acting malicious.
- Introduction of [Flashblocks](https://writings.flashbots.net/introducing-rollup-boost) in Unichain provides fast confirmations
times (~250ms) and verifiable priority ordering (via TEEs) to internalize MEV
and help improve UX.

To know more about the stack and methods to perform forced inclusions and
withdrawals, read the following:

- [All important there is to know about OP Stack](./features.md)
- [Forced Inclusion: L1 -> L2 and bypassing sequencer](./deposit-transaction.md)
- [Enroute to Withdrawals](./withdrawals.md)

