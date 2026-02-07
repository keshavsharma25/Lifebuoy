# All there is to know about OP Stack

Although, this documentation primarily discusses the methods to perform
forced-inclusion across various rollups (stacks) and withdrawals in case
these get censored. However, it is also important for us to understand
a few important internals of OP-Stack to truly grasp the concept i.e.
forced-inclusion.

## Features

OP Stack offers alot of features out of the box:

- [Full EVM Equivalence](https://medium.com/ethereum-optimism/introducing-evm-equivalence-5c2021deb306)
- Permissionless fault proof system via [Cannon](https://www.optimism.io/blog/permissionless-fault-proofs-and-stage-1-arrive-to-the-op-stack)
- Modular architecture for customizable rollups under the same umbrella known
as [Superchain](https://docs.optimism.io/superchain/introduction/superchain-explainer) (for composable interoperabitiliy)
- A [trust-minimized bridging and cross-chain messaging](https://specs.optimism.io/protocol/bridges.html) for secure and seamless
interaction between L1, L2, and interconnect chains in the Superchain ecosystem.
- Optimal data compression to reduce gas costs while publishing L2 data on L1
via blobs post-Dencun in March, 2024.
- Low transaction fees.
- Liberty to [force-include](https://docs.optimism.io/op-stack/bridging/deposit-flow#denial-of-service-dos-prevention) transactions which overrides the sequencer in case
sequencer is down or is acting malicious.
- Recent [Flashblocks](https://writings.flashbots.net/introducing-rollup-boost) integration provides fast confirmations times (~250ms)
and verifiable priority ordering (via TEEs) to internalize MEV and help improve
UX.

## Components of OP-Stack

OP Stack features `op-node`, a specialized extension to Geth (Go-Ethereum) client
that implements the rollup specific logic. There are important network
participants who collectively leverages `op-node` to deliver critical services
and ensures chain liveness and security:

1. **Sequencer**
2. **Batcher**
3. **Proposer**
4. **Challenger**

Every participant is expected to perform their role with utmost honesty and
call out any mischevious behaviour executed by any other component. Sequencer's
role is to ensure persistant ordering, batcher's role is to commit the sequenced
data on L1 (Ethereum) ensuring data availability, proposer again fetches the
data available on L1 to compute the state root and publish it back to L1.
Challengers jobs is to contest any invalid state roots proposed by the proposer.

### Sequencer

A sequencer in OP Stack rollups is tasked with a responsibility to *INCLUDE* and
*ORDER* the submitted transactions by users directly to the sequencer or relayed
via other replica nodes.

This component of the OP-Stack requires user's trust.

Almost all chains in the Superchain ecosystem uses a single centralized sequencer
as of today; quite afar from theoretical significance of a decentralized
sequencer.

### Batcher


### Proposer


### Challenger

## What's wrong???
