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
- A [trust-minimized bridging and cross-chain messaging](https://docs.optimism.io/op-stack/bridging/cross-domain)
for secure and seamless interaction between L1, L2, and interconnect chains in
the Superchain ecosystem.
- Optimal data compression to reduce gas costs while publishing L2 data on L1
via blobs post-Dencun in March, 2024.
- Low transaction fees.
- Liberty to [force-include](https://docs.optimism.io/op-stack/bridging/deposit-flow#denial-of-service-dos-prevention)
transactions which overrides the sequencer in case sequencer is down or is
acting malicious.
- And many more.

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

All services are interdependent to ensure liveness and security of a rollup.
Although, challengers are permissionless with the activation of fault proofs (Cannon)
since [Fjord upgrade](https://www.optimism.io/blog/permissionless-fault-proofs-and-stage-1-arrive-to-the-op-stack) (10 July, 2024), yet the other three actors are under the
umbrella of a single centralized sequencer. But, a single centralized sequencer
is not quite the answer to the ethos that the community envisions to pursue.

## Role of a sequencer in OP-Stack

Almost all chains in the Superchain ecosystem uses a single centralized sequencer
as of today; quite afar from theoretical significance of a decentralized
sequencer.

> ***Sequencer should not be trusted for anything more than including and ordering
submitted transaction.***
> — *Ed Felton in [Optimistic Rollups, CBER Forum](https://youtube.com/watch?v=c3eWG2v_wRw&t=249)*

Yet, the current system over relies on sequencers to almost every major role
that must be distributed roles to different actors who play their roles with
utmost honesty to further increase decentralization.

The [role of a sequencer](../sequencer.md) roughly paints the picture of
different responsibilities a sequencer is required to fulfill.
A sequencer is considered single and centralized when its reponsibility is not
only limited to sequencing (i.e. inclusion & ordering) but also extends to
performing the role of batcher and proposer.

And to overcome this shortcoming of centralization, there is an option for users
to perform forced-inclusion. Via forced-inclusion or deposit transaction (in
OP-Stack), the users can override the sequencer by submitting the
same transaction info from L1 (Ethereum) contracts.

To learn more about forced-inclusion in OP-Stack, checkout [Deposit transaction](./deposit-transaction.md)
and [withdrawals](./withdrawals.md).

## OP Stack Architecture Resources

For more details on OP Stack architecture, refer:

- [OP-Stack Components](https://docs.optimism.io/op-stack/protocol/components)
- [OP-Stack Specifications](https://specs.optimism.io/protocol/overview.html)
- [Protocol Berg: protolambda - Evolution of Optimistic Rollup proofs - YouTube](https://www.youtube.com/watch?v=nR17-46Rd7w)
- [Optimistic Rollups - YouTube](https://www.youtube.com/watch?v=kzC1AQ-O55Y)
- [Joshua Gutow: Optimism Bedrock: Upgraded optimistic rollups architecture - YouTube](https://www.youtube.com/watch?v=vXuRJgyISI0)
