# Deposit Transaction

Every rollup (stack) have different archicture, and hence different ways to
self-sequence transactions. Similarly, in OP-Stack, forced inclusion is aliased
as **deposit transaction** where a user can submit transactions to L2 directly
via L1.

Below we discuss the technical details to the process of forced inclusion that
OP-Stack follows to include user's transaction submitted via L1.

## How forced inclusion works in OP-Stack?

Similar to other optimistic rollups, the OP Stack requires deploying smart
contracts on Ethereum (L1) to maintain the rollup's integrity at all times.

Deposit Transactions are new [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718) compatible transaction type on L2 with
the prefix `0x7E` (126 in decimal).

Transactions from L1 (Ethereum) -> L2 (e.g. OP Mainnet) are known as
*deposits*. These transactions are only allowed to self-sequence once the
respective L1 transaction achieves finality.

>**NOTE:** Rollups are cautioned to follow the finalized checkpoint of Ethereum due
to **reorganization (reorg) risks**. Any message via L1 -> L2 must be finalized on
L1 first.

Self-sequence, means to forcing L2 arbitrary transactions via L1, overriding
the sequencer role of including and ordering the transactions. And these behave
quite differently in presence and absence of a sequencer.

### In presence of a sequencer

A working sequencer cannot suppress deposit transaction that are sent via
`depositTransaction()` in `OptimismPortal2` contract deployed on L1.

Once the L1 transaction achieves finality, it has to be included into ***the first
block of the next L2 epoch*** (equal to the difference between two consecutive
L1 block i.e. 1 slot time = 12 seconds).

>**NOTE:** In general (OP Mainnet & Base), an L2 block is published every
2 seconds. Hence, there are 6 blocks in an L2 epoch on average.

These deposit transactions are executed first in the block before all the
transactions are sequenced by the sequencer. Even if the sequencer is malicious
or has ill intent, it will have zero significance to the deposit transactions.

### In absence of a sequencer

When sequencer fails to sequence blocks for a long period (hours or days).

## Lifecycle of a Deposit Transaction

=== "In Sequencer's presence"

    -

=== "In Sequencer's absence"

    - Bye

## Examples
