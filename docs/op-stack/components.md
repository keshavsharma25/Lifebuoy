# Components of OP-Stack

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

## Sequencer

A sequencer in OP Stack rollups is tasked with a responsibility to *INCLUDE* and
*ORDER* the submitted transactions by users directly to the sequencer or relayed
via other replica nodes.

This component of the OP-Stack requires user's trust. Except

## Batcher


## Proposer


## Challenger


