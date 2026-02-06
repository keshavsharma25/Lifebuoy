# Role of a sequencer in OP-Stack

Almost all chains in the Superchain ecosystem uses a single centralized sequencer
as of today; quite afar from theoretical significance of a decentralized
sequencer.


## Centralized Sequencer Curse

All the services discussed in [OP-Stack components](./components.md) are interdependent
to ensure liveness and security of a rollup. Although, challengers are
permissionless with the activation of fault proofs (Cannon) since
[Fjord upgrade](https://www.optimism.io/blog/permissionless-fault-proofs-and-stage-1-arrive-to-the-op-stack) (July 2024), the other three actors are under the same
umbrella of a single centralized sequencer. A single centralized sequencer is
not quite the answer to the ethos that the community envisions to pursue.

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

