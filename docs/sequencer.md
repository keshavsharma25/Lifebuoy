# Sequencers: The Protagonist & The Antagonist

Sequencers are notoriously accused of doing the bad things behind the back of users
with no way to verify their honesty. They are often seen being cursed left right
and center even when everything is hunky dory in the rollup
land (NOT - stage 2 wen?).

Primary reason being, sequencers introduce a lot of trust issues with them.
And trust & decentralization are often the far end pieces in a spectrum.
The sheer possibility of someone telling you - "Trust me bro!" should ring
bells in your ear. Similarly, sequencers aren't criticized for their doings
because they haven't done anything suspicious but are yelled at due to just
some possibility of such mishap happening.

It is quite aspirational and easy to make promises. And Stage 2 seems to be one such promise.

The role of sequencer, in principle is to include transactions submitted by users and order them
based on the maximum MEV earned to distribute it back to the community either via governance or
grants. But the problem lies in the implementation.

---

rough work

All the services discussed in OP-Stack components are interdependent
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

The role of a sequencer roughly paints the picture of
different responsibilities a sequencer is required to fulfill.
A sequencer is considered single and centralized when its reponsibility is not
only limited to sequencing (i.e. inclusion & ordering) but also extends to
performing the role of batcher and proposer.

And to overcome this shortcoming of centralization, there is an option for users
to perform forced-inclusion. Via forced-inclusion or deposit transaction (in
OP-Stack), the users can override the sequencer by submitting the
same transaction info from L1 (Ethereum) contracts.
