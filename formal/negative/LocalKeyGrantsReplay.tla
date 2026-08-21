------------------------- MODULE LocalKeyGrantsReplay -------------------------
\* EffectAmbiguity with one extra edge: a locally minted identifier treated as
\* grounds for replay.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* "A locally generated identifier does not make a target idempotent." The
\* caller controls the key; the target decides whether it means anything. This
\* edge is what a system does when it confuses having sent a key with the key
\* being honoured, and it is invisible in review because the code reads exactly
\* like the correct version with one more disjunct.
EXTENDS EffectAmbiguity

BrokenNext ==
    \/ Next
    \/ /\ replay = Blocked
       /\ LocalIdentifierMinted
       /\ replay' = Allowed
       /\ delivery' = NotIssued
       /\ grants' = grants + 1
       /\ UNCHANGED <<outcome, resolution, overlap, receiptBound,
                      targetObserved, reconciled, compensated, effects>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
