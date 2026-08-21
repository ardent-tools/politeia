------------------------ MODULE UncertainOverlapReplay ------------------------
\* EffectAmbiguity with one extra edge: replay granted while equivalence is
\* uncertain.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* Distinct from the untested case: here the test ran and returned that it
\* could not tell. The document requires that to fail closed rather than mint a
\* fresh local subject, which is the move that turns "I am not sure this is the
\* same work" into "this is different work".
EXTENDS EffectAmbiguity

BrokenNext ==
    \/ Next
    \/ /\ replay = Blocked
       /\ overlap = Uncertain
       /\ resolution = Resolved
       /\ replay' = Allowed
       /\ delivery' = NotIssued
       /\ grants' = grants + 1
       /\ UNCHANGED <<outcome, resolution, overlap, receiptBound,
                      targetObserved, reconciled, compensated, effects>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
