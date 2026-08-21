-------------------- MODULE CompensationWithoutResolution --------------------
\* EffectAmbiguity with one extra edge: compensating an effect nobody has
\* established ran.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* Compensation looks like the conservative response to not knowing -- undo it
\* just in case. It is an effect of its own, and running it against an effect
\* that never happened is the same class of externally visible mistake as the
\* duplicate it was meant to avert.
EXTENDS EffectAmbiguity

BrokenNext ==
    \/ Next
    \/ /\ resolution = Unresolved
       /\ ~compensated
       /\ compensated' = TRUE
       /\ UNCHANGED <<delivery, outcome, resolution, replay, overlap,
                      receiptBound, targetObserved, reconciled, effects, grants>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
