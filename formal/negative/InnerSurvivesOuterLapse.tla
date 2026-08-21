----------------------- MODULE InnerSurvivesOuterLapse -----------------------
\* Authority with one extra edge: a nested effect that checks only its own term.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* The inner lease was legally issued and has not itself expired, so a check
\* written against the inner authority alone passes. What it misses is that the
\* authority it was derived from is gone. This is the defect that makes a
\* nested grant into a way to outlive a revocation: take the sub-lease while
\* everything is live, and stop asking about the parent.
EXTENDS Authority

BrokenNext ==
    \/ Next
    \/ /\ innerLeased
       /\ clock < innerExpiry
       /\ effects + innerEffects < MaxEffects
       /\ innerEffects' = innerEffects + 1
       /\ latestInnerEffectAt' = clock
       /\ everExecuted' = TRUE
       /\ UNCHANGED <<clock, revokedAt, outerLeased, innerLeased, innerExpiry,
                      effects, latestEffectAt>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
