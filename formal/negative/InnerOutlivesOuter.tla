-------------------------- MODULE InnerOutlivesOuter --------------------------
\* Authority with one extra edge: a nested lease issued past its parent's term.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* Monotonic attenuation on the time axis. `Delegation.tla` checks that a child
\* cannot widen its parent on any width axis; expiry is the axis a lease
\* actually runs out of, and a nested grant that outlives its parent is a way
\* to keep working after the authority behind it has ended.
EXTENDS Authority

BrokenNext ==
    \/ Next
    \/ /\ outerLeased
       /\ ~innerLeased
       /\ OuterLive
       /\ \E bound \in 0..MaxTime :
           /\ bound > OuterExpiry
           /\ innerExpiry' = bound
       /\ innerLeased' = TRUE
       /\ UNCHANGED <<clock, revokedAt, outerLeased,
                      effects, latestEffectAt, innerEffects, latestInnerEffectAt,
                      everExecuted>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
