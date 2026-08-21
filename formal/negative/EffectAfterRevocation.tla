------------------------ MODULE EffectAfterRevocation ------------------------
\* Authority with one extra edge: an effect that ignores a withdrawal.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* The edge keeps the expiry guard, so the authority is still inside its term
\* and every deadline-shaped check passes. What it ignores is that the
\* authority was taken away in the meantime -- the case an implementation
\* misses when it treats expiry as the only way authority ends.
EXTENDS Authority

BrokenNext ==
    \/ Next
    \/ /\ outerLeased
       /\ clock < OuterExpiry
       /\ effects + innerEffects < MaxEffects
       /\ effects' = effects + 1
       /\ latestEffectAt' = clock
       /\ everExecuted' = TRUE
       /\ UNCHANGED <<clock, revokedAt, outerLeased, innerLeased, innerExpiry,
                      innerEffects, latestInnerEffectAt>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
