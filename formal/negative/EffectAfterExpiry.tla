-------------------------- MODULE EffectAfterExpiry --------------------------
\* Authority with one extra edge: an effect that ignores the clock.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* The edge keeps every other guard, including the revocation one, so the lease
\* it runs under was validly issued and has not been withdrawn. It has simply
\* run out, and the only thing that could notice is a check made at effect time
\* rather than at issuance. This is the defect a system has when it decides
\* expiry once and trusts its own earlier answer.
EXTENDS Authority

BrokenNext ==
    \/ Next
    \/ /\ outerLeased
       /\ clock < revokedAt
       /\ effects + innerEffects < MaxEffects
       /\ effects' = effects + 1
       /\ latestEffectAt' = clock
       /\ everExecuted' = TRUE
       /\ UNCHANGED <<clock, revokedAt, outerLeased, innerLeased, innerExpiry,
                      innerEffects, latestInnerEffectAt>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
