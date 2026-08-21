---------------------- MODULE RevocationUnmakesTheEffect ----------------------
\* Authority with one extra edge: a revocation that erases what already ran.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* This is the appealing mistake, not the careless one. Withdrawing an
\* authority feels like it should leave no trace of what it permitted, and a
\* ledger that decrements on revoke reads as tidy. But the effect was external
\* and the world has already seen it; `docs/11-FAILURE_SEMANTICS.md` says
\* revocation blocks new work and does not disable what is already activated,
\* and `docs/02-CONSTITUTION.md` law 12 says corrections append rather than
\* rewrite.
EXTENDS Authority

BrokenNext ==
    \/ Next
    \/ /\ revokedAt = NeverRevoked
       /\ revokedAt' = clock
       /\ effects' = 0
       /\ innerEffects' = 0
       /\ UNCHANGED <<clock, outerLeased, innerLeased, innerExpiry,
                      latestEffectAt, latestInnerEffectAt, everExecuted>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
