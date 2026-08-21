----------------------- MODULE UnresolvedReadsAsNotRun -----------------------
\* EffectAmbiguity with one extra edge: an unresolved ambiguity recorded as
\* not-executed.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* The document forbids mapping an unresolved outcome to not-executed, failed,
\* or safe-to-retry. This plants the first of the three. It is the tempting one
\* because it looks conservative -- assuming nothing happened sounds like the
\* safe default, and it is the assumption under which a retry duplicates a
\* live effect.
\*
\* The reconciliation here really does run, so evidence exists and
\* `OutcomeRequiresEvidence` holds. What it omits is the resolution step: it
\* writes a conclusion while the system still stands as not having reached one.
\* That separation is why `UnresolvedIsNotAnOutcome` is not a corollary --
\* holding evidence and having resolved what it means are different states,
\* and this fixture is reachable only in the gap between them.
EXTENDS EffectAmbiguity

BrokenNext ==
    \/ Next
    \/ /\ delivery /= NotIssued
       /\ resolution = Unresolved
       /\ ~reconciled
       /\ reconciled' = TRUE
       /\ outcome' = DidNotRun
       /\ UNCHANGED <<delivery, resolution, replay, overlap, receiptBound,
                      targetObserved, compensated, effects, grants>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
