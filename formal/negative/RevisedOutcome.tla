---------------------------- MODULE RevisedOutcome ----------------------------
\* EffectAmbiguity with one extra edge: a second source overwriting an
\* established outcome.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* The parent model carried this defect during authoring, before its
\* establishers were guarded on `resolution = Unresolved`. TLC produced the
\* trace: an authoritative observation reported that the effect ran, a
\* compensation ran against that, and a reconciliation then reported that it
\* had not -- leaving a compensation standing behind an effect the system now
\* said never happened. Two sources disagreeing is a finding, not a
\* resolution.
EXTENDS EffectAmbiguity

BrokenNext ==
    \/ Next
    \/ /\ resolution = Resolved
       /\ ~reconciled
       /\ reconciled' = TRUE
       /\ outcome' = DidNotRun
       /\ UNCHANGED <<delivery, resolution, replay, overlap, receiptBound,
                      targetObserved, compensated, effects, grants>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
