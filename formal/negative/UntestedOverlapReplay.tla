------------------------ MODULE UntestedOverlapReplay ------------------------
\* EffectAmbiguity with one extra edge: replay granted before the overlap test
\* has run.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* The parent model carried this defect during authoring, with a guard reading
\* `overlap /= Uncertain` -- which an untested subject satisfies. TLC produced
\* the trace: grant, reissue, and only then the overlap test coming back
\* uncertain. The fixture keeps that guard from drifting back.
EXTENDS EffectAmbiguity

BrokenNext ==
    \/ Next
    \/ /\ replay = Blocked
       /\ overlap = NotTested
       /\ resolution = Resolved
       /\ replay' = Allowed
       /\ delivery' = NotIssued
       /\ grants' = grants + 1
       /\ UNCHANGED <<outcome, resolution, overlap, receiptBound,
                      targetObserved, reconciled, compensated, effects>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
