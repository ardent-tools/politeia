------------------------- MODULE AcknowledgedMeansRan -------------------------
\* EffectAmbiguity with one extra edge: acknowledgement writing an outcome.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* This is the defect docs/11-FAILURE_SEMANTICS.md names first, and it is the
\* one a single linear state machine makes by accident rather than by choice:
\* the transport reported success, so the effect ran. The transport reported
\* that it delivered a message.
EXTENDS EffectAmbiguity

BrokenNext ==
    \/ Next
    \/ /\ delivery = Acknowledged
       /\ outcome = NoOutcome
       /\ outcome' = Ran
       /\ resolution' = Resolved
       /\ UNCHANGED <<delivery, replay, overlap, receiptBound, targetObserved,
                      reconciled, compensated, effects, grants>>

BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
