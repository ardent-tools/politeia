--------------------------- MODULE EffectAmbiguity ---------------------------
EXTENDS Naturals

\* Ambiguous effect execution, per docs/11-FAILURE_SEMANTICS.md.
\*
\* The subject of this model is a single claim from that document: "Delivery
\* state, execution outcome, epistemic resolution, and replay disposition are
\* separate facts." Four variables, one per fact, and no transition that reads
\* one to conclude another.
\*
\* WHY four variables rather than one state machine: collapsing them is exactly
\* the defect. A single `state` that runs Issued -> Acknowledged -> Succeeded
\* encodes "acknowledged implies ran" in its edges, and no invariant written
\* over it can then contradict that -- the model would agree with itself while
\* the system it describes silently maps an acknowledgement onto an outcome.
\* Kept apart, the mapping has to be written as a transition, and a transition
\* is something an invariant can refuse.

\* How far a message got. None of these say anything about the effect.
CONSTANTS NotIssued, Issued, Transferred, Acknowledged

\* What the effect did, once something established it.
CONSTANTS NoOutcome, Ran, DidNotRun

\* Whether the system knows which of those holds.
CONSTANTS Unresolved, Resolved

\* Whether reissuing is permitted.
CONSTANTS Blocked, Allowed

\* How the effect subject derived from target, operation, resources and
\* normalized parameters compares against prior issued work. `Uncertain` is a
\* first-class answer, not a missing one: the document requires uncertain
\* equivalence to fail closed rather than mint a fresh local subject.
CONSTANTS NotTested, NoOverlap, Overlaps, Uncertain

\* Whether the exact target is known to enforce the declared idempotency
\* key, body, scope and window. A property of the target, evidenced by policy,
\* so it is a model parameter rather than something a transition may set.
CONSTANT TargetEnforcesIdempotency

\* Whether the caller minted a local identifier and called it an idempotency
\* key. Also a parameter, and deliberately never an input to any guard: "a
\* locally generated identifier does not make a target idempotent."
CONSTANT LocalIdentifierMinted

VARIABLES delivery, outcome, resolution, replay, overlap,
          receiptBound, targetObserved, reconciled, compensated, effects, grants

vars == <<delivery, outcome, resolution, replay, overlap,
          receiptBound, targetObserved, reconciled, compensated, effects, grants>>

\* The two things the document admits as establishing an outcome: a bound
\* receipt, or an authoritative observation of the target.
Established == receiptBound \/ targetObserved

MaxEffects == 2

Init ==
    /\ delivery = NotIssued
    /\ outcome = NoOutcome
    /\ resolution = Unresolved
    /\ replay = Blocked
    /\ overlap = NotTested
    /\ receiptBound = FALSE
    /\ targetObserved = FALSE
    /\ reconciled = FALSE
    /\ compensated = FALSE
    /\ effects = 0
    /\ grants = 0

\* --- Delivery. Each step moves the message and touches nothing else. ---

\* WHY issuing consumes the replay grant and resets the overlap test: both are
\* per-attempt facts. A grant that survived its reissue would authorise every
\* later one on grounds established for the first, and an overlap result
\* carried forward would answer a question about prior work with the answer to
\* an older question.
Issue ==
    /\ delivery = NotIssued
    /\ effects < MaxEffects
    /\ (effects = 0 \/ replay = Allowed)
    /\ delivery' = Issued
    /\ effects' = effects + 1
    /\ replay' = Blocked
    /\ overlap' = NotTested
    /\ UNCHANGED <<outcome, resolution, receiptBound, targetObserved,
                   reconciled, compensated, grants>>

Transfer ==
    /\ delivery = Issued
    /\ delivery' = Transferred
    /\ UNCHANGED <<outcome, resolution, replay, overlap, receiptBound,
                   targetObserved, reconciled, compensated, effects, grants>>

Acknowledge ==
    /\ delivery = Transferred
    /\ delivery' = Acknowledged
    /\ UNCHANGED <<outcome, resolution, replay, overlap, receiptBound,
                   targetObserved, reconciled, compensated, effects, grants>>

\* --- Establishing an outcome. Only these may write `outcome`. ---

\* WHY every establisher is guarded on `resolution = Unresolved`: without it a
\* later source may overwrite an outcome an earlier one established, and the
\* two disagreeing is not a resolution -- it is a finding. TLC found this
\* during authoring, on a trace where an authoritative observation reported
\* `Ran`, a compensation ran against it, and a reconciliation then reported
\* `DidNotRun`, leaving a compensation standing behind an effect the model now
\* said never happened. `formal/negative/RevisedOutcome.tla` plants that edge
\* back so the guard cannot be removed silently.
BindReceipt ==
    /\ delivery \in {Transferred, Acknowledged}
    /\ resolution = Unresolved
    /\ ~receiptBound
    /\ receiptBound' = TRUE
    /\ outcome' \in {Ran, DidNotRun}
    /\ resolution' = Resolved
    /\ UNCHANGED <<delivery, replay, overlap, targetObserved,
                   reconciled, compensated, effects, grants>>

ObserveTarget ==
    /\ delivery /= NotIssued
    /\ resolution = Unresolved
    /\ ~targetObserved
    /\ targetObserved' = TRUE
    /\ outcome' \in {Ran, DidNotRun}
    /\ resolution' = Resolved
    /\ UNCHANGED <<delivery, replay, overlap, receiptBound,
                   reconciled, compensated, effects, grants>>

\* An authorized read-only reconciliation. It reads the target and records what
\* it finds; it may not produce an effect, which is what makes it available
\* while the outcome is unknown.
Reconcile ==
    /\ delivery /= NotIssued
    /\ resolution = Unresolved
    /\ ~reconciled
    /\ reconciled' = TRUE
    /\ outcome' \in {Ran, DidNotRun}
    /\ resolution' = Resolved
    /\ UNCHANGED <<delivery, replay, overlap, receiptBound,
                   targetObserved, compensated, effects, grants>>

\* An approved compensation. It runs against a known-executed effect, so it
\* requires resolution first rather than substituting for it.
Compensate ==
    /\ resolution = Resolved
    /\ outcome = Ran
    /\ ~compensated
    /\ compensated' = TRUE
    /\ UNCHANGED <<delivery, outcome, resolution, replay, overlap,
                   receiptBound, targetObserved, reconciled, effects, grants>>

\* --- Deriving the effect subject and testing overlap. ---

DeriveSubject ==
    /\ overlap = NotTested
    /\ delivery /= NotIssued
    /\ overlap' \in {NoOverlap, Overlaps, Uncertain}
    /\ UNCHANGED <<delivery, outcome, resolution, replay, receiptBound,
                   targetObserved, reconciled, compensated, effects, grants>>

\* --- Replay disposition. The one transition that may unblock a reissue. ---
\*
\* Its guard is the document's rule, written once: replay is allowed only when
\* the outcome is known, or the exact target is evidenced to enforce
\* idempotency, or an authorized reconciliation or compensation has run -- and
\* never while equivalence is uncertain. `LocalIdentifierMinted` appears
\* nowhere in it, which is the point.
AllowReplay ==
    /\ replay = Blocked
    /\ overlap \in {NoOverlap, Overlaps}
    /\ \/ resolution = Resolved
       \/ TargetEnforcesIdempotency
       \/ reconciled
       \/ compensated
    /\ replay' = Allowed
    /\ delivery' = NotIssued
    /\ grants' = grants + 1
    /\ UNCHANGED <<outcome, resolution, overlap, receiptBound,
                   targetObserved, reconciled, compensated, effects, grants>>

Next ==
    \/ Issue \/ Transfer \/ Acknowledge
    \/ BindReceipt \/ ObserveTarget
    \/ Reconcile \/ Compensate
    \/ DeriveSubject \/ AllowReplay

TypeOK ==
    /\ delivery \in {NotIssued, Issued, Transferred, Acknowledged}
    /\ outcome \in {NoOutcome, Ran, DidNotRun}
    /\ resolution \in {Unresolved, Resolved}
    /\ replay \in {Blocked, Allowed}
    /\ overlap \in {NotTested, NoOverlap, Overlaps, Uncertain}
    /\ receiptBound \in BOOLEAN
    /\ targetObserved \in BOOLEAN
    /\ reconciled \in BOOLEAN
    /\ compensated \in BOOLEAN
    /\ effects \in 0..MaxEffects
    /\ grants \in 0..MaxEffects

\* No outcome is recorded until a bound receipt, an authoritative observation,
\* or an authorized reconciliation established one.
\*
\* This is what refuses "acknowledged means it ran", which is the confusion the
\* document names first. Its contrapositive covers every delivery state at
\* once: with no evidence there is no outcome, whatever the transport reported.
\* `formal/negative/AcknowledgedMeansRan.tla` plants the acknowledgement case
\* specifically, since that is the one an implementation reaches for.
\*
\* WARNING to anyone adding a companion invariant that names one delivery state:
\* it would be implied by this one, so no reachable state could violate it while
\* this holds and no run could ever fail because of it. The fixture is where a
\* specific case belongs. `.github/workflows/ci.yml` refuses an invariant that
\* no fixture can make fire.
OutcomeRequiresEvidence ==
    (outcome /= NoOutcome) => (Established \/ reconciled)

\* An unresolved ambiguity is not a failure, and is not a not-executed. The
\* document forbids mapping it to either; here that is the same as forbidding
\* any outcome at all while unresolved.
\*
\* Independent of `OutcomeRequiresEvidence` rather than a corollary of it: a
\* system can hold evidence and still not have resolved what the evidence
\* means, and recording an outcome in that state is the defect this catches and
\* that one does not.
UnresolvedIsNotAnOutcome ==
    (resolution = Unresolved) => (outcome = NoOutcome)

\* Replay stays blocked until something in the document's list holds.
\*
\* `LocalIdentifierMinted` is absent from that list, which is the whole of "a
\* locally generated identifier does not make a target idempotent": the caller
\* controls the key and the target decides whether it means anything.
\* `formal/negative/LocalKeyGrantsReplay.tla` plants the disjunct that would
\* consult it, and this invariant is what refuses it.
\*
\* WARNING: an invariant restating that case under
\* `~TargetEnforcesIdempotency` says exactly what this one already says under
\* that hypothesis, and would be unfalsifiable beside it.
ReplayNeedsGrounds ==
    (replay = Allowed) =>
        (resolution = Resolved \/ TargetEnforcesIdempotency
                              \/ reconciled \/ compensated)

\* Uncertain equivalence fails closed. Distinct from the rule above: a system
\* could have a resolved outcome for one subject and still be unsure whether
\* the work in front of it is that subject.
UncertainEquivalenceBlocksReplay ==
    (overlap = Uncertain) => (replay = Blocked)

\* An overlap test that has not run is not an overlap test that came back
\* clear. The document makes the derivation and the test preconditions of
\* reissuing, so a grant standing before either happened is a grant resting on
\* nothing.
\*
\* TLC found this one too: with the guard reading `overlap /= Uncertain`, an
\* untested subject satisfied it, replay was granted, the reissue went out, and
\* the test came back `Uncertain` afterwards -- which is the whole failure,
\* arriving in the right order to be useless.
UntestedEquivalenceBlocksReplay ==
    (overlap = NotTested) => (replay = Blocked)

\* Every effect after the first was preceded by a grant that had grounds.
\*
\* WHY a counter rather than a read of `replay`: the grant is consumed by the
\* reissue it authorises, so by the time the second effect exists the
\* disposition is blocked again and a state-reading invariant sees only that.
\* Counting the grants makes the claim about the trace, which is where it lives.
\*
\* This is also what keeps reconciliation read-only. A reconciliation that
\* produced an effect would be a retry wearing another name -- available
\* exactly when retrying is forbidden, since its whole purpose is to run while
\* the outcome is unknown -- and it would raise the count without a grant
\* behind it.
EveryReissueHadAGrant ==
    effects <= grants + 1

\* Compensation runs against a known outcome rather than in place of knowing
\* one.
CompensationFollowsResolution ==
    compensated => (resolution = Resolved /\ outcome = Ran)

Spec == Init /\ [][Next]_vars

THEOREM Spec => []TypeOK
            /\ []OutcomeRequiresEvidence
            /\ []UnresolvedIsNotAnOutcome
            /\ []ReplayNeedsGrounds
            /\ []UncertainEquivalenceBlocksReplay
            /\ []UntestedEquivalenceBlocksReplay
            /\ []EveryReissueHadAGrant
            /\ []CompensationFollowsResolution

=============================================================================
