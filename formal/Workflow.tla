------------------------------ MODULE Workflow ------------------------------
EXTENDS Naturals

\* The protected-operation path, per docs/18-FIRST_VERTICAL_SLICE.md and the
\* dispatcher in politeia-runtime. An operation is authorized, its budget is
\* committed, a single-use lease is issued, and only then may an effect run.
\* Denial is a terminal outcome available before the lease exists.
CONSTANTS Proposed, Authorized, Reserved, Leased,
          Running, Candidate, Verified, Accepted, Denied

\* How many effect invocations the model will explore. Two is the smallest
\* number that can exhibit a second one, which is the whole question.
CONSTANT MaxAttempts

\* The intents an operation could be about, and the absence of one.
\*
\* WHY intents rather than booleans on the authorization steps: `docs/02-CONSTITUTION.md`
\* law 8 requires exact binding, and a boolean cannot express it. "A lease
\* existed" and "the lease issued for this intent was the one spent" are
\* different claims, and a model carrying only the first is satisfied by a
\* dispatcher that treats a lease as a permission bit.
\*
\* Two is the smallest set in which a mismatch exists at all. One would make
\* every substitution unrepresentable and `ExecutesUnderItsOwnGrant` true by
\* construction with nothing able to falsify it.
CONSTANTS Intents, NoIntent

\* Five history variables. Four record *which intent* each precondition was
\* satisfied for, rather than that it was satisfied at all; the fifth records
\* which intent the effect actually ran for.
\*
\* WHY history rather than reading `state`: "nothing executes without a
\* committed reservation" is a claim about the trace. Derived from `state`
\* alone it can only be re-read off whichever edges the model happens to have,
\* which makes each invariant restate the transition relation instead of
\* constraining it. With history, removing a step from the path fails a check --
\* and `formal/negative/` checks in exactly those removals.
VARIABLES state, intent, authorized, reserved, leased, denied, leaseSpent,
          effects, effectFor

vars == <<state, intent, authorized, reserved, leased, denied, leaseSpent,
          effects, effectFor>>

\* States in which an externally visible effect may have run.
Executing == {Running, Candidate, Verified, Accepted}

Init ==
    /\ state = Proposed
    \* One operation, about one intent. The other intent exists as a value a
    \* substitution can name, not as concurrent work: two operations racing is
    \* a different question and the model says so in formal/README.md.
    /\ intent \in Intents
    /\ authorized = NoIntent
    /\ reserved = NoIntent
    /\ leased = NoIntent
    /\ denied = FALSE
    /\ leaseSpent = FALSE
    /\ effects = 0
    /\ effectFor = NoIntent

Next ==
    \* Authorization, then a committed budget reservation, then a single-use
    \* lease. Each records itself.
    \/ /\ state = Proposed   /\ state' = Authorized
       /\ authorized' = intent
       /\ UNCHANGED <<intent, reserved, leased, denied, leaseSpent, effects, effectFor>>
    \/ /\ state = Authorized /\ state' = Reserved
       /\ authorized = intent
       /\ reserved' = intent
       /\ UNCHANGED <<intent, authorized, leased, denied, leaseSpent, effects, effectFor>>
    \/ /\ state = Reserved   /\ state' = Leased
       /\ reserved = intent
       /\ leased' = intent
       /\ UNCHANGED <<intent, authorized, reserved, denied, leaseSpent, effects, effectFor>>
    \* Execution and the evidence path that follows it.
    \/ /\ state = Leased     /\ state' = Running
       /\ ~leaseSpent
       /\ leased = intent
       /\ leaseSpent' = TRUE /\ effects' = effects + 1 /\ effectFor' = intent
       /\ UNCHANGED <<intent, authorized, reserved, leased, denied>>
    \* A retry re-presenting the same lease. It is admissible only while that
    \* lease is unspent, which -- since executing spends it -- means never after
    \* the first invocation. The edge exists so that the guard is something the
    \* model states and a fixture can remove, rather than an absence.
    \/ /\ state \in {Running, Candidate} /\ ~leaseSpent /\ effects < MaxAttempts
       /\ state' = Running
       /\ leased = intent
       /\ leaseSpent' = TRUE /\ effects' = effects + 1 /\ effectFor' = intent
       /\ UNCHANGED <<intent, authorized, reserved, leased, denied>>
    \/ /\ state = Running    /\ state' = Candidate
       /\ UNCHANGED <<intent, authorized, reserved, leased, denied, leaseSpent, effects, effectFor>>
    \/ /\ state = Candidate  /\ state' = Verified
       /\ UNCHANGED <<intent, authorized, reserved, leased, denied, leaseSpent, effects, effectFor>>
    \/ /\ state = Verified   /\ state' = Accepted
       /\ UNCHANGED <<intent, authorized, reserved, leased, denied, leaseSpent, effects, effectFor>>
    \* Denial is available until a lease exists, and is terminal.
    \/ /\ state \in {Proposed, Authorized, Reserved} /\ state' = Denied
       /\ denied' = TRUE
       /\ UNCHANGED <<intent, authorized, reserved, leased, leaseSpent, effects, effectFor>>

TypeOK ==
    /\ state \in {Proposed, Authorized, Reserved, Leased,
                  Running, Candidate, Verified, Accepted, Denied}
    /\ intent \in Intents
    /\ authorized \in Intents \cup {NoIntent}
    /\ reserved \in Intents \cup {NoIntent}
    /\ leased \in Intents \cup {NoIntent}
    /\ denied \in BOOLEAN
    /\ leaseSpent \in BOOLEAN
    /\ effects \in 0..MaxAttempts
    /\ effectFor \in Intents \cup {NoIntent}

\* Nothing executes without having been authorized first.
NeverExecutesUnauthorized == (state \in Executing) => (authorized /= NoIntent)

\* Nothing executes without a committed budget reservation. Distinct from
\* authorization: an operation may be permitted and still have no budget
\* committed to it, and spending in that state is the overdraft the reservation
\* exists to prevent.
NeverExecutesWithoutReservation == (state \in Executing) => (reserved /= NoIntent)

\* Nothing executes without an issued lease. Distinct again: authorization says
\* the operation may run, the reservation says it may spend, and the lease is
\* the single-use grant that a specific effect invocation consumes.
NeverExecutesWithoutLease == (state \in Executing) => (leased /= NoIntent)

\* A denied operation stays denied. Without this, a path that re-establishes a
\* reservation and lease could carry a refused operation into execution with
\* every other precondition satisfied.
DenialIsFinal == denied => (state = Denied)

\* An effect lease is single-use. However many times an intent is retried, at
\* most one effect invocation may follow from one lease.
\*
\* This is the property that makes a retry safe. Its absence is not a lost
\* update or a slow path -- it is the same externally visible effect happening
\* twice, which no later evidence can undo.
AtMostOneEffectPerLease == effects <= 1

\* Nothing runs an effect at all without a spent lease behind it. Separate from
\* the count: one asks whether an effect was permitted, the other whether it was
\* permitted more than once.
EffectsRequireASpentLease == (effects > 0) => leaseSpent

\* The effect ran under the grant issued for its own intent.
\*
\* Every invariant above asks whether *a* step happened. This is the only one
\* that asks whether it happened for this operation, and it is the model's
\* statement of `docs/02-CONSTITUTION.md` law 8. A dispatcher that treats a
\* lease as a permission bit rather than as a grant naming one intent satisfies
\* all four of the others and fails this one -- which is exactly what
\* `negative/CrossIntentLease.tla` demonstrates.
ExecutesUnderItsOwnGrant ==
    (effectFor /= NoIntent)
        => /\ authorized = effectFor
           /\ reserved = effectFor
           /\ leased = effectFor

Spec == Init /\ [][Next]_vars

THEOREM Spec => []TypeOK
            /\ []NeverExecutesUnauthorized
            /\ []NeverExecutesWithoutReservation
            /\ []NeverExecutesWithoutLease
            /\ []DenialIsFinal
            /\ []AtMostOneEffectPerLease
            /\ []EffectsRequireASpentLease
            /\ []ExecutesUnderItsOwnGrant

=============================================================================
