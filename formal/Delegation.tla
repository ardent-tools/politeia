----------------------------- MODULE Delegation -----------------------------
EXTENDS FiniteSets, Naturals

\* Every width axis `Delegation::is_attenuation_of` compares in politeia-core.
\* The six budget caps are modelled as one, because they are six instances of
\* one rule rather than six rules: `ResourceBudget::is_attenuation_of` applies
\* the same `narrows` to each. What the model owes is that the rule is sound;
\* that every field actually uses it is a property of the implementation, and
\* the generated tests in `crates/politeia-core/src/attenuation_properties.rs`
\* are what establish it for all six.
CONSTANTS Actions, Resources, Effects, DataClasses, Audiences, MaxExpiry, MaxCap

VARIABLE grants

\* The root grant carries full authority and no parent. Every later grant is
\* issued by narrowing an existing one.
\*
\* WHY a record rather than a bare string: every `parent` field then holds one
\* kind of value, so `c.parent # NoParent` compares like with like. With a
\* string sentinel that comparison asks TLC to weigh a record against a string,
\* which it refuses -- and it refuses on the root grant, the first one it
\* examines, so the model aborts before checking any invariant at all.
NoParent == [root |-> TRUE]

\* An optional numeric cap. Both shapes are records for the same reason
\* `NoParent` is: a bare number beside a sentinel of another type makes every
\* comparison a type error waiting for the first state that reaches it.
NoCap == [capped |-> FALSE]
Cap(n) == [capped |-> TRUE, value |-> n]
Caps == {NoCap} \cup {Cap(n) : n \in 0..MaxCap}

Root == [parent      |-> NoParent,
         actions     |-> Actions,
         resources   |-> Resources,
         effects     |-> Effects,
         dataClasses |-> DataClasses,
         audience    |-> Audiences,
         expiresAt   |-> MaxExpiry,
         cap         |-> NoCap]

\* The optional-cap narrowing rule, mirroring `narrows` in
\* `ResourceBudget::is_attenuation_of`:
\*   parent uncapped               -> it imposed no limit, so anything narrows
\*   child uncapped, parent capped -> removing a cap exceeds it
\*   both capped                   -> the child must not exceed the parent
NarrowsCap(child, parent) ==
    IF ~parent.capped THEN TRUE
    ELSE IF ~child.capped THEN FALSE
    ELSE child.value <= parent.value

SubsetGrant(child, parent) ==
    /\ child.actions \subseteq parent.actions
    /\ child.resources \subseteq parent.resources
    /\ child.effects \subseteq parent.effects
    /\ child.dataClasses \subseteq parent.dataClasses
    /\ child.audience \subseteq parent.audience
    /\ child.expiresAt <= parent.expiresAt
    /\ NarrowsCap(child.cap, parent.cap)

Init == grants = {Root}

\* Delegation: issue a grant that narrows an existing grant on every axis.
\* Sets of records are finite here, so identical re-issue is excluded to keep
\* the state space honest rather than to change the semantics.
Next ==
    \E p \in grants :
        \E a \in SUBSET Actions,
           r \in SUBSET Resources,
           e \in SUBSET Effects,
           d \in SUBSET DataClasses,
           u \in SUBSET Audiences,
           x \in 0..MaxExpiry,
           c \in Caps :
            LET child == [parent      |-> p,
                          actions     |-> a,
                          resources   |-> r,
                          effects     |-> e,
                          dataClasses |-> d,
                          audience    |-> u,
                          expiresAt   |-> x,
                          cap         |-> c] IN
            /\ SubsetGrant(child, p)
            /\ child \notin grants
            /\ grants' = grants \cup {child}

TypeOK ==
    \A g \in grants :
        /\ g.actions \subseteq Actions
        /\ g.resources \subseteq Resources
        /\ g.effects \subseteq Effects
        /\ g.dataClasses \subseteq DataClasses
        /\ g.audience \subseteq Audiences
        /\ g.expiresAt \in 0..MaxExpiry
        /\ g.cap \in Caps

\* The constitution's monotonic-delegation law: no grant in the system exceeds
\* its parent on any axis.
Monotonic ==
    \A c \in grants :
        (c.parent # NoParent) => SubsetGrant(c, c.parent)

\* A grant narrowed to nothing on every axis, so widening any single axis from
\* it is unambiguously a widening.
Narrow == [parent      |-> NoParent,
           actions     |-> {},
           resources   |-> {},
           effects     |-> {},
           dataClasses |-> {},
           audience    |-> {},
           expiresAt   |-> 0,
           cap         |-> Cap(0)]

\* Every axis is load-bearing in `SubsetGrant`.
\*
\* WHY this is here rather than left to the reachability check above: `Next`
\* requires `SubsetGrant` before admitting any child, so `Monotonic` is
\* maintained by construction and would still hold if an axis were dropped from
\* `SubsetGrant` entirely -- the widened children simply become admissible and
\* nothing objects. This asserts each axis separately, so removing one fails a
\* check rather than quietly enlarging what the model calls a narrowing.
\*
\* It constrains `SubsetGrant` rather than the trace. It is checked as an
\* invariant because that is the mechanism TLC offers for evaluating it.
EveryAxisIsChecked ==
    /\ SubsetGrant(Narrow, Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.actions = Actions], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.resources = Resources], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.effects = Effects], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.dataClasses = DataClasses], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.audience = Audiences], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.expiresAt = MaxExpiry], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.cap = Cap(MaxCap)], Narrow)
    \* Removing a cap exceeds a capped parent just as raising one does, and
    \* travels through a different arm of `NarrowsCap`.
    /\ ~SubsetGrant([Narrow EXCEPT !.cap = NoCap], Narrow)

\* Root-to-leaf attenuation, obtained by transitivity rather than by exploring
\* deep chains.
\*
\* `Monotonic` relates each grant to its direct parent. The constitutional law
\* is stronger: a leaf must not exceed the *root*, however many issuances lie
\* between. That follows from pairwise narrowing exactly when the narrowing
\* relation is transitive, so this checks the relation instead of lengthening
\* the trace -- which is what makes the bound below affordable without giving
\* up the property.
\*
\* `SubsetGrant` conjoins `\subseteq`, `<=` and `NarrowsCap`. The first two are
\* transitive by construction. `NarrowsCap` is the one written here, so it is
\* the one checked -- exhaustively over the modelled cap domain, which is small
\* enough to enumerate completely.
NarrowsCapIsTransitive ==
    \A a, b, c \in Caps :
        (NarrowsCap(a, b) /\ NarrowsCap(b, c)) => NarrowsCap(a, c)

\* Exploration bound. The grant set only grows, so the reachable state space is
\* unbounded and TLC would not terminate.
\*
\* Two is not an arbitrary cut. `Monotonic` relates each grant to its direct
\* parent, so it is a pairwise property: a root and one child already exercise
\* every pair the invariant can form. Deeper chains multiply states -- three
\* costs five million generated states and three minutes -- without putting a
\* single new pair in front of the check.
\*
\* What the bound does cost is honest and worth stating: this is a bounded
\* check, not an exhaustive one, and an invariant that only failed on a
\* longer chain would not be found here.
GrantBound == Cardinality(grants) <= 2

Spec == Init /\ [][Next]_grants

THEOREM Spec => []TypeOK /\ []Monotonic /\ []EveryAxisIsChecked
            /\ []NarrowsCapIsTransitive

=============================================================================
