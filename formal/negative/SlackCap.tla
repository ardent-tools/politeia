------------------------------ MODULE SlackCap ------------------------------
\* A copy of Delegation whose cap rule grants one unit of slack to an already
\* capped parent.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* WHY it exists: this defect is invisible to every other check in the model.
\* `EveryAxisIsChecked` passes -- widening the narrow grant's cap from 0 to
\* MaxCap is still refused, because the slack is only one unit and only applies
\* above zero. `Monotonic` passes, for the usual reason that it is defined in
\* terms of the same rule that admits the children. `TypeOK` is untouched.
\*
\* What fails is transitivity, and only transitivity: a chain of single-unit
\* concessions, each individually admissible, arrives at a leaf that exceeds its
\* root. Cap(3) narrows Cap(2), Cap(2) narrows Cap(1), and Cap(3) does not
\* narrow Cap(1). Every issuance in that chain looked legal to the pairwise
\* check.
\*
\* This is the shape a "tolerance", "grace" or "rounding" allowance takes in a
\* real comparison, and it is why root-to-leaf attenuation is not a corollary of
\* pairwise attenuation unless the relation is transitive.
EXTENDS FiniteSets, Naturals

CONSTANTS Actions, Resources, Effects, DataClasses, Audiences, MaxExpiry, MaxCap

VARIABLE grants

NoParent == [root |-> TRUE]

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

\* The planted defect is the second disjunct: one unit of slack, allowed only
\* against a parent that already imposed a positive cap.
NarrowsCap(child, parent) ==
    IF ~parent.capped THEN TRUE
    ELSE IF ~child.capped THEN FALSE
    ELSE \/ child.value <= parent.value
         \/ (child.value = parent.value + 1 /\ parent.value > 0)

SubsetGrant(child, parent) ==
    /\ child.actions \subseteq parent.actions
    /\ child.resources \subseteq parent.resources
    /\ child.effects \subseteq parent.effects
    /\ child.dataClasses \subseteq parent.dataClasses
    /\ child.audience \subseteq parent.audience
    /\ child.expiresAt <= parent.expiresAt
    /\ NarrowsCap(child.cap, parent.cap)

Init == grants = {Root}

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

Monotonic ==
    \A c \in grants :
        (c.parent # NoParent) => SubsetGrant(c, c.parent)

Narrow == [parent      |-> NoParent,
           actions     |-> {},
           resources   |-> {},
           effects     |-> {},
           dataClasses |-> {},
           audience    |-> {},
           expiresAt   |-> 0,
           cap         |-> Cap(0)]

EveryAxisIsChecked ==
    /\ SubsetGrant(Narrow, Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.actions = Actions], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.resources = Resources], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.effects = Effects], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.dataClasses = DataClasses], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.audience = Audiences], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.expiresAt = MaxExpiry], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.cap = Cap(MaxCap)], Narrow)
    /\ ~SubsetGrant([Narrow EXCEPT !.cap = NoCap], Narrow)

NarrowsCapIsTransitive ==
    \A a, b, c \in Caps :
        (NarrowsCap(a, b) /\ NarrowsCap(b, c)) => NarrowsCap(a, c)

GrantBound == Cardinality(grants) <= 2

Spec == Init /\ [][Next]_grants

=============================================================================
