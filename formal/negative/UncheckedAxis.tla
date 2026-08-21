---------------------------- MODULE UncheckedAxis ----------------------------
\* A copy of Delegation with one axis silently dropped from the narrowing rule.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* WHY it exists: `Monotonic` cannot catch this. It is defined in terms of
\* `SubsetGrant`, and `Next` admits children using the same `SubsetGrant`, so
\* weakening the rule weakens the check and the guard in step -- more children
\* become admissible, and every one of them still satisfies the invariant that
\* was supposed to constrain them. The model goes green while its notion of
\* "narrowing" has quietly grown.
\*
\* `EveryAxisIsChecked` is what notices, because it asserts each axis against a
\* fixed pair rather than against whatever `Next` happens to admit. This module
\* is the demonstration that it does.
\*
\* The only difference from `Delegation` is the missing `dataClasses` conjunct
\* in `SubsetGrant`.
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

NarrowsCap(child, parent) ==
    IF ~parent.capped THEN TRUE
    ELSE IF ~child.capped THEN FALSE
    ELSE child.value <= parent.value

SubsetGrant(child, parent) ==
    /\ child.actions \subseteq parent.actions
    /\ child.resources \subseteq parent.resources
    /\ child.effects \subseteq parent.effects
    \* The planted defect: data classes are no longer compared, so a child may
    \* reach data its parent never could.
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

GrantBound == Cardinality(grants) <= 2

Spec == Init /\ [][Next]_grants

=============================================================================
