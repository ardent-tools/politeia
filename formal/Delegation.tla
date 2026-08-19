----------------------------- MODULE Delegation -----------------------------
EXTENDS FiniteSets

CONSTANTS Actions, Resources, Effects

VARIABLE grants

\* The root grant carries full authority and no parent. Every later grant is
\* issued by narrowing an existing one.
NoParent == "none"

Root == [parent |-> NoParent, actions |-> Actions, resources |-> Resources, effects |-> Effects]

SubsetGrant(child, parent) ==
    /\ child.actions \subseteq parent.actions
    /\ child.resources \subseteq parent.resources
    /\ child.effects \subseteq parent.effects

Init == grants = {Root}

\* Delegation: issue a grant that narrows an existing grant on every axis.
\* Sets of records are finite here, so identical re-issue is excluded to keep
\* the state space honest rather than to change the semantics.
Next ==
    \E p \in grants :
        \E a \in SUBSET Actions, r \in SUBSET Resources, e \in SUBSET Effects :
            LET child == [parent |-> p, actions |-> a, resources |-> r, effects |-> e] IN
            /\ SubsetGrant(child, p)
            /\ child \notin grants
            /\ grants' = grants \cup {child}

TypeOK ==
    \A g \in grants :
        /\ g.actions \subseteq Actions
        /\ g.resources \subseteq Resources
        /\ g.effects \subseteq Effects

\* The constitution's monotonic-delegation law: no grant in the system exceeds
\* its parent on any axis.
Monotonic ==
    \A c \in grants :
        (c.parent # NoParent) => SubsetGrant(c, c.parent)

Spec == Init /\ [][Next]_grants

THEOREM Spec => []TypeOK /\ []Monotonic

=============================================================================
