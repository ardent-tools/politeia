----------------------------- MODULE Delegation -----------------------------
EXTENDS FiniteSets, Naturals

CONSTANTS Actions, Resources, Effects

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

\* Exploration bound. The grant set only grows, so the reachable state space is
\* unbounded and TLC would not terminate. Capping its size makes the check
\* bounded rather than exhaustive -- a real distinction, and the reason the
\* configuration says so rather than letting a green run imply completeness.
\* A widening admitted only at depth five would not be found here.
GrantBound == Cardinality(grants) <= 4

Spec == Init /\ [][Next]_grants

THEOREM Spec => []TypeOK /\ []Monotonic

=============================================================================
