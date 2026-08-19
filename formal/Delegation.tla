----------------------------- MODULE Delegation -----------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS Principals, Actions, Resources, Effects

VARIABLES grants

SubsetGrant(child, parent) ==
    child.actions \subseteq parent.actions /\
    child.resources \subseteq parent.resources /\
    child.effects \subseteq parent.effects

TypeOK == grants \in SUBSET [actions: SUBSET Actions,
                             resources: SUBSET Resources,
                             effects: SUBSET Effects]

Monotonic == \A c, p \in grants : (c.parent = p) => SubsetGrant(c, p)

=============================================================================
