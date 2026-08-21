------------------------- MODULE UnattenuatedChild -------------------------
\* Delegation with one extra edge: a child admitted without narrowing.
\*
\* CI requires TLC to REJECT this module. A green run here is the failure.
\*
\* `Monotonic` is maintained by construction in the parent model -- `Next`
\* requires `SubsetGrant` before admitting anything, so no reachable state can
\* violate it there. That is a fine way to build a model and a poor reason to
\* trust an invariant: an invariant that holds because nothing can reach its
\* negation reports the same green whether or not it is watching anything.
\*
\* This edge admits a child that widens every axis at once, which is the state
\* the constitution's monotonic-delegation law forbids and the parent model
\* simply cannot construct.
EXTENDS Delegation

Widest == [parent      |-> Root,
           actions     |-> Actions,
           resources   |-> Resources,
           effects     |-> Effects,
           dataClasses |-> DataClasses,
           audience    |-> Audiences,
           expiresAt   |-> MaxExpiry,
           cap         |-> Cap(MaxCap)]

Unattenuated == [Widest EXCEPT !.parent = Narrow]

BrokenNext ==
    \/ Next
    \/ /\ Unattenuated \notin grants
       /\ Narrow \in grants
       /\ grants' = grants \cup {Unattenuated}
    \* Narrow is not otherwise reachable from Root in one step under the
    \* configured bounds, so the fixture seeds it. Seeding a legal grant is not
    \* the planted defect; admitting a child that widens on every axis is.
    \/ /\ Narrow \notin grants
       /\ grants' = grants \cup {Narrow}

BrokenSpec == Init /\ [][BrokenNext]_grants

=============================================================================
