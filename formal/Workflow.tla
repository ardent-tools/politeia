------------------------------ MODULE Workflow ------------------------------
EXTENDS Naturals, Sequences

CONSTANTS Proposed, Authorized, Running, Candidate, Verified, Accepted

VARIABLE state

Allowed ==
  state = Proposed \/ state = Authorized \/ state = Running \/
  state = Candidate \/ state = Verified \/ state = Accepted

Next ==
  \/ /\ state = Proposed /\ state' = Authorized
  \/ /\ state = Authorized /\ state' = Running
  \/ /\ state = Running /\ state' = Candidate
  \/ /\ state = Candidate /\ state' = Verified
  \/ /\ state = Verified /\ state' = Accepted

=============================================================================
