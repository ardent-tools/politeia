# First vertical slice

Build exactly one end-to-end path before adding breadth.

## Scenario

A reconnaissance agent with a bounded read-only grant discovers one source system, produces observations, proposes one institutional fact, obtains human approval, then executes one authorized semantic read operation whose result is independently verified and attested.

## Required path

1. bounded reconnaissance delegation;
2. read-only adapter;
3. observation provenance;
4. candidate claim with confidence;
5. contradiction handling and missed axes;
6. constitutional approval;
7. operation specification;
8. preflight;
9. normalized policy decision;
10. dispatcher-issued lease;
11. effect port;
12. evidence journal;
13. independent verifier;
14. attestation bound to exact subject + policy + runtime + adapter + delegation;
15. transition journal.

## Acceptance

- no frontend bypass exists;
- nested operations re-authorize;
- child delegation is a subset on every axis;
- expired/wrong-audience leases fail;
- attestation cannot be replayed for a different subject;
- contradictions remain visible until approved;
- maintenance identity cannot approve its own authority expansion;
- stale/downgraded protected policy fails closed.
