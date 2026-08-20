# ADR: Derived operational specialization

## Status
Accepted for starter architecture.

## Decision
Derive each operational deployment as an immutable, content-bound specialization of canonical source, the client-owned workspace, approved policy, lifecycle profile, deployment topology, and exact component inputs. Do not narrow operation by destructively mutating the only source authority.

## Consequences
- This refines ADR 0012 by naming the complete specialization inputs.
- Runtime generations are reproducible, inspectable, rollback-capable, and safe to recommission.
- Broad commissioning capabilities can remain absent from ordinary operation without deleting their source.
- Reversal requires an explicit superseding ADR and migration strategy.
