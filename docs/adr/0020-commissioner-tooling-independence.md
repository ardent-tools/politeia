# ADR: Commissioner-tooling independence

## Status
Accepted for starter architecture.

## Decision
Politeia may integrate with or learn from commissioner-controlled or otherwise institution-external systems, but no such system is required for client commissioning, operation, handoff, or recommissioning.

## Consequences
- Product independence does not subsume or retire unrelated private tools.
- Private tools remain optional integrations rather than semantic authorities.
- Common components are extracted only when their ownership and contract are genuinely shared.
- Reversal requires an explicit superseding ADR and migration strategy.
