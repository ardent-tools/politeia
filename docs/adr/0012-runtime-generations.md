# ADR: Complete immutable runtime generations

## Status
Accepted for starter architecture.

## Decision
Release, sign, activate, and rollback the whole semantic runtime generation rather than binary-only artifacts.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
- **Refined by [ADR 0016](0016-derived-specialization.md)**, which names the complete
  specialization input set. `RuntimeGeneration` as shipped
  (`crates/politeia-core/src/generation.rs`) implements 0016's fuller axis set as the only
  representation — there is no simpler 0012-shaped type alongside it. Read 0016 before
  reasoning about generation inputs from this ADR alone.
