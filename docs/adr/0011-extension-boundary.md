# ADR: Typed extension manifests and sandboxing

## Status
Accepted for starter architecture.

## Decision
Extensions declare required capabilities; executable third-party code is isolated/sandboxed by default.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
