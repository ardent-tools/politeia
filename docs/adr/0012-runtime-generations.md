# ADR: Complete immutable runtime generations

## Status
Accepted for starter architecture.

## Decision
Release, sign, activate, and rollback the whole semantic runtime generation rather than binary-only artifacts.

## Consequences
- This decision is part of the greenfield architectural baseline.
- Implementations may change; semantic intent may not silently drift.
- Reversal requires an explicit superseding ADR and migration strategy.
