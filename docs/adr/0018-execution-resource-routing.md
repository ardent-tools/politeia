# ADR: Requirement-driven execution-resource routing

## Status
Accepted for starter architecture.

## Decision
Represent models, deterministic tools, humans, and services as execution resources selected by explicit requirements. Satisfy hard policy, data, capability, locality, budget, and assurance constraints before applying ordered soft preferences.

## Consequences
- No vendor or worker identity owns semantic authority.
- Routing decisions are provenance-bearing but do not grant authority.
- Deterministic tools can be required without silent model fallback.
- Capability calibration relies on independently admitted evidence rather than self-rating.
- Reversal requires an explicit superseding ADR and migration strategy.
