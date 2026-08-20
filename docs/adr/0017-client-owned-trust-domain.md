# ADR: Client-owned trust domain by default

## Status
Accepted for starter architecture.

## Decision
Institution data, credentials, inference authority, production systems, durable state, evidence, and the private workspace remain in a client-controlled environment by default.

## Consequences
- Commissioner hardware and accounts are not the default client data plane.
- Offboarding is principally authority revocation rather than reconstruction of hidden dependencies.
- Any commissioner-hosted client state is an explicit, separately governed exception.
- Reversal requires an explicit superseding ADR and migration strategy.
