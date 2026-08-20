# Persistence and provenance

Use a normalized authoritative state model plus immutable journals.

## Stores

- **State store:** normalized current institutional model.
- **Transition journal:** append-only record of accepted state transitions.
- **Evidence journal:** immutable evidence metadata and subject bindings.
- **Outbox:** transactional publication boundary for external notifications/integrations.

Do not require reconstruction of all operational state solely through event replay.

## Production authority

Initial production persistence target: PostgreSQL.

Production state, journals, evidence, credentials, and the institution workspace remain in the institution-controlled trust domain by default. The public product source owns general semantics; a private institution workspace owns that institution's facts, policies, adapters, tests, and generation inputs. Neither becomes a hidden copy of the other.

In-memory implementations exist for deterministic tests.

Do not promise multiple durable storage engines until the persistence contract and migration model are stable.

Every stored record is scoped to an exact institution and trust domain. Cross-institution inputs fail closed.

## Every consequential journal entry binds

- actor/principal;
- delegation;
- semantic operation;
- before/after state identity where applicable;
- policy bundle;
- runtime generation;
- execution resource and routing decision when applicable;
- adapter identity;
- evidence references;
- timestamp;
- chain/digest metadata.
