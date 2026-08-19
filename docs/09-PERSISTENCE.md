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

In-memory implementations exist for deterministic tests.

Do not promise multiple durable storage engines until the persistence contract and migration model are stable.

## Every consequential journal entry binds

- actor/principal;
- delegation;
- semantic operation;
- before/after state identity where applicable;
- policy bundle;
- runtime generation;
- adapter identity;
- evidence references;
- timestamp;
- chain/digest metadata.
