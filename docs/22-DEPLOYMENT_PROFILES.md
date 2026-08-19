# Deployment profiles

Profiles change operational topology and assurance requirements, not semantic meaning.

## Local development
Single operator, in-memory or local PostgreSQL, development signing allowances, extensive diagnostics.

## Managed single-tenant
Dedicated control plane per client, authenticated principals, durable PostgreSQL, signed runtime generations, strict secrets/data policy.

## Enterprise high-assurance
Isolated adapter execution, stronger identity federation, external policy/runtime signing authorities, disaster recovery, separation of duties, formal assurance for selected invariants.

A profile may strengthen controls. It may not redefine core semantics.
