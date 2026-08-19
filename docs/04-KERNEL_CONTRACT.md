# Kernel contract

The semantic kernel is the trusted computing base for institutional work.

## Kernel responsibilities

- canonical typed identities and digests;
- principal and delegation semantics;
- multidimensional attenuation;
- operation specifications;
- effect declarations and data classifications;
- policy-decision normalization;
- complete mediation through the authorized dispatcher;
- unforgeable short-lived effect leases;
- transition and evidence journal contracts;
- exact attestation subject binding;
- lifecycle transition validity;
- semantic protocol version negotiation.

## Kernel non-responsibilities

The kernel does not own model sessions, provider routing, Git, ticketing, warehouses, messaging, user interfaces, generic workflow DSLs, or client-specific domain models.

## Protected operation path

`intent → operation resolution → principal/delegation validation → policy decision → budget reservation → authorization → effect lease → effect port → evidence → journal`

Every productive frontend uses this path.

Internal composition does not inherit blanket authority: each nested protected operation is independently resolved and authorized.

## Effect lease

An effect port must accept an unforgeable lease rather than a boolean.

A lease binds:

- principal;
- delegation chain;
- operation;
- resource set;
- effect set;
- data classes;
- budget;
- policy digest;
- runtime generation;
- adapter identity;
- audience;
- expiry;
- replay domain.

Lease construction is private to the dispatcher/authorization boundary.
