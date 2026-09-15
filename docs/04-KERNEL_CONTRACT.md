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
- canonical effect-subject identity and conservative overlap checks;
- transition and evidence journal contracts;
- exact attestation subject binding;
- lifecycle transition validity;
- semantic protocol version negotiation.

## Kernel non-responsibilities

The kernel does not own model sessions, execution-resource ranking, provider invocation, Git, ticketing, warehouses, messaging, user interfaces, generic workflow DSLs, or client-specific domain models.

Execution routing consumes kernel identities and policy contracts but remains outside the trusted semantic kernel. A routing decision must bind the selected resource and capability evidence into the operation authorization path; it cannot grant effects, widen delegation, or substitute a different resource after authorization.

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

For a productive direct effect, authorization binds an exact subject from the concrete
adapter/audience port target, full resolved operation, declared resource set, and authenticated
input identity. Admission also compares a separate conservative projection: effects through the
same target potentially overlap when their declared resource identities intersect, even when their
operation, parameters, key, generation, or other local identifiers differ. Empty or non-concrete
resource scope is unknown and overlaps every resource on that target. A read-only operation and an
attempt completed with a canonical outcome receipt do not block productive admission.

Resource comparison uses the exact canonical identities exposed by the installed port contract. An
adapter that needs path, object, or endpoint alias semantics must register canonical identities for
them; the runtime does not infer target-specific equivalence.
