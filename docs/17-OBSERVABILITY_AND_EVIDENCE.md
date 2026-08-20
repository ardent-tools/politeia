# Observability versus evidence

Telemetry supports operations. Evidence supports claims.

OpenTelemetry-compatible traces, logs, and metrics are useful for diagnosis and correlation, but they are not automatically authoritative evidence.

Evidence additionally requires:

- exact subject identity;
- producer identity;
- collection method;
- policy/runtime context;
- provenance;
- durability class;
- independence class;
- verification status.

A policy binding may explicitly admit a telemetry record as evidence. There is no implicit promotion.

Commissioning records, routing decisions, generation manifests, reproducibility reports, data-boundary decisions, and handoff/revocation receipts must be typed evidence classes. Each record binds the exact identities it owns and the identity or digest of every adjacent receipt it relies on. Together, the authorization and evidence chain binds the applicable institution workspace, lifecycle profile, principal/delegation, policy, generation, execution resource, adapter, and subject identities; an individual record does not invent axes outside its semantic scope.

Worker-performance telemetry may support a capability profile only through an explicit evidence admission and independent evaluation. It never becomes authority and cannot satisfy an independence obligation for the worker that produced it.
