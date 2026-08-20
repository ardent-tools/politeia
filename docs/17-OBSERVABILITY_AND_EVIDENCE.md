# Observability versus evidence

Telemetry supports operations. Evidence supports claims.

OpenTelemetry-compatible traces, logs, and metrics are useful for diagnosis and correlation, but they are not automatically authoritative evidence.

Evidence requires:

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

An `ExecutionReceipt` is evidence about target-side execution, never a retroactive authority
grant. It binds the exact envelope admission, envelope/effect-subject/derived-intent identities,
local lease/reservation, executor/resource, target environment, outcome evidence, and applicable
policy/runtime identities. Receipt absence alone leaves the execution assessment unresolved; an
admitted authoritative target observation may resolve it, but delivery telemetry cannot collapse
it to not-executed.

An `ActivationProof` and `ControlResult` bind the exact control version, real mediation path,
subject/population identity, observed coverage, known-good control, planted violation, and retained
evidence. Green telemetry without those bindings does not establish an enforced control.

Corrections, supersessions, and assessment events are typed evidence classes where historical
interpretation matters. They preserve the original attested subject. A `CurrentAssessment` is a
reproducible view over those admitted records and the criterion version; the projection is neither
new evidence nor a second authority.
