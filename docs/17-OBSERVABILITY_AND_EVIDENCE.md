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
