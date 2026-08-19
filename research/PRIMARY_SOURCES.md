# Primary-source research register

The implementation team should validate designs against current primary sources before adopting details.

## Policy and authorization
- Cedar policy language and authorization model.
- Open Policy Agent/Rego and bundle/distribution model.
- Google Zanzibar paper for relationship-based authorization concepts.
- Biscuit authorization tokens for attenuation/delegation ideas.
- SPIFFE/SPIRE for workload identity.

## Typed configuration and constraints
- CUE language and constraint unification.
- JSON Schema 2020-12.

## Agent and transport protocols
- Model Context Protocol specification.
- Agent2Agent protocol specification.
- CloudEvents for event-envelope ideas where useful.

## Extensions / sandboxing
- WebAssembly Component Model.
- WASI capability model.

## Provenance and update security
- in-toto.
- DSSE.
- SLSA.
- Sigstore.
- The Update Framework (TUF).

## Findings and observability
- SARIF 2.1.
- OpenTelemetry semantic conventions and protocol.

## Formal methods / assurance
- TLA+.
- Alloy.
- NIST secure software / assurance guidance.

Rule: mine mechanisms and proven concepts. Do not let any external system dictate product ontology merely because it is mature.
