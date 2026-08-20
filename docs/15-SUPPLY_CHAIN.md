# Runtime generation and supply chain

A release is a complete immutable runtime generation, not merely a binary.

A generation includes:

- exact public source revision and digest;
- institution-workspace identity, snapshot, and digest;
- approved institutional model and commissioning record;
- executable(s);
- policy bundle;
- lifecycle profile and deployment topology;
- schemas;
- migrations;
- trusted adapters;
- domain packs;
- execution-resource registry, capability evidence, and routing policy;
- generated projections;
- specialization compiler/toolchain identity and configuration;
- compatibility metadata;
- SBOM;
- build provenance;
- signatures;
- update metadata;
- a machine-readable reproducibility or allowed-nondeterminism declaration.

Activation is authenticated, atomic, rollback-capable, and resistant to policy/runtime mix-and-match.

Generation identity is derived from canonical inputs and excludes incidental build time. The manifest separates public core inputs from private institution inputs, binds every component digest and provenance record, and either reproduces the same bytes from the same inputs or identifies every intentionally nondeterministic field. Activation and rollback do not require commissioner- or vendor-owned infrastructure.

The design should mine TUF for update security, in-toto/SLSA for provenance, and Sigstore/DSSE for signing/attestation patterns without coupling the ontology to any one implementation.
