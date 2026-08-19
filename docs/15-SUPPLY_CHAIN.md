# Runtime generation and supply chain

A release is a complete immutable runtime generation, not merely a binary.

A generation includes:

- executable(s);
- policy bundle;
- schemas;
- migrations;
- trusted adapters;
- domain packs;
- generated projections;
- compatibility metadata;
- SBOM;
- build provenance;
- signatures;
- update metadata.

Activation is authenticated, atomic, rollback-capable, and resistant to policy/runtime mix-and-match.

The design should mine TUF for update security, in-toto/SLSA for provenance, and Sigstore/DSSE for signing/attestation patterns without coupling the ontology to any one implementation.
