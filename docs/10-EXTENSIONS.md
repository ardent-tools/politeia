# Extension architecture

Extensions are typed and untrusted by default.

## Classes

1. **Declarative domain packs** — preferred; knowledge, probes, mappings, policy templates, workflows.
2. **Trusted in-process components** — only for small audited kernel-adjacent functionality.
3. **Isolated native adapters** — external system bridges under OS/process isolation.
4. **Sandboxed executable components** — preferred boundary for third-party executable extensions; target WebAssembly Component Model/WASI capabilities.

## Manifest requirements

Every extension declares:

- stable identity/version;
- compatibility range;
- provided semantic operations;
- required capabilities;
- effects;
- resources;
- data classes handled;
- network/process/filesystem requirements;
- schemas;
- budgets;
- provenance/signature;
- trust class.

An extension manifest is a request for capabilities, not a grant.
