# Extension architecture

Extensions are typed and untrusted by default.

## Classes

1. **Declarative domain packs** — preferred; knowledge, probes, mappings, policy templates, workflows.
2. **Trusted in-process components** — only for small audited kernel-adjacent functionality.
3. **Isolated native adapters** — external system bridges under OS/process isolation.
4. **Sandboxed executable components** — preferred boundary for third-party executable extensions; target WebAssembly Component Model/WASI capabilities.

Model, harness, provider, tool, and service bridges are execution-resource adapters. They translate typed requests to an external runtime; they do not own routing policy, capability truth, or semantic authority.

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
- trust class;
- execution trust domain and locality;
- every data class and inference/egress sink the adapter may expose.

An extension manifest is a request for capabilities, not a grant.
