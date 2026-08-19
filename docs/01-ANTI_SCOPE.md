# Anti-scope

This product is not, by default:

- an agent harness or model runtime;
- an LLM provider router;
- a forge;
- a general-purpose workflow engine;
- a ticket tracker;
- a BI platform;
- a data warehouse;
- a secrets manager;
- a generic IAM replacement;
- a chat product;
- a universal knowledge base;
- an operating system kernel;
- a replacement for every client system.

A component belongs in the kernel only if all product deployments require the invariant it owns.

A component belongs in an adapter when it exists to translate between the product's semantic protocol and an external system.

A component belongs in a domain pack when it supplies declarative domain knowledge, policy templates, probes, mappings, or workflows without changing kernel semantics.

Do not absorb an external system merely because owning it would be convenient. Own a boundary only when external ownership prevents complete mediation, semantic correctness, assurance, or a required invariant.
