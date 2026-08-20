# politeia

A greenfield, harness-independent institutional control plane for human and machine work.

The product starts from one recurring institutional friction and attaches to the approved systems, workflows, and optional agent harnesses needed to resolve it. It constructs a typed operating model, exposes only authorized operations, binds consequential state transitions to evidence, and improves its own operating projections without granting itself new authority.

This repository is intentionally a *starter architecture*, not a feature-complete product.

## Product thesis

Organizations increasingly have machine workers but still govern them through human-interpreted artifacts: prose conventions, tribal knowledge, disconnected SaaS permissions, informal reviews, and manually reconstructed context. Politeia starts from that institutional friction, makes it observable, and turns approved corrections into durable structure.

This product turns the institution itself into an explicit, typed, evidence-bearing control plane.

## Core properties

- One semantic authority per fact.
- Derive every projection mechanically from its canonical owner.
- Separate normative clauses, detectors, bindings, evidence, decisions, and attestations.
- Move enforcement to the hardest *semantically faithful* surface.
- Complete mediation for protected effects.
- Explicit effect uncertainty: missing outcome evidence is not proof that an issued effect did not run, and unsafe replay fails closed.
- Monotonic authority: delegated authority can only narrow.
- Self-maintenance without self-authorization.
- Exact binding of evidence and attestations to artifact, policy, runtime, adapter, and delegation identities.
- Harness independence: MCP/A2A/HTTP/CLI are transports, not the ontology.
- Progressive hardening: observe → model → approve → shadow → calibrate → enforce → structural.
- A deliberately small trusted semantic kernel.
- Adapters and domain packs remain at the edges.
- Self-sufficient commissioning from the public source distribution inside a client-controlled environment.
- Client-owned institutional state, credentials, inference accounts, evidence, and production authority by default.
- Reproducible specialization into a narrower immutable runtime generation instead of destructive source mutation.
- Execution-resource neutrality: explicit requirements and evidence select models, deterministic tools, services, and people. Vendor rank never does.
- Closed-loop learning from observed friction and corrections.
- Authoritative population membership plus type-or-fail derivation for every included member.
- Assurance results distinguish a control that proved clean from one that did not run, could not observe its subject, or examined an empty population.
- Invalid states should be unrepresentable where practical.
- Product anti-scope is first-class.

Start with [`START_HERE.md`](START_HERE.md).

## License

Open source under the **Mozilla Public License 2.0**. See [`LICENSE`](LICENSE). Modifications to
this project's own files stay MPL when distributed. Adapters, domain packs, and configuration
built on top remain yours to keep private. Copyright Ardent Works LLC (<https://ardent.tools>).
