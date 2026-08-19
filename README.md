# politeia

A greenfield, harness-independent institutional control plane for agentic work.

The product attaches to an organization's existing systems and agent harnesses, discovers the shape of the institution, constructs a typed operating model, exposes only authorized operations, binds consequential state transitions to evidence, and improves its own operating projections without granting itself new authority.

This repository is intentionally a *starter architecture*, not a feature-complete product.

## Product thesis

Organizations increasingly have machine workers but still govern them with artifacts designed for humans: prose conventions, tribal knowledge, disconnected SaaS permissions, informal reviews, and manually reconstructed context.

This product turns the institution itself into an explicit, typed, evidence-bearing control plane.

## Core properties

- One semantic authority per fact.
- Derive projections rather than synchronize copies.
- Separate normative clauses, detectors, bindings, evidence, decisions, and attestations.
- Move enforcement to the hardest *semantically faithful* surface.
- Complete mediation for protected effects.
- Monotonic authority: delegated authority can only narrow.
- Self-maintenance without self-authorization.
- Exact binding of evidence and attestations to artifact, policy, runtime, adapter, and delegation identities.
- Harness independence: MCP/A2A/HTTP/CLI are transports, not the ontology.
- Progressive hardening: observe → model → approve → shadow → calibrate → enforce → structural.
- A deliberately small trusted semantic kernel.
- Adapters and domain packs remain at the edges.
- Closed-loop learning from observed friction and corrections.
- Invalid states should be unrepresentable where practical.
- Product anti-scope is first-class.

Start with [`START_HERE.md`](START_HERE.md).

## License

Open source under the **Mozilla Public License 2.0**. See [`LICENSE`](LICENSE). Modifications to
this project's own files stay MPL when distributed. Adapters, domain packs, and configuration
built on top remain yours to keep private. Copyright Ardent Works LLC (<https://ardent.tools>).
