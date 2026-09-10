# politeia

A greenfield, harness-independent institutional control plane for human and machine work.

Politeia learns an institution's approved knowledge, systems, and workflows before a particular task needs them. Observations become candidate claims; authenticated owner approval makes them available to authorized context, discovery, and work. Feedback proposes corrections, and approved changes improve those projections without granting the system new authority.

The product is under active development. Its first commissioning package combines a Rust API, Linux CLI and daemon, PostgreSQL state, and immutable signed generations for two synthetic reference institutions.

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
  The ladder is declared by `politeia_policy::hardening` and published as a transition table at
  `spec/policy-lifecycle.yaml`; this line is prose for a reader, not the authority.
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

## Local installation and synthetic commissioning

The first package is a single-tenant Linux daemon backed by PostgreSQL. It uses a private Unix socket and an institution-owned prefix; signing keys remain outside PostgreSQL under `<prefix>/keys` (mode `0700` directory and `0600` files). The daemon never accepts a client filesystem path: CLI request files are read locally and their JSON bytes cross the socket.

Build the CLI from source, prepare an empty PostgreSQL database, and set its connection string only in the process environment:

```sh
cargo build --release -p politeiad --bins
export POLITEIA_DATABASE_URL='postgres://…/politeia_synthetic'
./target/release/politeia initialize /tmp/politeia-synthetic ./host-trust.json
./target/release/politeiad serve /tmp/politeia-synthetic
```

`host-trust.json` is a serialized `politeiad::config::HostTrustConfiguration`. It contains public verification keys and an owner-signed `WorkspaceBootstrapRequest`; it contains no private signing key. Construct and sign it with the public Rust APIs demonstrated by the [synthetic commissioning fixture](crates/politeiad/tests/package_support/mod.rs), then keep the corresponding signing keys in your institution-owned key directory, never in Git or PostgreSQL. The fixture's deterministic test keys are examples only; an installation supplies its own independently generated keys.

In another terminal, submit an already signed synthetic request document and inspect JSON evidence responses:

```sh
./target/release/politeia status /tmp/politeia-synthetic/run/politeiad.sock
./target/release/politeia commissioning /tmp/politeia-synthetic/run/politeiad.sock ./grant.json
./target/release/politeia snapshot /tmp/politeia-synthetic/run/politeiad.sock ./capture.json
./target/release/politeia commissioning /tmp/politeia-synthetic/run/politeiad.sock ./approval.json
```

The command names are stable; their documents are typed signed wires, not loose JSON configuration. `grant.json` is `{"kind":"admit_delegation","delegation":…}`. `capture.json` is a `SourceCaptureSubmission`, and `approval.json` is `{"kind":"approve_claim","candidate":…,"approval":…}`. A bootstrap capture requires a direct owner-to-commissioner grant whose singleton action, resources, effect, audience, and finite budget exactly match the signed capture descriptor. Use `commissioning` with `{"kind":"generation","request":…}` for publication, verification, reproduction, activation, rollback, and recommissioning lifecycle requests.

For a published generation, `{"kind":"generation","request":{"kind":"reproduce","generation":"<digest>"}}` materializes its retained signed inputs in a fresh directory and compares the complete bundle byte for byte. It needs neither the original source working directory nor the original commissioner's private key. The result proves generation materialization; approved executables are inputs to this operation, so it does not claim an independent compiler rebuild.

Run `politeiad serve` only after `initialize` succeeds. A normal daemon exit removes its own socket; a restart removes only a proved stale private socket. Refused requests print a JSON refusal and exit nonzero.

The executable acceptance harness constructs the software-development and analytics installations from public Rust APIs and signed JSON documents. Run it and the durable storage checks with `python3 bin/check-postgres.py`; the script uses `POLITEIA_STORAGE_TEST_DATABASE_URL` when supplied, or starts a disposable PostgreSQL container with Docker or Podman. PostgreSQL is required: an absent database is a failed prerequisite, never a passing acceptance result.
