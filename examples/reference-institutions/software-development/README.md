# Synthetic software-development institution

This public fixture represents a small software-development institution. It has
an owner, a temporary commissioner, an operational worker, an independent
verifier, and a replacement maintainer. The facts are synthetic and do not
describe a customer or a production system.

## Approved institutional knowledge

- The source population is the checked-in service, schema, migration, and
  public release metadata selected by an explicit manifest.
- Changes to the deployment runbook require owner approval and preserve the
  previous approved version as evidence.
- The production worker may perform only the deterministic canary operation;
  it has no authority to commission, approve facts, or alter policy.
- The verifier attests the exact generation, selected source membership, and
  canary receipt independently of the commissioner.

## Runbook facts

- Installation uses a private local prefix, PostgreSQL, and a Unix socket.
- A commissioner grant is temporary and revocation must leave the active
  generation and worker canary usable.
- A replacement maintainer receives fresh authority and reuses only preserved
  signed records plus public source inputs.
