# Deployment topology and lifecycle profiles

Deployment topology and lifecycle are independent axes. Both may narrow capability or strengthen assurance; neither may redefine semantic meaning. Every runtime generation binds one of each.

## Deployment topology

### Local development

Single operator, in-memory or local PostgreSQL, development signing allowances, extensive diagnostics.

### Client-controlled single-tenant

Dedicated control plane per client, authenticated principals, durable PostgreSQL, signed runtime generations, strict secrets/data policy.

### Enterprise high-assurance

Isolated adapter execution, stronger identity federation, external policy/runtime signing authorities, disaster recovery, separation of duties, formal assurance for selected invariants.

A topology may strengthen controls. It may not redefine core semantics or grant lifecycle authority.

## Lifecycle profile

### Bootstrap

Bounded, expiring, read-heavy reconnaissance and candidate-model construction. It cannot approve constitutional truth.

### Commissioning

Institution-specific engineering: adapters, packs, policies, tests, evidence obligations, calibration, and generation derivation. Constitutional changes still require institution-owner authority.

### Operational

The smallest normal production surface. Generic reconnaissance and authoring authority are absent; only approved policy, adapters, packs, execution resources, and mediated operations are active.

### Maintenance

Bounded reconciliation and approved improvements. It cannot widen its own authority, waive policy, or weaken constitutional commitments.

### Recommissioning

A deliberate return to broader engineering after material change. It requires a fresh explicit authorization and preserves the prior operational generation until a replacement is verified and activated.

## Legal lifecycle transitions

`bootstrap → commissioning → operational`

`operational ↔ maintenance`

`operational | maintenance → recommissioning → operational`

No other transition is structurally valid. Policy may impose additional owner approval, evidence, or separation-of-duty requirements; it may not invent a shortcut around handoff or revocation. Every transition is authorized and evidence-bearing.
