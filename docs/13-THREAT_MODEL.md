# Threat model

## Adversaries and failures

- compromised or misaligned agent;
- prompt/tool-output injection;
- malicious external content;
- compromised adapter;
- over-broad delegation;
- confused deputy;
- stale or replayed authority;
- compromised evidence producer;
- self-certifying worker;
- policy downgrade;
- runtime mix-and-match;
- TOCTOU between verification and use;
- secret/PII exfiltration;
- dependency/supply-chain compromise;
- resource exhaustion;
- partial failure and duplicate side effects;
- poisoned institutional knowledge;
- malicious or accidental waiver use.

## Security architecture

Favor complete mediation, capability attenuation, explicit audiences, short-lived leases, typed data/effect labels, least privilege, independent evidence, immutable provenance, sandboxed extensions, authenticated runtime generations, and rollback-safe update metadata.
