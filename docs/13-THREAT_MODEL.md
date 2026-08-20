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
- malicious or accidental waiver use;
- client data or credentials copied into a commissioner-controlled environment;
- cross-institution workspace, evidence, or generation contamination;
- inference-provider egress that violates a data-locality policy;
- over-broad, stale, or unrecoverable commissioning authority;
- poisoned or self-reported worker-performance evidence;
- routing-requirement downgrade or soft-preference override;
- execution-resource substitution after authorization;
- generation-input, commissioning-record, or activation-channel substitution;
- incomplete handoff that leaves a hidden commissioner or vendor dependency;
- false verifier independence through shared identity or control domain.

## Trust boundaries and protected assets

Name and bind the public core, each institution workspace and state/evidence store, lifecycle profile, commissioner environment, execution-resource/provider boundary, adapter and pack inputs, generation builder, and activation channel. The commissioner workstation and every remote inference endpoint are outside the client trust domain unless an explicit policy says otherwise.

## Security architecture

Favor complete mediation, capability attenuation, explicit audiences, short-lived leases, typed data/effect labels, least privilege, independent evidence, immutable provenance, sandboxed extensions, authenticated runtime generations, and rollback-safe update metadata.
