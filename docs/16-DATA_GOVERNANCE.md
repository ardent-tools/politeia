# Data governance

Data classification is part of operation semantics.

At minimum model:

- public;
- internal;
- confidential;
- secret;
- regulated;
- personal;
- health;
- financial;
- client-restricted;
- derived-sensitive.

Policies constrain sources, transformations, retention, locality, and sinks.

Agent-visible context is a data sink.

Tool output is a data sink.

Logs and telemetry are data sinks.

A client-local model runtime and each remote inference provider are distinct data sinks.

Locality is a hard policy axis over the data class, operation, execution resource, trust domain, and sink. It may be a soft routing preference only when policy permits every candidate locality. An unknown sink, locality, purpose, retention rule, or institution boundary fails closed.

The institution workspace owns client-specific data classifications and approved secret references. Secret values, private facts, operational logs, evidence, and prompts do not move to a commissioner-controlled machine by default. Cross-institution reuse requires an explicit authorized export; it is never inferred from shared public-core code.

Every allowed or denied boundary crossing records purpose, source, transformation, sink, locality, retention/deletion policy, execution resource, routing decision, and authority.

The product must be able to answer: which classified data was allowed or denied at which boundary, under what authority, for what purpose, through which execution resource, and with what retention policy.
