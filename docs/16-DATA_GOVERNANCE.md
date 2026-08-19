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

A model provider is a data sink.

The product must be able to answer: which classified data crossed which boundary, under what authority, for what purpose, and with what retention policy.
