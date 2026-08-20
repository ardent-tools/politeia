# Policy compiler

Policy is represented as typed semantics, then projected into human and machine surfaces.

## Separation

`NormativeClause != DetectorSpec != PolicyBinding`

A clause defines a desired proposition.

A detector defines an evidence-producing method and its limitations.

A binding defines where the clause applies, which evidence is admissible, and what consequence follows.

## Detector assurance

A detector declares:

- evidence class: substance / structural proxy / lexical proxy / heuristic / formal proof;
- precision expectations;
- recall expectations where measurable;
- supported scopes;
- known blind spots;
- adversarial fixtures;
- calibration status;
- independence characteristics;
- cost/latency.

Blocking authority is a property of the binding, not inherent in the detector.

## Projections

Generate, where possible:

- human standards;
- agent context;
- rule catalogs;
- schemas;
- CI/gate configuration;
- local hooks;
- SARIF mapping;
- waiver forms;
- documentation indexes.

Generated projections never become semantic peers of their source.

For execution routing, policy produces hard eligibility constraints before any optimization occurs. A preference for cost, locality, or latency cannot override a data-boundary, capability, authority, or independent-assurance requirement.
