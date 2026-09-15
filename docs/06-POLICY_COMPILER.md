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

Promotion to an enforced assurance state requires activation evidence: a known
violation must traverse the intended mediation path and produce the promised refusal or finding,
with a known-good control. Unit detector tests prove local logic; they do not prove that the host
invokes the detector, preserves its signal, or honors its result.

Before first activation, the institution owner may authorize qualification of an
exact, verified inactive generation. The grant binds the policy, binding, control,
population, and both signed vector intents. Qualification uses the operational
dispatcher, ledger, and effect port. It may omit only the target binding's missing
activation prerequisite; every other applicable obligation still holds. Its
authority cannot authorize ordinary execution, arbitrary inputs, or a change to
the active generation.

The retained report records the actual control invocations, the known-good
receipt, and the planted violation's attributable denial. A rule reproduction or
caller-authored outcome is insufficient. An independently authorized verifier
admits evidence bound to that retained report. Activation and rollback require
the complete set of blocking-control proofs selected by the candidate policy;
the owner transition binds that set with its other assurance inputs. Missing or
mismatched evidence leaves the active pointer unchanged.

An activation proof identifies the detector version, configuration, policy,
calibration population, and mediation path. Bindings that reference that same
detector reuse its proof within its declared supported scopes. The qualification
grant remains binding-specific; it confines the exceptional exercise and does
not create a separate activation identity. Each subsequent operation still
requires its own exact control run through the declared path.

`ControlResult` uses the exact states `clean`, `violation`, `not_run`, `unavailable`, `unevaluable`,
`unexpectedly_empty`, `not_applicable`, and `unresolved`. A state in which nothing meaningful was
checked may not contribute to a clean assurance summary.

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

## No semantic orphans

Each governed projection declares one authoritative membership selector or exhaustive source
manifest and a stable source-identity function. Membership evaluation produces an attributable
included/excluded decision for every source object; the compiler may not omit an eligible object
before typing begins. Missing required contract data for an included member is an attributable
derivation error, not a reason to skip the object and emit an apparently complete projection. The
error names the source object/location, missing semantic field, owning contract, and a legitimate
closure when one is known.

Completeness compares the selected source identity set with the typed output identity set and then
compares identities across representations, with explicit allowed subset predicates where needed.
Count equality alone cannot prove that two projections contain the same members.

For execution routing, policy produces hard eligibility constraints before any optimization occurs. A preference for cost, locality, or latency cannot override a data-boundary, capability, authority, or independent-assurance requirement.
