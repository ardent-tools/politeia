# Context compilation

Agents should receive the smallest sufficient context projection for the current intent, authority, and phase.

Context compilation is derived from the institutional model and may include:

- applicable constitutional commitments;
- approved facts and unresolved conflicts;
- task/plan state;
- allowed operations and effects;
- evidence obligations;
- data-handling constraints;
- relevant runbooks/knowledge;
- known hazards and missed axes.

Do not expose the entire institutional model by default.

Authorization, data-class, audience, trust-domain, and sink eligibility filter the candidate set
before semantic relevance or optimization is considered. A worker/model's capability cannot make
an unauthorized source eligible.

Ranking among eligible sources accounts for canonical/derived/evidence/reference/archive authority
class, provenance quality, recency/staleness, exact subject identity, and task need as well as
semantic relevance. For a current-state intent, current canonical state may not be displaced by a
lexically stronger stale projection or raw archive unless the intent explicitly requests history.

Ordinary context carries secret references or credential identities where possible, not raw secret
values. Retrieving secret material is a separately authorized capability/effect.

Context projections are disposable derived artifacts and must be reproducible from the eligible
source identities, authorization decision, ranking inputs, and compiler version.
