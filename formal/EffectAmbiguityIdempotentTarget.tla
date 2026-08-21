--------------------- MODULE EffectAmbiguityIdempotentTarget ---------------------
\* EffectAmbiguity under the other value of TargetEnforcesIdempotency.
\*
\* WHY a second module rather than a second configuration: with the constant
\* FALSE, `ReplayNeedsGrounds` can only be satisfied by resolution,
\* reconciliation or compensation, so the target-evidence disjunct is never the
\* reason a grant was legal and is never exercised. With it TRUE that disjunct
\* is available everywhere -- and the question becomes whether the *other*
\* rules still hold when the easiest one is always satisfied. Uncertain
\* equivalence in particular must still fail closed against a target that
\* enforces idempotency perfectly, because idempotency is a property of a
\* subject and uncertainty is doubt about which subject this is.
\*
\* It adds no operators. Everything it checks is the parent's, under one
\* changed parameter.
EXTENDS EffectAmbiguity

=============================================================================
