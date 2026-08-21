use jiff::Timestamp;
use politeia_core::{BudgetReservationId, Delegation, EffectLeaseId};
use snafu::ensure;

use super::{
    AuthorizationLedger, AuthorizedEffect, DecisionMismatchSnafu, DeniedSnafu, Dispatcher,
    DispatcherConfig, EffectLease, EffectPort, InvalidDelegationSnafu,
    InvalidExecutionAssignmentSnafu, LeaseClaims, LeaseMismatchSnafu, OperationIntent,
    PolicyDecisionPoint, RuntimeError, WrongAudienceSnafu,
};

impl<P: PolicyDecisionPoint, H: EffectPort, L: AuthorizationLedger> Dispatcher<P, H, L> {
    /// Construct a dispatcher that owns its registered effect port and trusted
    /// bootstrap configuration.
    ///
    /// Time: O(1). Space: O(1).
    pub fn new(policy: P, port: H, ledger: L, config: DispatcherConfig) -> Self {
        let adapter = port.adapter().clone();
        Self {
            policy,
            port,
            ledger,
            config,
            adapter,
        }
    }

    /// Authorize an operation intent against the current time.
    ///
    /// Time: O(d log d) locally for a d-hop delegation chain, plus the policy
    /// and ledger implementations. Space: O(d) for immutable lease claims.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the delegation chain, requested axes, or
    /// normalized policy decision is invalid or denied.
    pub async fn authorize(&self, intent: &OperationIntent) -> Result<EffectLease, RuntimeError> {
        let now = self.ledger.observed_at().await?;
        let delegation = self.validate_intent(intent, now)?;
        let intent_digest = intent.digest()?;
        let decision =
            self.policy
                .decide(intent)
                .await
                .map_err(|source| RuntimeError::PolicyEvaluation {
                    source: Box::new(source),
                })?;
        ensure!(
            decision.principal == intent.principal,
            DecisionMismatchSnafu { field: "principal" }
        );
        ensure!(
            decision.bundle == self.config.policy_bundle,
            DecisionMismatchSnafu {
                field: "policy bundle"
            }
        );
        ensure!(
            decision.policy_digest == self.config.policy_digest,
            DecisionMismatchSnafu {
                field: "policy digest"
            }
        );
        ensure!(
            decision.intent_digest == intent_digest,
            DecisionMismatchSnafu {
                field: "operation intent digest"
            }
        );
        ensure!(decision.allowed, DeniedSnafu);
        let max_expiry = now + self.config.max_lease_ttl;
        let assignment_expiry = intent
            .execution
            .as_ref()
            .map_or(max_expiry, |assignment| assignment.expires_at);
        let claims = LeaseClaims {
            id: EffectLeaseId::new(),
            reservation_id: BudgetReservationId::new(),
            principal: intent.principal.clone(),
            delegation_chain: intent.delegation_chain.clone(),
            operation: intent.operation.clone(),
            resources: intent.resources.clone(),
            budget: intent.budget.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            execution: intent.execution.clone(),
            decision,
            runtime: self.config.runtime.clone(),
            adapter: self.adapter.clone(),
            audience: delegation.audience.clone(),
            expires_at: delegation.expires_at.min(max_expiry).min(assignment_expiry),
            replay_domain: self.config.replay_domain.clone(),
        };
        let claims_digest = EffectLease::claims_digest(&claims)?;
        let lease = EffectLease {
            claims,
            claims_digest,
        };
        let reservation = lease.reservation_request()?;
        self.ledger.reserve(&reservation).await?;
        Ok(lease)
    }

    fn validate_intent<'intent>(
        &self,
        intent: &'intent OperationIntent,
        now: Timestamp,
    ) -> Result<&'intent Delegation, RuntimeError> {
        let root = intent.delegation_chain.first().ok_or_else(|| {
            InvalidDelegationSnafu {
                reason: "delegation chain is empty",
            }
            .build()
        })?;
        ensure!(
            root.parent.is_none(),
            InvalidDelegationSnafu {
                reason: "root delegation names a parent"
            }
        );
        ensure!(
            self.config.trusted_delegations.get(&root.id) == Some(root),
            InvalidDelegationSnafu {
                reason: "delegation root is not an exact trusted root"
            }
        );

        for pair in intent.delegation_chain.windows(2) {
            if let [parent, child] = pair {
                ensure!(
                    self.config.trusted_delegations.get(&child.id) == Some(child),
                    InvalidDelegationSnafu {
                        reason: "delegation child is not exactly registered"
                    }
                );
                ensure!(
                    child.parent.as_ref() == Some(&parent.id),
                    InvalidDelegationSnafu {
                        reason: "delegation parent link does not match the chain"
                    }
                );
                ensure!(
                    child.issuer == parent.subject,
                    InvalidDelegationSnafu {
                        reason: "child issuer is not the parent subject"
                    }
                );
                ensure!(
                    child.is_attenuation_of(parent),
                    InvalidDelegationSnafu {
                        reason: "child delegation widens its parent"
                    }
                );
            }
        }

        let leaf = intent.delegation_chain.last().ok_or_else(|| {
            InvalidDelegationSnafu {
                reason: "delegation chain is empty",
            }
            .build()
        })?;
        ensure!(
            self.config.trusted_operations.get(&intent.operation.id) == Some(&intent.operation),
            InvalidDelegationSnafu {
                reason: "operation contract is not exactly registered"
            }
        );
        ensure!(
            !leaf.is_expired(now),
            InvalidDelegationSnafu {
                reason: "delegation has expired"
            }
        );
        ensure!(
            leaf.subject == intent.principal,
            InvalidDelegationSnafu {
                reason: "requesting principal is not the delegated subject"
            }
        );
        ensure!(
            intent.operation.actions.is_subset(&leaf.actions),
            InvalidDelegationSnafu {
                reason: "operation actions exceed the delegation"
            }
        );
        ensure!(
            intent.resources.is_subset(&leaf.resources),
            InvalidDelegationSnafu {
                reason: "operation resources exceed the delegation"
            }
        );
        ensure!(
            intent.operation.effects.is_subset(&leaf.effects),
            InvalidDelegationSnafu {
                reason: "operation effects exceed the delegation"
            }
        );
        ensure!(
            intent.operation.data_classes.is_subset(&leaf.data_classes),
            InvalidDelegationSnafu {
                reason: "operation data classes exceed the delegation"
            }
        );
        ensure!(
            intent.budget.is_attenuation_of(&leaf.budget),
            InvalidDelegationSnafu {
                reason: "requested budget exceeds the delegation"
            }
        );
        ensure!(
            intent.budget.is_finite(),
            InvalidDelegationSnafu {
                reason: "operation budget is not finite"
            }
        );
        let valid_idempotency_key = match intent.idempotency_key.as_deref() {
            Some(key) => !key.trim().is_empty() && key.len() <= 256,
            None => !intent.operation.requires_idempotency,
        };
        ensure!(
            valid_idempotency_key,
            InvalidDelegationSnafu {
                reason: "operation idempotency key is missing or invalid"
            }
        );
        match (
            intent.operation.execution_requirement.as_ref(),
            intent.execution.as_ref(),
        ) {
            (None, None) => {}
            (Some(required), Some(assignment)) => {
                ensure!(
                    &assignment.requirement_digest == required,
                    InvalidExecutionAssignmentSnafu {
                        reason: "routing assignment satisfies a different requirement"
                    }
                );
                ensure!(
                    self.config
                        .trusted_execution_assignments
                        .get(&assignment.routing_decision)
                        == Some(assignment),
                    InvalidExecutionAssignmentSnafu {
                        reason: "routing assignment is absent from trusted bootstrap or substituted"
                    }
                );
                ensure!(
                    now < assignment.expires_at,
                    InvalidExecutionAssignmentSnafu {
                        reason: "routing assignment is expired"
                    }
                );
                ensure!(
                    assignment.adapter == self.adapter,
                    InvalidExecutionAssignmentSnafu {
                        reason: "selected execution resource belongs to a different adapter"
                    }
                );
            }
            (Some(_), None) => {
                return InvalidExecutionAssignmentSnafu {
                    reason: "operation requires an admitted routing assignment",
                }
                .fail();
            }
            (None, Some(_)) => {
                return InvalidExecutionAssignmentSnafu {
                    reason: "operation contract does not admit an execution resource",
                }
                .fail();
            }
        }
        Ok(leaf)
    }

    /// Validate and atomically consume `lease`, then invoke the registered port.
    ///
    /// # Errors
    ///
    /// Returns a typed error without invoking the port when the lease is
    /// expired, replayed, unreserved, or bound to a different adapter, replay
    /// domain, policy, runtime, or audience. The ledger atomically charges the
    /// full reserved maximum before the port call, so errors are at-most-once
    /// and remain conservatively spent.
    ///
    /// Time: O(d) locally for a d-hop reservation projection, plus the ledger
    /// and port implementations. Space: O(d) for that projection.
    pub async fn execute(&self, lease: &EffectLease) -> Result<H::Output, RuntimeError> {
        ensure!(
            lease.policy() == &self.config.policy_bundle,
            LeaseMismatchSnafu {
                field: "policy bundle"
            }
        );
        ensure!(
            lease.policy_digest() == &self.config.policy_digest,
            LeaseMismatchSnafu {
                field: "policy digest"
            }
        );
        ensure!(
            lease.runtime() == &self.config.runtime,
            LeaseMismatchSnafu {
                field: "runtime generation"
            }
        );
        ensure!(
            lease.adapter() == &self.adapter && self.port.adapter() == &self.adapter,
            LeaseMismatchSnafu { field: "adapter" }
        );
        ensure!(
            lease.replay_domain() == self.config.replay_domain,
            LeaseMismatchSnafu {
                field: "replay domain"
            }
        );
        ensure!(
            lease.allows_audience(self.port.audience()),
            WrongAudienceSnafu
        );

        let reservation = lease.reservation_request()?;
        self.ledger.claim(&reservation).await?;

        self.port
            .execute(AuthorizedEffect {
                lease,
                _dispatcher_seal: (),
            })
            .await
            .map_err(|source| RuntimeError::EffectInvocation {
                source: Box::new(source),
            })
    }
}
