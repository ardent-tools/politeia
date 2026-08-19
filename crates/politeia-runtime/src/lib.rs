//! politeia-runtime: the authorized dispatcher and effect lease.
//!
//! Every protected effect crosses the same boundary: an operation intent is
//! decided by the policy point, and only an allowed decision mints an
//! unforgeable effect lease. Lease construction is private to this crate.

#![deny(missing_docs)]

use async_trait::async_trait;
use jiff::Timestamp;
use politeia_core::{
    AdapterId, Delegation, Effect, OperationSpec, PolicyBundleId, PrincipalId, RuntimeGenerationId,
};
use politeia_policy::PolicyDecision;
use std::collections::BTreeSet;
use thiserror::Error;

/// Failures of the dispatch boundary. All deny-shaped variants fail closed.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The policy decision denied the operation.
    #[error("operation denied")]
    Denied,
    /// The delegation was invalid or expired.
    #[error("invalid or expired delegation")]
    InvalidDelegation,
    /// The presented lease does not match the request.
    #[error("effect lease does not match request")]
    LeaseMismatch,
}

/// A request to perform one bounded operation: who asks, under which
/// delegation, which operation contract, over which resources.
#[derive(Clone, Debug, JsonSchema)]
pub struct OperationIntent {
    /// The requesting principal.
    pub principal: PrincipalId,
    /// The delegation under which the request proceeds.
    pub delegation: Delegation,
    /// The operation contract being invoked.
    pub operation: OperationSpec,
    /// The resources the invocation touches.
    pub resources: BTreeSet<String>,
}

/// An unforgeable authorization to produce effects, issued only by the
/// dispatcher. Per docs/04-KERNEL_CONTRACT.md a lease binds principal, effect
/// set, policy bundle, runtime generation, adapter, audience, expiry, and a
/// replay domain; construction is private so a caller cannot mint one.
#[derive(Clone, Debug)]
pub struct EffectLease {
    principal: PrincipalId,
    effects: BTreeSet<Effect>,
    policy: PolicyBundleId,
    runtime: RuntimeGenerationId,
    adapter: AdapterId,
    audience: BTreeSet<String>,
    expires_at: Timestamp,
    replay_domain: String,
}

impl EffectLease {
    /// The principal the lease was issued to.
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    /// The effects the lease permits.
    pub fn effects(&self) -> &BTreeSet<Effect> {
        &self.effects
    }
    /// The policy bundle the decision was made under.
    pub fn policy(&self) -> &PolicyBundleId {
        &self.policy
    }
    /// The runtime generation the decision was made under.
    pub fn runtime(&self) -> &RuntimeGenerationId {
        &self.runtime
    }
    /// The adapter the lease is valid through.
    pub fn adapter(&self) -> &AdapterId {
        &self.adapter
    }
    /// The audiences the lease is valid for.
    pub fn audience(&self) -> &BTreeSet<String> {
        &self.audience
    }
    /// The lease's expiry instant.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
    /// The replay domain the lease is bound to.
    pub fn replay_domain(&self) -> &str {
        &self.replay_domain
    }

    /// True when the lease has expired at `now`.
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }

    /// True when the lease is valid for `audience`.
    pub fn allows_audience(&self, audience: &str) -> bool {
        self.audience.contains(audience)
    }
}

/// The policy decision point: evaluates an operation intent and returns a
/// normalized decision.
#[async_trait]
pub trait PolicyDecisionPoint: Send + Sync {
    /// Decide an operation intent. An error is a failure of evaluation; a
    /// denied decision is `allowed: false`.
    async fn decide(&self, intent: &OperationIntent) -> Result<PolicyDecision, RuntimeError>;
}

/// An effect port: executes an authorized operation under a lease.
#[async_trait]
pub trait OperationHandler: Send + Sync {
    /// Execute one bounded operation under its lease.
    async fn execute(
        &self,
        lease: &EffectLease,
        intent: &OperationIntent,
    ) -> Result<serde_json::Value, RuntimeError>;
}

/// The single authorized dispatcher. Every productive frontend resolves and
/// authorizes through this type; there is no bypass path.
pub struct Dispatcher<P> {
    policy: P,
    policy_bundle: PolicyBundleId,
    runtime: RuntimeGenerationId,
    adapter: AdapterId,
    replay_domain: String,
}

impl<P: PolicyDecisionPoint> Dispatcher<P> {
    /// Construct a dispatcher bound to a policy point and the exact policy,
    /// runtime, adapter, and replay-domain identities it mints leases under.
    pub fn new(
        policy: P,
        policy_bundle: PolicyBundleId,
        runtime: RuntimeGenerationId,
        adapter: AdapterId,
        replay_domain: String,
    ) -> Self {
        Self {
            policy,
            policy_bundle,
            runtime,
            adapter,
            replay_domain,
        }
    }

    /// Authorize an operation intent. Fails closed on an expired delegation or
    /// a denying decision; on success mints a lease bound to the delegation's
    /// own audience and expiry.
    pub async fn authorize(&self, intent: &OperationIntent) -> Result<EffectLease, RuntimeError> {
        if intent.delegation.is_expired(Timestamp::now()) {
            return Err(RuntimeError::InvalidDelegation);
        }
        let decision = self.policy.decide(intent).await?;
        if !decision.allowed {
            return Err(RuntimeError::Denied);
        }
        Ok(EffectLease {
            principal: intent.principal.clone(),
            effects: intent.operation.effects.clone(),
            policy: self.policy_bundle.clone(),
            runtime: self.runtime.clone(),
            adapter: self.adapter.clone(),
            audience: intent.delegation.audience.clone(),
            expires_at: intent.delegation.expires_at,
            replay_domain: self.replay_domain.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::SignedDuration;
    use politeia_core::{DataClass, DelegationId, OperationId, ResourceBudget};

    struct AllowAll;

    #[async_trait]
    impl PolicyDecisionPoint for AllowAll {
        async fn decide(&self, intent: &OperationIntent) -> Result<PolicyDecision, RuntimeError> {
            Ok(PolicyDecision {
                bundle: PolicyBundleId::new(),
                principal: intent.principal.clone(),
                allowed: true,
                binding_ids: vec![],
                reasons: vec![],
            })
        }
    }

    fn delegation(expires_at: Timestamp) -> Delegation {
        Delegation {
            id: DelegationId::new(),
            issuer: PrincipalId::new(),
            subject: PrincipalId::new(),
            parent: None,
            actions: BTreeSet::from(["read".to_string()]),
            resources: BTreeSet::from(["repo:main".to_string()]),
            effects: BTreeSet::from([Effect::ReadExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Public]),
            audience: BTreeSet::from(["effect-port:fs".to_string()]),
            expires_at,
            budget: ResourceBudget {
                wall_ms: Some(1000),
                cpu_ms: None,
                memory_bytes: None,
                io_bytes: None,
                network_bytes: None,
                external_cost_microunits: None,
            },
        }
    }

    fn intent(expires_at: Timestamp) -> OperationIntent {
        OperationIntent {
            principal: PrincipalId::new(),
            delegation: delegation(expires_at),
            operation: OperationSpec {
                id: OperationId::new(),
                name: "read_repo".to_string(),
                actions: BTreeSet::from(["read".to_string()]),
                effects: BTreeSet::from([Effect::ReadExternalSystem]),
                data_classes: BTreeSet::from([DataClass::Public]),
                evidence_obligations: vec![],
                retryable: true,
                requires_idempotency: false,
            },
            resources: BTreeSet::from(["repo:main".to_string()]),
        }
    }

    fn dispatcher() -> Dispatcher<AllowAll> {
        Dispatcher::new(
            AllowAll,
            PolicyBundleId::new(),
            RuntimeGenerationId::new(),
            AdapterId::new(),
            "test-runtime".to_string(),
        )
    }

    #[tokio::test]
    async fn expired_delegation_fails_closed() {
        let d = dispatcher();
        let past = Timestamp::now() - SignedDuration::from_hours(1);
        let result = d.authorize(&intent(past)).await;
        assert!(matches!(result, Err(RuntimeError::InvalidDelegation)));
    }

    #[tokio::test]
    async fn lease_carries_delegation_bounds() {
        let d = dispatcher();
        let future = Timestamp::now() + SignedDuration::from_hours(1);
        let lease = d
            .authorize(&intent(future))
            .await
            .expect("valid delegation authorizes");
        assert_eq!(lease.expires_at(), future);
        assert!(lease.allows_audience("effect-port:fs"));
        assert!(!lease.allows_audience("effect-port:network"));
        assert_eq!(lease.replay_domain(), "test-runtime");
        assert!(!lease.is_expired(Timestamp::now()));
    }
}
