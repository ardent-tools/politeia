use async_trait::async_trait;
use chrono::{DateTime, Utc};
use politeia_core::{
    AdapterId, Delegation, Effect, OperationSpec, PolicyBundleId, PrincipalId, RuntimeGenerationId,
};
use politeia_policy::PolicyDecision;
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("operation denied")]
    Denied,
    #[error("invalid or expired delegation")]
    InvalidDelegation,
    #[error("effect lease does not match request")]
    LeaseMismatch,
}

#[derive(Clone, Debug)]
pub struct OperationIntent {
    pub principal: PrincipalId,
    pub delegation: Delegation,
    pub operation: OperationSpec,
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
    expires_at: DateTime<Utc>,
    replay_domain: String,
}

impl EffectLease {
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    pub fn effects(&self) -> &BTreeSet<Effect> {
        &self.effects
    }
    pub fn policy(&self) -> &PolicyBundleId {
        &self.policy
    }
    pub fn runtime(&self) -> &RuntimeGenerationId {
        &self.runtime
    }
    pub fn adapter(&self) -> &AdapterId {
        &self.adapter
    }
    pub fn audience(&self) -> &BTreeSet<String> {
        &self.audience
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    pub fn replay_domain(&self) -> &str {
        &self.replay_domain
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    pub fn allows_audience(&self, audience: &str) -> bool {
        self.audience.contains(audience)
    }
}

#[async_trait]
pub trait PolicyDecisionPoint: Send + Sync {
    async fn decide(&self, intent: &OperationIntent) -> Result<PolicyDecision, RuntimeError>;
}

#[async_trait]
pub trait OperationHandler: Send + Sync {
    async fn execute(
        &self,
        lease: &EffectLease,
        intent: &OperationIntent,
    ) -> Result<serde_json::Value, RuntimeError>;
}

pub struct Dispatcher<P> {
    policy: P,
    policy_bundle: PolicyBundleId,
    runtime: RuntimeGenerationId,
    adapter: AdapterId,
    replay_domain: String,
}

impl<P: PolicyDecisionPoint> Dispatcher<P> {
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

    pub async fn authorize(&self, intent: &OperationIntent) -> Result<EffectLease, RuntimeError> {
        if intent.delegation.is_expired(Utc::now()) {
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
    use politeia_core::{DataClass, DelegationId, OperationId};

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

    fn delegation(expires_at: DateTime<Utc>) -> Delegation {
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
            budget: politeia_core::ResourceBudget {
                wall_ms: Some(1000),
                cpu_ms: None,
                memory_bytes: None,
                io_bytes: None,
                network_bytes: None,
                external_cost_microunits: None,
            },
        }
    }

    fn intent(expires_at: DateTime<Utc>) -> OperationIntent {
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
        let past = Utc::now() - chrono::Duration::hours(1);
        let result = d.authorize(&intent(past)).await;
        assert!(matches!(result, Err(RuntimeError::InvalidDelegation)));
    }

    #[tokio::test]
    async fn lease_carries_delegation_bounds() {
        let d = dispatcher();
        let future = Utc::now() + chrono::Duration::hours(1);
        let lease = d
            .authorize(&intent(future))
            .await
            .expect("valid delegation authorizes");
        assert_eq!(lease.expires_at(), future);
        assert!(lease.allows_audience("effect-port:fs"));
        assert!(!lease.allows_audience("effect-port:network"));
        assert_eq!(lease.replay_domain(), "test-runtime");
        assert!(!lease.is_expired(Utc::now()));
    }
}
