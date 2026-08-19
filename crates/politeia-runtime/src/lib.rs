use async_trait::async_trait;
use politeia_core::{AdapterId, Delegation, Effect, OperationSpec, PolicyBundleId, PrincipalId, RuntimeGenerationId};
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

#[derive(Clone, Debug)]
pub struct EffectLease {
    principal: PrincipalId,
    effects: BTreeSet<Effect>,
    policy: PolicyBundleId,
    runtime: RuntimeGenerationId,
    adapter: AdapterId,
}

impl EffectLease {
    pub fn principal(&self) -> &PrincipalId { &self.principal }
    pub fn effects(&self) -> &BTreeSet<Effect> { &self.effects }
    pub fn policy(&self) -> &PolicyBundleId { &self.policy }
    pub fn runtime(&self) -> &RuntimeGenerationId { &self.runtime }
    pub fn adapter(&self) -> &AdapterId { &self.adapter }
}

#[async_trait]
pub trait PolicyDecisionPoint: Send + Sync {
    async fn decide(&self, intent: &OperationIntent) -> Result<PolicyDecision, RuntimeError>;
}

#[async_trait]
pub trait OperationHandler: Send + Sync {
    async fn execute(&self, lease: &EffectLease, intent: &OperationIntent) -> Result<serde_json::Value, RuntimeError>;
}

pub struct Dispatcher<P> {
    policy: P,
    policy_bundle: PolicyBundleId,
    runtime: RuntimeGenerationId,
    adapter: AdapterId,
}

impl<P: PolicyDecisionPoint> Dispatcher<P> {
    pub fn new(policy: P, policy_bundle: PolicyBundleId, runtime: RuntimeGenerationId, adapter: AdapterId) -> Self {
        Self { policy, policy_bundle, runtime, adapter }
    }

    pub async fn authorize(&self, intent: &OperationIntent) -> Result<EffectLease, RuntimeError> {
        let decision = self.policy.decide(intent).await?;
        if !decision.allowed { return Err(RuntimeError::Denied); }
        Ok(EffectLease {
            principal: intent.principal.clone(),
            effects: intent.operation.effects.clone(),
            policy: self.policy_bundle.clone(),
            runtime: self.runtime.clone(),
            adapter: self.adapter.clone(),
        })
    }
}
