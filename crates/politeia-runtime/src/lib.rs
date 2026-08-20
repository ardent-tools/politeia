//! politeia-runtime: the authorized dispatcher and effect lease.
//!
//! The scaffold models one protected-effect boundary: an operation intent is
//! decided by the policy point, and only an allowed decision mints an
//! unforgeable effect lease. Lease construction is private to this crate.

#![deny(missing_docs)]

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
};

use jiff::{SignedDuration, Timestamp};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu, ensure};

use politeia_core::{
    AdapterId, BudgetReservationId, DataClass, Delegation, DelegationId, Digest, Effect,
    EffectLeaseId, OperationId, OperationSpec, PolicyBundleId, PrincipalId, ResourceBudget,
    RuntimeGenerationId,
};
use politeia_policy::PolicyDecision;

mod ledger;
pub mod routing;

pub use ledger::{
    AuthorizationLedger, BudgetScope, InMemoryAuthorizationLedger, ReservationRequest,
};

/// Failures of the dispatch boundary. All deny-shaped variants fail closed.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RuntimeError {
    /// The policy decision denied the operation.
    #[snafu(display("operation denied"))]
    Denied {
        /// Source location where the denial surfaced.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// The delegation chain or requested authority was invalid.
    #[snafu(display("invalid delegation: {reason}"))]
    InvalidDelegation {
        /// The invariant that the delegation or request violated.
        reason: &'static str,
        /// Source location where invalid delegation was detected.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// Trusted dispatcher bootstrap configuration was internally invalid.
    #[snafu(display("invalid dispatcher configuration: {reason}"))]
    InvalidConfiguration {
        /// The configuration invariant that was violated.
        reason: &'static str,
        /// Source location where invalid configuration was detected.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// The selected execution resource or routing receipt is stale or invalid.
    #[snafu(display("invalid execution assignment: {reason}"))]
    InvalidExecutionAssignment {
        /// The routing/assignment invariant that was violated.
        reason: &'static str,
        /// Source location where the invalid assignment was detected.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// The normalized policy decision did not match the request or dispatcher.
    #[snafu(display("policy decision does not match {field}"))]
    DecisionMismatch {
        /// The decision field that did not match.
        field: &'static str,
        /// Source location where the mismatch surfaced.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// The presented lease does not match the dispatcher or effect port.
    #[snafu(display("effect lease does not match {field}"))]
    LeaseMismatch {
        /// The lease field that did not match.
        field: &'static str,
        /// Source location where the mismatch surfaced.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// The lease expired before effect invocation.
    #[snafu(display("effect lease expired before invocation"))]
    LeaseExpired {
        /// Source location where expiry was detected.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// The effect port is outside the lease's authorized audience.
    #[snafu(display("effect port audience is not authorized"))]
    WrongAudience {
        /// Source location where the audience mismatch surfaced.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// The lease has already been consumed in this replay domain.
    #[snafu(display("effect lease replay detected"))]
    ReplayDetected {
        /// Source location where replay was detected.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// The immutable lease claims could not be encoded for exact binding.
    #[snafu(display("failed to encode effect lease claims"))]
    LeaseEncoding {
        /// JSON encoding failure for the typed lease claims.
        source: serde_json::Error,
        /// Source location where encoding failed.
        #[snafu(implicit)]
        location: snafu::Location,
    },
    /// A finite operation budget could not be reserved or charged.
    #[snafu(display("operation budget unavailable: {reason}"))]
    BudgetUnavailable {
        /// The invariant or capacity bound that rejected the reservation.
        reason: &'static str,
    },
    /// Durable authorization state did not exactly match the presented lease.
    #[snafu(display("authorization reservation mismatch: {reason}"))]
    ReservationMismatch {
        /// The mismatched reservation invariant.
        reason: &'static str,
    },
    /// The authoritative ledger could not read or commit authorization state.
    #[snafu(display("authorization state unavailable: {source}"))]
    AuthorizationState {
        /// The durable ledger implementation's source error. The generic
        /// backend type is erased while the public outer error stays matchable.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The policy decision point failed to evaluate the request.
    #[snafu(display("policy evaluation failed: {source}"))]
    PolicyEvaluation {
        /// The policy implementation's source error. The generic policy type
        /// is erased here while the public outer error remains matchable.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The registered effect port failed after authorization was claimed.
    #[snafu(display("effect invocation failed: {source}"))]
    EffectInvocation {
        /// The effect-port implementation's source error. The generic port
        /// type is erased here while the public outer error remains matchable.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

fn lease_expired() -> RuntimeError {
    LeaseExpiredSnafu.build()
}

fn replay_detected() -> RuntimeError {
    ReplayDetectedSnafu.build()
}

/// A request to perform one bounded operation: who asks, under which
/// delegation, which operation contract, over which resources.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationIntent {
    /// The requesting principal.
    pub principal: PrincipalId,
    /// The complete root-to-leaf delegation chain under which the request proceeds.
    pub delegation_chain: Vec<Delegation>,
    /// The operation contract being invoked.
    pub operation: OperationSpec,
    /// The resources the invocation touches.
    pub resources: BTreeSet<String>,
    /// The bounded resources this invocation requests.
    pub budget: ResourceBudget,
    /// Stable operation key required when the operation declares idempotency.
    pub idempotency_key: Option<String>,
    /// Exact resource selection bound before policy evaluation, when the work
    /// requires an external execution resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<routing::ExecutionAssignment>,
}

impl OperationIntent {
    /// Digest the exact canonical wire representation used for policy binding.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::LeaseEncoding`] if the typed intent cannot be
    /// serialized. BTree-backed sets make the representation deterministic.
    pub fn digest(&self) -> Result<Digest, RuntimeError> {
        let bytes = serde_json::to_vec(self).context(LeaseEncodingSnafu)?;
        Ok(Digest::blake3(&bytes))
    }
}

/// An unforgeable, single-use authorization to produce effects.
///
/// Every claim required by `docs/04-KERNEL_CONTRACT.md` is immutable and
/// construction remains private to the dispatcher.
#[derive(Serialize)]
struct LeaseClaims {
    id: EffectLeaseId,
    reservation_id: BudgetReservationId,
    principal: PrincipalId,
    delegation_chain: Vec<Delegation>,
    operation: OperationSpec,
    resources: BTreeSet<String>,
    budget: ResourceBudget,
    idempotency_key: Option<String>,
    execution: Option<routing::ExecutionAssignment>,
    decision: PolicyDecision,
    runtime: RuntimeGenerationId,
    adapter: AdapterId,
    audience: BTreeSet<String>,
    expires_at: Timestamp,
    replay_domain: String,
}

/// An unforgeable, single-use authorization to produce effects.
///
/// The private typed claims bind every axis required by the kernel contract;
/// `claims_digest` detects any substitution before the effect port is called.
pub struct EffectLease {
    claims: LeaseClaims,
    claims_digest: Digest,
}

impl EffectLease {
    /// The unique single-use identity of this lease.
    pub fn id(&self) -> &EffectLeaseId {
        &self.claims.id
    }
    /// Identity of the durable budget and replay reservation backing the lease.
    pub fn reservation_id(&self) -> &BudgetReservationId {
        &self.claims.reservation_id
    }
    /// The principal the lease was issued to.
    pub fn principal(&self) -> &PrincipalId {
        &self.claims.principal
    }
    /// The exact root-to-leaf delegation identities bound to the lease.
    pub fn delegation_chain(&self) -> &[Delegation] {
        &self.claims.delegation_chain
    }
    /// The exact operation contract bound to the lease.
    pub fn operation(&self) -> &OperationSpec {
        &self.claims.operation
    }
    /// The resources the lease permits the operation to touch.
    pub fn resources(&self) -> &BTreeSet<String> {
        &self.claims.resources
    }
    /// The effects the lease permits.
    pub fn effects(&self) -> &BTreeSet<Effect> {
        &self.claims.operation.effects
    }
    /// The data classes the lease permits the operation to touch.
    pub fn data_classes(&self) -> &BTreeSet<DataClass> {
        &self.claims.operation.data_classes
    }
    /// The resource budget bound to the lease.
    pub fn budget(&self) -> &ResourceBudget {
        &self.claims.budget
    }
    /// Stable operation key bound to the lease, when idempotency is required.
    pub fn idempotency_key(&self) -> Option<&str> {
        self.claims.idempotency_key.as_deref()
    }
    /// Exact resource selection and routing receipt bound to the lease.
    pub fn execution(&self) -> Option<&routing::ExecutionAssignment> {
        self.claims.execution.as_ref()
    }
    /// The normalized policy decision receipt that authorized the lease.
    pub fn decision(&self) -> &PolicyDecision {
        &self.claims.decision
    }
    /// The policy bundle the decision was made under.
    pub fn policy(&self) -> &PolicyBundleId {
        &self.claims.decision.bundle
    }
    /// Digest of the exact policy bundle used for authorization.
    pub fn policy_digest(&self) -> &Digest {
        &self.claims.decision.policy_digest
    }
    /// The runtime generation the decision was made under.
    pub fn runtime(&self) -> &RuntimeGenerationId {
        &self.claims.runtime
    }
    /// The adapter the lease is valid through.
    pub fn adapter(&self) -> &AdapterId {
        &self.claims.adapter
    }
    /// The audiences the lease is valid for.
    pub fn audience(&self) -> &BTreeSet<String> {
        &self.claims.audience
    }
    /// The lease's expiry instant.
    pub fn expires_at(&self) -> Timestamp {
        self.claims.expires_at
    }
    /// The replay domain the lease is bound to.
    pub fn replay_domain(&self) -> &str {
        &self.claims.replay_domain
    }

    /// True when the lease has expired at `now`.
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now >= self.claims.expires_at
    }

    /// True when the lease is valid for `audience`.
    pub fn allows_audience(&self, audience: &str) -> bool {
        self.claims.audience.contains(audience)
    }

    fn claims_digest(claims: &LeaseClaims) -> Result<Digest, RuntimeError> {
        let bytes = serde_json::to_vec(claims).context(LeaseEncodingSnafu)?;
        Ok(Digest::blake3(&bytes))
    }

    fn has_valid_claims_digest(&self) -> Result<bool, RuntimeError> {
        Ok(Self::claims_digest(&self.claims)? == self.claims_digest)
    }

    fn replay_key(&self) -> ReplayKey {
        match (
            self.claims.operation.requires_idempotency,
            self.claims.idempotency_key.as_ref(),
        ) {
            (true, Some(key)) => ReplayKey::Operation {
                principal: self.claims.principal.clone(),
                operation: self.claims.operation.id.clone(),
                key: key.clone(),
            },
            _ => ReplayKey::Lease(self.claims.id.clone()),
        }
    }

    fn reservation_request(&self) -> Result<ReservationRequest, RuntimeError> {
        let replay_key =
            serde_json::to_vec(&(self.claims.replay_domain.as_str(), self.replay_key()))
                .context(LeaseEncodingSnafu)?;
        let mut budget_scopes = Vec::with_capacity(self.claims.delegation_chain.len());
        for delegation in &self.claims.delegation_chain {
            let encoded = serde_json::to_vec(delegation).context(LeaseEncodingSnafu)?;
            budget_scopes.push(BudgetScope::new(
                delegation.id.clone(),
                Digest::blake3(&encoded),
                delegation.budget.clone(),
            ));
        }
        Ok(ReservationRequest::new(
            self.claims.reservation_id.clone(),
            Digest::blake3(&replay_key),
            self.claims.operation.requires_idempotency,
            self.claims.replay_domain.clone(),
            budget_scopes,
            self.claims.budget.clone(),
            self.claims.decision.intent_digest.clone(),
            self.claims.expires_at,
            self.claims_digest.clone(),
        ))
    }
}

/// A move-only invocation capability constructed only by [`Dispatcher`].
///
/// Effect ports remain externally implementable, but callers cannot invoke
/// them without this opaque token. The dispatcher creates it only after lease
/// validation and atomic replay reservation.
///
/// ```compile_fail
/// use politeia_runtime::{AuthorizedEffect, EffectLease};
///
/// fn bypass(lease: &EffectLease) {
///     let _ = AuthorizedEffect {
///         lease,
///         _dispatcher_seal: (),
///     };
/// }
/// ```
pub struct AuthorizedEffect<'lease> {
    lease: &'lease EffectLease,
    _dispatcher_seal: (),
}

impl AuthorizedEffect<'_> {
    /// The exact validated lease authorizing this invocation.
    pub fn lease(&self) -> &EffectLease {
        self.lease
    }
}

/// The policy decision point: evaluates an operation intent and returns a
/// normalized decision.
pub trait PolicyDecisionPoint: Send + Sync {
    /// Policy-engine failure type, distinct from a normalized deny decision.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Decide an operation intent. An error is a failure of evaluation; a
    /// denied decision is `allowed: false`.
    fn decide(
        &self,
        intent: &OperationIntent,
    ) -> impl Future<Output = Result<PolicyDecision, Self::Error>> + Send;
}

/// An effect port reached only through [`Dispatcher::execute`].
pub trait EffectPort: Send + Sync {
    /// Result returned by one successful effect invocation.
    type Output: Send;
    /// Port-specific failure surfaced after the authorization is claimed.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Adapter identity implemented by this effect port.
    fn adapter(&self) -> &AdapterId;

    /// Audience identity implemented by this effect port.
    fn audience(&self) -> &str;

    /// Execute the exact operation and resource claims carried by the opaque
    /// dispatcher-issued invocation capability.
    fn execute<'lease>(
        &'lease self,
        invocation: AuthorizedEffect<'lease>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'lease;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
enum ReplayKey {
    Lease(EffectLeaseId),
    Operation {
        principal: PrincipalId,
        operation: OperationId,
        key: String,
    },
}

fn operation_contract_is_safe(operation: &OperationSpec) -> bool {
    let has_productive_effect = operation.effects.iter().any(|effect| {
        !matches!(
            effect,
            Effect::ReadFilesystem | Effect::ReadSecret | Effect::ReadExternalSystem
        )
    });
    !operation.retryable || !has_productive_effect || operation.requires_idempotency
}

/// Trusted bootstrap inputs for one dispatcher instance.
///
/// Delegations and operation contracts are stored as exact typed values. A
/// request therefore cannot invent an unsigned child delegation or weaken a
/// protected operation's retry/idempotency contract.
pub struct DispatcherConfig {
    policy_bundle: PolicyBundleId,
    policy_digest: Digest,
    runtime: RuntimeGenerationId,
    replay_domain: String,
    max_lease_ttl: SignedDuration,
    trusted_delegations: BTreeMap<DelegationId, Delegation>,
    trusted_operations: BTreeMap<OperationId, OperationSpec>,
    trusted_execution_assignments:
        BTreeMap<politeia_core::RoutingDecisionId, routing::ExecutionAssignment>,
}

impl DispatcherConfig {
    /// Validate and construct trusted dispatcher bootstrap configuration.
    ///
    /// Time: O((d + o) log(d + o)). Space: O(d + o), where d is the
    /// delegation count and o is the operation count.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConfiguration`] for an empty replay
    /// domain, an invalid delegation registry, or an invalid operation
    /// registry.
    #[expect(
        clippy::too_many_arguments,
        reason = "trusted bootstrap binds seven independent security axes"
    )]
    pub fn new(
        policy_bundle: PolicyBundleId,
        policy_digest: Digest,
        runtime: RuntimeGenerationId,
        replay_domain: String,
        max_lease_ttl: SignedDuration,
        trusted_delegations: impl IntoIterator<Item = Delegation>,
        trusted_operations: impl IntoIterator<Item = OperationSpec>,
    ) -> Result<Self, RuntimeError> {
        ensure!(
            !replay_domain.trim().is_empty(),
            InvalidConfigurationSnafu {
                reason: "replay domain is empty"
            }
        );
        ensure!(
            max_lease_ttl > SignedDuration::ZERO,
            InvalidConfigurationSnafu {
                reason: "maximum lease TTL is not positive"
            }
        );
        let mut delegations = BTreeMap::new();
        for delegation in trusted_delegations {
            let duplicate = delegations
                .insert(delegation.id.clone(), delegation)
                .is_some();
            ensure!(
                !duplicate,
                InvalidConfigurationSnafu {
                    reason: "trusted delegation ID is duplicated"
                }
            );
        }
        ensure!(
            !delegations.is_empty(),
            InvalidConfigurationSnafu {
                reason: "no trusted delegations are configured"
            }
        );
        ensure!(
            delegations
                .values()
                .any(|delegation| delegation.parent.is_none()),
            InvalidConfigurationSnafu {
                reason: "delegation registry has no root"
            }
        );
        for delegation in delegations.values() {
            let mut cursor = delegation;
            let mut visited = BTreeSet::new();
            while let Some(parent_id) = cursor.parent.as_ref() {
                ensure!(
                    visited.insert(cursor.id.clone()),
                    InvalidConfigurationSnafu {
                        reason: "delegation registry contains a cycle"
                    }
                );
                let parent = delegations.get(parent_id).ok_or_else(|| {
                    InvalidConfigurationSnafu {
                        reason: "delegation registry names a missing parent",
                    }
                    .build()
                })?;
                ensure!(
                    cursor.issuer == parent.subject,
                    InvalidConfigurationSnafu {
                        reason: "registered child issuer is not the parent subject"
                    }
                );
                ensure!(
                    cursor.is_attenuation_of(parent),
                    InvalidConfigurationSnafu {
                        reason: "registered child delegation widens its parent"
                    }
                );
                cursor = parent;
            }
        }

        let mut operations = BTreeMap::new();
        for operation in trusted_operations {
            ensure!(
                operation_contract_is_safe(&operation),
                InvalidConfigurationSnafu {
                    reason: "retryable productive operation lacks idempotency"
                }
            );
            let duplicate = operations.insert(operation.id.clone(), operation).is_some();
            ensure!(
                !duplicate,
                InvalidConfigurationSnafu {
                    reason: "trusted operation ID is duplicated"
                }
            );
        }
        ensure!(
            !operations.is_empty(),
            InvalidConfigurationSnafu {
                reason: "no trusted operations are configured"
            }
        );
        Ok(Self {
            policy_bundle,
            policy_digest,
            runtime,
            replay_domain,
            max_lease_ttl,
            trusted_delegations: delegations,
            trusted_operations: operations,
            trusted_execution_assignments: BTreeMap::new(),
        })
    }

    /// Admit exact selected routing receipts into trusted bootstrap.
    ///
    /// A caller-provided assignment never becomes authority merely because it
    /// is well-shaped: authorization requires byte-for-byte equality with one
    /// of the selected decisions admitted here.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConfiguration`] for an escalation,
    /// duplicate decision identity, or decision that cannot be digest-bound.
    ///
    /// Time: O(n log n). Space: O(n), where n is admitted decisions.
    pub fn with_trusted_routing_decisions(
        mut self,
        decisions: impl IntoIterator<Item = routing::RoutingDecision>,
    ) -> Result<Self, RuntimeError> {
        for decision in decisions {
            let assignment = decision
                .assignment()
                .map_err(|_| {
                    InvalidConfigurationSnafu {
                        reason: "trusted routing decision cannot be digest-bound",
                    }
                    .build()
                })?
                .ok_or_else(|| {
                    InvalidConfigurationSnafu {
                        reason: "trusted routing decision is an escalation",
                    }
                    .build()
                })?;
            let duplicate = self
                .trusted_execution_assignments
                .insert(assignment.routing_decision.clone(), assignment)
                .is_some();
            ensure!(
                !duplicate,
                InvalidConfigurationSnafu {
                    reason: "trusted routing-decision ID is duplicated"
                }
            );
        }
        Ok(self)
    }
}

/// The single authorization and effect-invocation boundary.
pub struct Dispatcher<P, H, L> {
    policy: P,
    port: H,
    ledger: L,
    config: DispatcherConfig,
    adapter: AdapterId,
}

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
            lease.has_valid_claims_digest()?,
            LeaseMismatchSnafu {
                field: "claims digest"
            }
        );
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

#[cfg(test)]
mod tests;
