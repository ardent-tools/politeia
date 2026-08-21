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

use politeia_core::canonical::{CanonicalError, to_canonical_bytes};
use politeia_core::{
    AdapterId, BudgetReservationId, DataClass, Delegation, DelegationId, Digest, DigestDomain,
    Effect, EffectLeaseId, OperationId, OperationSpec, PolicyBundleId, PrincipalId, ResourceBudget,
    RuntimeGenerationId,
};
use politeia_policy::PolicyDecision;

mod dispatcher;
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
        /// Canonical-encoding failure for the typed lease claims.
        source: CanonicalError,
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
    // See `OperationSpec::execution_requirement`: absence is encoded, not
    // omitted, so that it is covered by the digest. This struct previously
    // carried both conventions at once -- `idempotency_key` emitted null while
    // this field vanished -- in the record whose digest binds policy.
    #[serde(default)]
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
        Digest::of(DigestDomain::OperationIntent, self).context(LeaseEncodingSnafu)
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
/// The private typed claims bind every axis required by the kernel contract.
/// Unforgeability comes from the type, not from a check: both fields are
/// private, the only construction site is [`Dispatcher::authorize`], neither
/// this type nor [`LeaseClaims`] implements `Deserialize`, and the invocation
/// capability that follows is move-only. A lease therefore cannot be built,
/// decoded, or mutated from outside this crate.
///
/// WARNING against adding an in-process integrity check here: the digest and
/// the claims are set together at the one construction site and nothing can
/// change either afterwards, so comparing them can only ever return true. Such
/// a check reads as though it detects substitution while detecting nothing, and
/// crediting it teaches the next reader that the real guarantees above are
/// decorative.
///
/// `claims_digest` is checked where the comparison can fail: it travels in the
/// [`ledger::ReservationRequest`], and `claim` requires the ledger's recorded
/// reservation to equal the one presented. That boundary is a store, possibly
/// in another process, so the two sides can genuinely differ.
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
        Digest::of(DigestDomain::LeaseClaims, claims).context(LeaseEncodingSnafu)
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
            to_canonical_bytes(&(self.claims.replay_domain.as_str(), self.replay_key()))
                .context(LeaseEncodingSnafu)?;
        let mut budget_scopes = Vec::with_capacity(self.claims.delegation_chain.len());
        for delegation in &self.claims.delegation_chain {
            let encoded = to_canonical_bytes(delegation).context(LeaseEncodingSnafu)?;
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

#[cfg(test)]
mod tests;
