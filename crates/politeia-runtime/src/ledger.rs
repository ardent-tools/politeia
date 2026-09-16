//! Shared authorization reservation and replay state.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::Arc,
};

use jiff::Timestamp;
use politeia_core::{
    AdapterId, BudgetReservationId, DelegationId, Digest, ResourceBudget, RuntimeGenerationId,
};
use politeia_policy::DecisionPurpose;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::{RuntimeError, lease_expired, replay_detected};

/// Concrete effect-port identity used when comparing productive effects.
///
/// The adapter and audience are both supplied by the installed effect port.
/// They name the bounded runtime target; constructing this value grants no
/// authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectTarget {
    adapter: AdapterId,
    audience: String,
}

impl EffectTarget {
    pub(crate) fn new(adapter: AdapterId, audience: String) -> Self {
        Self { adapter, audience }
    }

    /// Adapter implementing the concrete effect port.
    pub fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    /// Concrete audience implemented by the effect port.
    pub fn audience(&self) -> &str {
        &self.audience
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "resources", rename_all = "snake_case")]
enum ResourceOverlapScope {
    Named(BTreeSet<String>),
    Unknown,
}

/// Conservative overlap projection for a productive effect.
///
/// Operation identity and effect parameters are deliberately absent. Two
/// writes through the same target potentially overlap when their exact,
/// registered resource identities intersect. An empty or non-concrete resource
/// set is unknown and therefore overlaps every resource on that target. The
/// runtime does not infer filesystem aliases or equivalence outside the
/// resource identities declared by the installed port contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOverlap {
    target: EffectTarget,
    resources: ResourceOverlapScope,
}

impl EffectOverlap {
    pub(crate) fn new(target: EffectTarget, resources: &BTreeSet<String>) -> Self {
        let concrete = !resources.is_empty()
            && resources
                .iter()
                .all(|resource| !resource.is_empty() && resource.trim() == resource);
        Self {
            target,
            resources: if concrete {
                ResourceOverlapScope::Named(resources.clone())
            } else {
                ResourceOverlapScope::Unknown
            },
        }
    }

    /// Concrete port target used by the conservative overlap relation.
    pub fn target(&self) -> &EffectTarget {
        &self.target
    }

    /// True when neither subject proves it addresses disjoint resources.
    pub fn potentially_overlaps(&self, other: &Self) -> bool {
        if self.target != other.target {
            return false;
        }
        match (&self.resources, &other.resources) {
            (ResourceOverlapScope::Named(left), ResourceOverlapScope::Named(right)) => {
                !left.is_disjoint(right)
            }
            (ResourceOverlapScope::Unknown, _) | (_, ResourceOverlapScope::Unknown) => true,
        }
    }
}

/// Canonical identity and conservative overlap projection of one effect.
///
/// The identity binds the full resolved operation and authenticated input. The
/// overlap projection intentionally carries less information so a fresh
/// operation, key, or parameter encoding cannot make an unresolved write look
/// disjoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectSubject {
    identity: Digest,
    overlap: EffectOverlap,
}

impl EffectSubject {
    pub(crate) fn new(identity: Digest, overlap: EffectOverlap) -> Self {
        Self { identity, overlap }
    }

    /// Domain-separated exact effect-subject identity.
    pub fn identity(&self) -> &Digest {
        &self.identity
    }

    /// Conservative relation used to guard unresolved productive effects.
    pub fn overlap(&self) -> &EffectOverlap {
        &self.overlap
    }
}

/// Effect classification recorded atomically with an authorization reservation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "subject", rename_all = "snake_case")]
pub enum EffectReservation {
    /// The operation declares no externally productive effect.
    ReadOnly,
    /// The operation may mutate external state and carries its canonical subject.
    Mutating(EffectSubject),
}

impl EffectReservation {
    /// True when this reservation may conflict with an unresolved claimed effect.
    pub fn potentially_overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Mutating(left), Self::Mutating(right)) => {
                left.overlap().potentially_overlaps(right.overlap())
            }
            (Self::ReadOnly, _) | (_, Self::ReadOnly) => false,
        }
    }
}

/// One delegation budget account participating in a reservation.
///
/// Fields are read-only so only the dispatcher can assemble an admitted
/// root-to-leaf scope, while durable ledger implementations can inspect and
/// serialize it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetScope {
    delegation_id: DelegationId,
    delegation_digest: Digest,
    limit: ResourceBudget,
}

impl BudgetScope {
    pub(crate) fn new(
        delegation_id: DelegationId,
        delegation_digest: Digest,
        limit: ResourceBudget,
    ) -> Self {
        Self {
            delegation_id,
            delegation_digest,
            limit,
        }
    }

    /// The admitted delegation owning this budget account.
    pub fn delegation_id(&self) -> &DelegationId {
        &self.delegation_id
    }

    /// Digest of the exact admitted delegation value.
    pub fn delegation_digest(&self) -> &Digest {
        &self.delegation_digest
    }

    /// Aggregate consumption limit for the delegation.
    pub fn limit(&self) -> &ResourceBudget {
        &self.limit
    }
}

/// Exact state request derived from immutable lease claims.
///
/// `reserve` records this value before a lease is returned. `claim` must see
/// the same value before an effect token is issued, making state substitution
/// fail closed even across dispatcher processes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    reservation_id: BudgetReservationId,
    replay_key: Digest,
    retain_replay: bool,
    effect: EffectReservation,
    replay_domain: String,
    budget_scopes: Vec<BudgetScope>,
    requested_budget: ResourceBudget,
    intent_digest: Digest,
    expires_at: Timestamp,
    claims_digest: Digest,
    runtime_generation: RuntimeGenerationId,
    #[serde(skip_serializing_if = "DecisionPurpose::is_operational")]
    purpose: DecisionPurpose,
}

impl ReservationRequest {
    #[expect(
        clippy::too_many_arguments,
        reason = "the constructor binds the complete durable reservation receipt"
    )]
    pub(crate) fn new(
        reservation_id: BudgetReservationId,
        replay_key: Digest,
        retain_replay: bool,
        effect: EffectReservation,
        replay_domain: String,
        budget_scopes: Vec<BudgetScope>,
        requested_budget: ResourceBudget,
        intent_digest: Digest,
        expires_at: Timestamp,
        claims_digest: Digest,
        runtime_generation: RuntimeGenerationId,
        purpose: DecisionPurpose,
    ) -> Self {
        Self {
            reservation_id,
            replay_key,
            retain_replay,
            effect,
            replay_domain,
            budget_scopes,
            requested_budget,
            intent_digest,
            expires_at,
            claims_digest,
            runtime_generation,
            purpose,
        }
    }

    /// Unique identity of this pending budget reservation.
    pub fn reservation_id(&self) -> &BudgetReservationId {
        &self.reservation_id
    }

    /// Digest identifying a lease replay or semantic idempotency key.
    pub fn replay_key(&self) -> &Digest {
        &self.replay_key
    }

    /// Whether the completed semantic replay identity must be retained durably.
    pub fn retains_replay(&self) -> bool {
        self.retain_replay
    }

    /// Read-only classification or canonical productive effect subject.
    pub fn effect(&self) -> &EffectReservation {
        &self.effect
    }

    /// The isolation domain for replay and budget accounts.
    pub fn replay_domain(&self) -> &str {
        &self.replay_domain
    }

    /// Ordered root-to-leaf delegation budget accounts.
    pub fn budget_scopes(&self) -> &[BudgetScope] {
        &self.budget_scopes
    }

    /// Finite maximum charged if the reservation is claimed.
    pub fn requested_budget(&self) -> &ResourceBudget {
        &self.requested_budget
    }

    /// Digest of the exact operation intent authorized by policy.
    pub fn intent_digest(&self) -> &Digest {
        &self.intent_digest
    }

    /// Expiry of the pending lease and reservation.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Digest of all immutable lease claims.
    pub fn claims_digest(&self) -> &Digest {
        &self.claims_digest
    }

    /// Exact runtime generation that must still govern admission at claim time.
    pub fn runtime_generation(&self) -> &RuntimeGenerationId {
        &self.runtime_generation
    }

    /// Exact admitted purpose copied from the policy decision into the lease.
    pub fn purpose(&self) -> &DecisionPurpose {
        &self.purpose
    }
}

/// Atomic shared state required by the authorization boundary.
///
/// Production implementations persist the same replay domain across process
/// restarts. The ledger owns time observation so expiry is rechecked inside
/// the same atomic boundary that reserves or claims state.
pub trait AuthorizationLedger: Send + Sync {
    /// Observe the ledger's authoritative time for early validation.
    fn observed_at(&self) -> impl Future<Output = Result<Timestamp, RuntimeError>> + Send;

    /// Atomically hold a finite budget across every delegation scope.
    fn reserve(
        &self,
        request: &ReservationRequest,
    ) -> impl Future<Output = Result<(), RuntimeError>> + Send;

    /// Atomically claim the exact reservation, charge its full budget, and
    /// spend its replay key before an effect begins.
    fn claim(
        &self,
        request: &ReservationRequest,
    ) -> impl Future<Output = Result<(), RuntimeError>> + Send;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AccountKey {
    replay_domain: String,
    delegation_id: DelegationId,
}

#[derive(Clone, Copy, Debug, Default)]
struct BudgetTotals {
    wall_ms: u128,
    cpu_ms: u128,
    memory_bytes: u128,
    io_bytes: u128,
    network_bytes: u128,
    external_cost_microunits: u128,
}

impl BudgetTotals {
    fn from_finite(budget: &ResourceBudget) -> Option<Self> {
        Some(Self {
            wall_ms: u128::from(budget.wall_ms?),
            cpu_ms: u128::from(budget.cpu_ms?),
            memory_bytes: u128::from(budget.memory_bytes?),
            io_bytes: u128::from(budget.io_bytes?),
            network_bytes: u128::from(budget.network_bytes?),
            external_cost_microunits: u128::from(budget.external_cost_microunits?),
        })
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            wall_ms: self.wall_ms.checked_add(other.wall_ms)?,
            cpu_ms: self.cpu_ms.checked_add(other.cpu_ms)?,
            memory_bytes: self.memory_bytes.checked_add(other.memory_bytes)?,
            io_bytes: self.io_bytes.checked_add(other.io_bytes)?,
            network_bytes: self.network_bytes.checked_add(other.network_bytes)?,
            external_cost_microunits: self
                .external_cost_microunits
                .checked_add(other.external_cost_microunits)?,
        })
    }

    fn fits_within(self, limit: &ResourceBudget) -> bool {
        fn fits(value: u128, limit: Option<u64>) -> bool {
            limit.is_none_or(|limit| value <= u128::from(limit))
        }

        fits(self.wall_ms, limit.wall_ms)
            && fits(self.cpu_ms, limit.cpu_ms)
            && fits(self.memory_bytes, limit.memory_bytes)
            && fits(self.io_bytes, limit.io_bytes)
            && fits(self.network_bytes, limit.network_bytes)
            && fits(
                self.external_cost_microunits,
                limit.external_cost_microunits,
            )
    }
}

#[derive(Clone, Debug)]
struct Account {
    delegation_digest: Digest,
    limit: ResourceBudget,
    committed: BudgetTotals,
}

#[derive(Debug, Default)]
struct LedgerState {
    observed_at: Option<Timestamp>,
    accounts: BTreeMap<AccountKey, Account>,
    pending: BTreeMap<BudgetReservationId, ReservationRequest>,
    claimed: BTreeMap<BudgetReservationId, EffectReservation>,
    completion_evidence: BTreeMap<BudgetReservationId, Digest>,
    replay: BTreeMap<Digest, Option<Timestamp>>,
}

/// Shared in-memory reference ledger for local development and tests.
///
/// Clones share one atomic state within a process. This implementation is not
/// restart-durable; production hosts must supply a durable
/// [`AuthorizationLedger`] for persistent replay domains.
#[derive(Clone, Debug, Default)]
pub struct InMemoryAuthorizationLedger {
    // WHY: reserve and claim update coupled account, pending, and replay maps
    // as one transaction. The async-aware mutex is never held across a second
    // await, and a read/write split would weaken that atomic boundary.
    state: Arc<Mutex<LedgerState>>,
}

impl InMemoryAuthorizationLedger {
    /// Construct an empty process-local ledger.
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn at(now: Timestamp) -> Self {
        Self {
            state: Arc::new(Mutex::new(LedgerState {
                observed_at: Some(now),
                ..LedgerState::default()
            })),
        }
    }

    #[cfg(test)]
    pub(crate) async fn set_observed_at(&self, now: Timestamp) {
        self.state.lock().await.observed_at = Some(now);
    }

    fn now(state: &LedgerState) -> Timestamp {
        state.observed_at.unwrap_or_else(Timestamp::now)
    }

    fn prune(state: &mut LedgerState, now: Timestamp) {
        state
            .pending
            .retain(|_id, request| request.expires_at > now);
        state.replay.retain(|_key, expires_at| match expires_at {
            Some(expires_at) => *expires_at > now,
            None => true,
        });
    }

    fn pending_for_account(
        state: &LedgerState,
        account_key: &AccountKey,
    ) -> Result<BudgetTotals, RuntimeError> {
        let mut total = BudgetTotals::default();
        for request in state.pending.values() {
            let includes_account = request.budget_scopes.iter().any(|scope| {
                request.replay_domain == account_key.replay_domain
                    && scope.delegation_id == account_key.delegation_id
            });
            if includes_account {
                let requested = BudgetTotals::from_finite(&request.requested_budget).ok_or(
                    RuntimeError::BudgetUnavailable {
                        reason: "pending reservation has an unbounded request",
                    },
                )?;
                total = total
                    .checked_add(requested)
                    .ok_or(RuntimeError::BudgetUnavailable {
                        reason: "pending budget total overflowed",
                    })?;
            }
        }
        Ok(total)
    }

    fn ensure_no_unresolved_overlap(
        state: &LedgerState,
        effect: &EffectReservation,
    ) -> Result<(), RuntimeError> {
        if state
            .claimed
            .values()
            .any(|claimed| effect.potentially_overlaps(claimed))
        {
            return Err(RuntimeError::AmbiguousEffect);
        }
        Ok(())
    }

    /// Record specific outcome evidence and close one claimed in-memory attempt.
    ///
    /// This explicit transition mirrors durable PostgreSQL completion. A port
    /// return does not call it automatically: the caller supplies the digest of
    /// the concrete outcome evidence that resolves the attempt.
    pub async fn record_completion(
        &self,
        reservation_id: &BudgetReservationId,
        outcome_evidence: Digest,
    ) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().await;
        if !state.claimed.contains_key(reservation_id)
            || state.completion_evidence.contains_key(reservation_id)
        {
            return Err(RuntimeError::ReservationMismatch {
                reason: "claimed reservation is missing or already completed",
            });
        }
        state.claimed.remove(reservation_id);
        state
            .completion_evidence
            .insert(reservation_id.clone(), outcome_evidence);
        Ok(())
    }
}

impl AuthorizationLedger for InMemoryAuthorizationLedger {
    async fn observed_at(&self) -> Result<Timestamp, RuntimeError> {
        let state = self.state.lock().await;
        Ok(Self::now(&state))
    }

    async fn reserve(&self, request: &ReservationRequest) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().await;
        let now = Self::now(&state);
        Self::prune(&mut state, now);
        if !request.purpose.is_operational() {
            return Err(RuntimeError::ReservationMismatch {
                reason: "ordinary ledger cannot admit candidate qualification",
            });
        }
        if request.expires_at <= now {
            return Err(lease_expired());
        }
        if !request.requested_budget.is_finite() {
            return Err(RuntimeError::BudgetUnavailable {
                reason: "operation budget is not finite",
            });
        }
        if request.budget_scopes.is_empty() {
            return Err(RuntimeError::ReservationMismatch {
                reason: "reservation has no delegation budget scope",
            });
        }
        if state.pending.contains_key(&request.reservation_id) {
            return Err(RuntimeError::ReservationMismatch {
                reason: "reservation identity already exists",
            });
        }
        if state.replay.contains_key(&request.replay_key)
            || state
                .pending
                .values()
                .any(|pending| pending.replay_key == request.replay_key)
        {
            return Err(replay_detected());
        }
        Self::ensure_no_unresolved_overlap(&state, &request.effect)?;

        let requested = BudgetTotals::from_finite(&request.requested_budget).ok_or(
            RuntimeError::BudgetUnavailable {
                reason: "operation budget is not finite",
            },
        )?;
        for scope in &request.budget_scopes {
            if !request.requested_budget.is_attenuation_of(&scope.limit) {
                return Err(RuntimeError::BudgetUnavailable {
                    reason: "requested budget exceeds a delegation scope",
                });
            }
            let key = AccountKey {
                replay_domain: request.replay_domain.clone(),
                delegation_id: scope.delegation_id.clone(),
            };
            if let Some(account) = state.accounts.get(&key) {
                if account.delegation_digest != scope.delegation_digest
                    || account.limit != scope.limit
                {
                    return Err(RuntimeError::ReservationMismatch {
                        reason: "delegation budget account changed identity or limit",
                    });
                }
            }
            let committed = state
                .accounts
                .get(&key)
                .map_or_else(BudgetTotals::default, |account| account.committed);
            let pending = Self::pending_for_account(&state, &key)?;
            let total = committed
                .checked_add(pending)
                .and_then(|used| used.checked_add(requested))
                .ok_or(RuntimeError::BudgetUnavailable {
                    reason: "reserved budget total overflowed",
                })?;
            if !total.fits_within(&scope.limit) {
                return Err(RuntimeError::BudgetUnavailable {
                    reason: "delegation budget has insufficient remaining capacity",
                });
            }
        }

        for scope in &request.budget_scopes {
            let key = AccountKey {
                replay_domain: request.replay_domain.clone(),
                delegation_id: scope.delegation_id.clone(),
            };
            state.accounts.entry(key).or_insert_with(|| Account {
                delegation_digest: scope.delegation_digest.clone(),
                limit: scope.limit.clone(),
                committed: BudgetTotals::default(),
            });
        }
        state
            .pending
            .insert(request.reservation_id.clone(), request.clone());
        Ok(())
    }

    async fn claim(&self, request: &ReservationRequest) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().await;
        let now = Self::now(&state);
        if !request.purpose.is_operational() {
            return Err(RuntimeError::ReservationMismatch {
                reason: "ordinary ledger cannot claim candidate qualification",
            });
        }
        if request.expires_at <= now {
            Self::prune(&mut state, now);
            return Err(lease_expired());
        }
        Self::prune(&mut state, now);
        let Some(pending) = state.pending.get(&request.reservation_id) else {
            if state.replay.contains_key(&request.replay_key) {
                return Err(replay_detected());
            }
            return Err(RuntimeError::ReservationMismatch {
                reason: "pending reservation is missing",
            });
        };
        if pending != request {
            return Err(RuntimeError::ReservationMismatch {
                reason: "pending reservation does not match the lease",
            });
        }
        Self::ensure_no_unresolved_overlap(&state, &request.effect)?;

        let requested = BudgetTotals::from_finite(&request.requested_budget).ok_or(
            RuntimeError::BudgetUnavailable {
                reason: "operation budget is not finite",
            },
        )?;
        for scope in &request.budget_scopes {
            let key = AccountKey {
                replay_domain: request.replay_domain.clone(),
                delegation_id: scope.delegation_id.clone(),
            };
            let account =
                state
                    .accounts
                    .get_mut(&key)
                    .ok_or(RuntimeError::ReservationMismatch {
                        reason: "delegation budget account is missing",
                    })?;
            account.committed = account.committed.checked_add(requested).ok_or(
                RuntimeError::BudgetUnavailable {
                    reason: "committed budget total overflowed",
                },
            )?;
        }
        state.pending.remove(&request.reservation_id);
        if matches!(request.effect(), EffectReservation::Mutating(_)) {
            state
                .claimed
                .insert(request.reservation_id.clone(), request.effect.clone());
        }
        state.replay.insert(
            request.replay_key.clone(),
            (!request.retain_replay).then_some(request.expires_at),
        );
        Ok(())
    }
}
