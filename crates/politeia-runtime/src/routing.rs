//! Requirement-first execution-resource selection outside the semantic kernel.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use politeia_core::{
    AdapterId, CapabilityProfileId, CapabilityVerificationId, DataClass, Digest, DigestDomain,
    Effect, EvidenceId, ExecutionResourceId, PrincipalId, RoutingDecisionId,
    institution::TrustDomainId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

mod ranking;

use politeia_core::canonical::CanonicalError;
use ranking::compare_resources;

/// Exact identity and provenance shape of something that can execute work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionResourceDescriptor {
    /// A model reached through a named runtime and harness.
    Model {
        /// Provider or operator of the exact model endpoint.
        provider: String,
        /// Exact model/version identity.
        model: String,
        /// Runtime serving the model.
        runtime: String,
        /// Harness mediating the model session.
        harness: String,
    },
    /// A deterministic executable reached through an adapter.
    DeterministicTool {
        /// Digest of the exact executable/tool artifact.
        artifact_digest: Digest,
        /// Tool version label carried as provenance, not capability evidence.
        version: String,
    },
    /// A human principal accepting bounded work.
    Human {
        /// Exact human principal identity.
        principal: PrincipalId,
    },
    /// A specialized service reached through an adapter.
    Service {
        /// Exact service/version identity.
        service: String,
    },
}

/// Trusted, time-bounded verification of one exact capability profile.
///
/// The router accepts these records only through its trusted-bootstrap input
/// and requires an exact identity, digest, subject, and claim match. A profile
/// cannot make its own evidence authoritative by embedding verifier fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityVerificationRecord {
    /// Verification-record identity.
    pub id: CapabilityVerificationId,
    /// Exact profile whose claims were verified.
    pub profile: CapabilityProfileId,
    /// Exact execution resource evaluated.
    pub resource: ExecutionResourceId,
    /// Digest of the immutable resource definition evaluated.
    pub resource_digest: Digest,
    /// Bounded task classes independently observed.
    pub task_classes: BTreeSet<String>,
    /// Named capabilities demonstrated under the verified conditions.
    pub capabilities: BTreeSet<String>,
    /// Trusted verifier principal.
    pub verifier: PrincipalId,
    /// Trusted verifier control domain used for independence judgments.
    pub verifier_control_domain: TrustDomainId,
    /// Exact evidence records on which the profile relies.
    pub evidence: BTreeSet<EvidenceId>,
    /// Time at which the capability evidence was observed.
    pub observed_at: Timestamp,
    /// Time at and after which the profile becomes stale.
    pub expires_at: Timestamp,
}

impl CapabilityVerificationRecord {
    /// Digest the exact trusted verification record for profile admission.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the record cannot be represented.
    ///
    /// Time: O(n). Space: O(n), where n is the encoded record size.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        Digest::of(DigestDomain::CapabilityVerification, self)
    }
}

/// Where an execution resource operates relative to the client trust domain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLocality {
    /// Runs inside the client-controlled local environment.
    ClientLocal,
    /// Runs in a remote environment controlled by the client.
    ClientRemote,
    /// Runs in a remote provider-controlled environment.
    ProviderRemote,
    /// Runs on commissioner-controlled infrastructure.
    CommissionerLocal,
    /// Other explicitly modeled locality.
    Other,
}

/// Immutable identity, boundaries, and cost envelope of one execution resource.
///
/// Live availability is deliberately absent and belongs to a time-bounded
/// [`AvailabilitySnapshot`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResource {
    /// Stable resource identity.
    pub id: ExecutionResourceId,
    /// Exact kind-specific identity and provenance.
    pub descriptor: ExecutionResourceDescriptor,
    /// Adapter/effect boundary through which the selected resource is invoked.
    pub adapter: AdapterId,
    /// Trust domain controlling data and execution.
    pub trust_domain: TrustDomainId,
    /// Control domain used when judging verifier independence.
    pub control_domain: TrustDomainId,
    /// Execution locality.
    pub locality: ExecutionLocality,
    /// Data classes the resource may receive.
    pub allowed_data_classes: BTreeSet<DataClass>,
    /// Effects available to work assigned to the resource.
    pub allowed_effects: BTreeSet<Effect>,
    /// Maximum supported context size in tokens.
    #[schemars(range(max = u64::MAX))]
    pub max_context_tokens: u64,
    /// Estimated cost for the bounded task class, in integer microunits.
    #[schemars(range(max = u64::MAX))]
    pub estimated_cost_microunits: u64,
    /// Estimated latency for the bounded task class, in milliseconds.
    #[schemars(range(max = u64::MAX))]
    pub estimated_latency_ms: u64,
}

impl ExecutionResource {
    /// Digest the canonical immutable resource descriptor and boundaries.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the typed resource cannot be
    /// represented canonically.
    ///
    /// Time: O(n). Space: O(n), where n is the encoded resource size.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        Digest::of(DigestDomain::ExecutionResource, self)
    }
}

/// Evidence-backed capability claim for an exact resource under named conditions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProfile {
    /// Profile identity.
    pub id: CapabilityProfileId,
    /// Resource whose behavior was evaluated.
    pub resource: ExecutionResourceId,
    /// Digest of the exact immutable resource definition evaluated.
    pub resource_digest: Digest,
    /// Bounded task classes independently observed.
    pub task_classes: BTreeSet<String>,
    /// Named capabilities demonstrated under the profile's conditions.
    pub capabilities: BTreeSet<String>,
    /// Trusted verification record that must be resolved before routing.
    pub verification: CapabilityVerificationId,
    /// Digest of that exact trusted verification record.
    pub verification_digest: Digest,
}

impl CapabilityProfile {
    /// Digest the canonical capability profile for routing-decision binding.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the typed profile cannot be
    /// represented canonically.
    ///
    /// Time: O(n). Space: O(n), where n is the encoded profile size.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        Digest::of(DigestDomain::CapabilityProfile, self)
    }
}

/// Time-bounded observation of which registered resources are available.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AvailabilitySnapshot {
    /// Time at which availability was observed.
    pub observed_at: Timestamp,
    /// Time at and after which the snapshot is stale.
    pub expires_at: Timestamp,
    /// Resource identities observed as available.
    pub available_resources: BTreeSet<ExecutionResourceId>,
}

impl AvailabilitySnapshot {
    /// Digest the exact snapshot for routing-decision binding.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the typed snapshot cannot be
    /// represented canonically.
    ///
    /// Time: O(n). Space: O(n), where n is the encoded snapshot size.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        Digest::of(DigestDomain::AvailabilitySnapshot, self)
    }
}

/// Ordered optimization applied only after every hard requirement succeeds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SoftPreference {
    /// Prefer work closer to the client-controlled environment.
    PreferLocal,
    /// Prefer lower estimated monetary cost.
    MinimizeCost,
    /// Prefer lower estimated latency.
    MinimizeLatency,
}

/// Hard constraints and ordered soft preferences for one bounded unit of work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequirement {
    /// Exact bounded task class.
    pub task_class: String,
    /// Capabilities the profile must demonstrate.
    pub required_capabilities: BTreeSet<String>,
    /// Effects the resource boundary must support.
    pub required_effects: BTreeSet<Effect>,
    /// Data classes the resource will receive.
    pub data_classes: BTreeSet<DataClass>,
    /// Hard-allowed localities. Empty means no resource is eligible.
    pub allowed_localities: BTreeSet<ExecutionLocality>,
    /// Hard-allowed trust domains. Empty means no resource is eligible.
    pub allowed_trust_domains: BTreeSet<TrustDomainId>,
    /// Minimum context capacity in tokens.
    #[schemars(range(max = u64::MAX))]
    pub minimum_context_tokens: u64,
    /// Hard maximum cost in microunits.
    #[schemars(range(max = u64::MAX))]
    pub maximum_cost_microunits: Option<u64>,
    /// Hard maximum latency in milliseconds.
    #[schemars(range(max = u64::MAX))]
    pub maximum_latency_ms: Option<u64>,
    /// Require independent verification of the selected work result.
    ///
    /// Capability profiles always require independently admitted evidence;
    /// this separate obligation applies after execution.
    pub require_independent_result_verification: bool,
    /// Require a verified deterministic tool; models and humans are ineligible.
    pub deterministic_only: bool,
    /// Ordered preferences compared lexicographically after hard filtering.
    pub preferences: Vec<SoftPreference>,
}

impl ExecutionRequirement {
    /// Digest the canonical requirement for routing-decision binding.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the typed requirement cannot be
    /// represented canonically.
    ///
    /// Time: O(n). Space: O(n), where n is the encoded requirement size.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        Digest::of(DigestDomain::ExecutionRequirement, self)
    }
}

/// One hard reason a resource was ineligible.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum RoutingRejection {
    /// No capability profile exists for the resource.
    MissingCapabilityProfile,
    /// The profile describes different resource bytes.
    ResourceDigestMismatch,
    /// The resource was not available in the snapshot.
    Unavailable,
    /// The task class was not independently demonstrated.
    UnsupportedTaskClass,
    /// One or more required capabilities are absent.
    MissingCapability,
    /// The resource boundary lacks a required effect.
    MissingEffect,
    /// A data class may not cross into this resource.
    DataClassForbidden,
    /// The resource locality is not allowed.
    LocalityForbidden,
    /// The resource trust domain is not allowed.
    TrustDomainForbidden,
    /// The resource context capacity is too small.
    InsufficientContext,
    /// The hard maximum cost would be exceeded.
    CostExceeded,
    /// The hard latency deadline would be exceeded.
    LatencyExceeded,
    /// Required independent capability evidence is absent.
    IndependentEvidenceMissing,
    /// The named capability verifier is absent from trusted bootstrap or mismatched.
    VerifierNotAdmitted,
    /// Capability evidence is future-dated, empty-lived, or expired.
    StaleCapabilityEvidence,
    /// Resource and verifier share a control domain where independence is required.
    SelfVerifiedCapability,
    /// The task requires a verified deterministic tool.
    DeterministicToolRequired,
}

/// Result of requirement-first routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RoutingOutcome {
    /// One exact resource/profile pair satisfied every hard constraint.
    Selected {
        /// Selected resource identity.
        resource: ExecutionResourceId,
        /// Digest of the exact immutable resource definition.
        resource_digest: Digest,
        /// Adapter/effect boundary registered for the resource.
        adapter: AdapterId,
        /// Trust domain controlling data and execution.
        trust_domain: TrustDomainId,
        /// Control domain used for verifier-independence judgments.
        control_domain: TrustDomainId,
        /// Locality established by the registered resource definition.
        locality: ExecutionLocality,
        /// Selected capability-profile identity.
        capability_profile: CapabilityProfileId,
        /// Digest of the exact selected capability profile.
        capability_profile_digest: Digest,
    },
    /// No resource satisfied every hard constraint; explicit escalation is required.
    #[serde(deserialize_with = "deserialize_routing_outcome_unit")]
    Escalate,
}

fn deserialize_routing_outcome_unit<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct NoFieldsVisitor;

    impl<'de> serde::de::Visitor<'de> for NoFieldsVisitor {
        type Value = ();

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object with no fields")
        }

        fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            if let Some(field) = map.next_key::<String>()? {
                return Err(serde::de::Error::unknown_field(&field, &[]));
            }
            Ok(())
        }
    }

    deserializer.deserialize_map(NoFieldsVisitor)
}

/// Provenance-bearing resource selection or escalation.
///
/// A routing decision contains no delegation or effect grant and therefore
/// cannot authorize the selected resource by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoutingDecision {
    /// Decision identity.
    pub id: RoutingDecisionId,
    /// Digest of the exact execution requirement.
    pub requirement_digest: Digest,
    /// Digest of the exact availability snapshot.
    pub availability_snapshot_digest: Digest,
    /// Snapshot expiry, also bounding any selected assignment.
    pub expires_at: Timestamp,
    /// Selected resource/profile or typed escalation.
    pub outcome: RoutingOutcome,
    /// Every resource that satisfied all hard constraints before ranking.
    pub eligible_resources: BTreeSet<ExecutionResourceId>,
    /// Hard rejection reasons for each ineligible resource.
    pub rejected_resources: BTreeMap<ExecutionResourceId, BTreeSet<RoutingRejection>>,
    /// Exact soft-preference order used to compare eligible resources.
    pub preference_order: Vec<SoftPreference>,
    /// Whether subsequent work requires an independent verifier.
    pub independent_verification_required: bool,
}

/// Exact routing result bound into an operation intent before policy evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAssignment {
    /// Selected execution resource.
    pub resource: ExecutionResourceId,
    /// Digest of the exact selected resource definition.
    pub resource_digest: Digest,
    /// Adapter/effect boundary through which it must be invoked.
    pub adapter: AdapterId,
    /// Trust domain controlling data and execution.
    pub trust_domain: TrustDomainId,
    /// Control domain used for verifier-independence judgments.
    pub control_domain: TrustDomainId,
    /// Selected resource locality.
    pub locality: ExecutionLocality,
    /// Capability profile used to establish eligibility.
    pub capability_profile: CapabilityProfileId,
    /// Digest of that exact capability profile.
    pub capability_profile_digest: Digest,
    /// Routing-decision identity.
    pub routing_decision: RoutingDecisionId,
    /// Exact requirement the selected resource satisfied.
    pub requirement_digest: Digest,
    /// Digest of the full routing receipt.
    pub routing_decision_digest: Digest,
    /// Availability observation on which routing relied.
    pub availability_snapshot_digest: Digest,
    /// Assignment expiry; authorization may narrow but never extend it.
    pub expires_at: Timestamp,
}

impl RoutingDecision {
    /// Digest the exact routing receipt for policy/intent binding.
    ///
    /// # Errors
    ///
    /// Returns the JSON encoding failure if the typed decision cannot be
    /// represented canonically.
    ///
    /// Time: O(n). Space: O(n), where n is the encoded decision size.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        Digest::of(DigestDomain::ExecutionAssignment, self)
    }

    /// Project a selected routing decision into the exact authorization input.
    ///
    /// Escalation has no assignment and therefore cannot enter execution.
    ///
    /// # Errors
    ///
    /// Returns the canonical-encoding failure if the routing decision cannot
    /// be digest-bound.
    pub fn assignment(&self) -> Result<Option<ExecutionAssignment>, CanonicalError> {
        let RoutingOutcome::Selected {
            resource,
            resource_digest,
            adapter,
            trust_domain,
            control_domain,
            locality,
            capability_profile,
            capability_profile_digest,
        } = &self.outcome
        else {
            return Ok(None);
        };
        Ok(Some(ExecutionAssignment {
            resource: resource.clone(),
            resource_digest: resource_digest.clone(),
            adapter: adapter.clone(),
            trust_domain: trust_domain.clone(),
            control_domain: control_domain.clone(),
            locality: locality.clone(),
            capability_profile: capability_profile.clone(),
            capability_profile_digest: capability_profile_digest.clone(),
            routing_decision: self.id.clone(),
            requirement_digest: self.requirement_digest.clone(),
            routing_decision_digest: self.digest()?,
            availability_snapshot_digest: self.availability_snapshot_digest.clone(),
            expires_at: self.expires_at,
        }))
    }
}

/// Routing inputs were ambiguous, stale, duplicated, or could not be encoded.
#[derive(Debug)]
#[non_exhaustive]
pub enum RoutingError {
    /// A resource identity appeared more than once.
    DuplicateResource,
    /// A resource had more than one capability profile in the first-proof registry.
    DuplicateCapabilityProfile,
    /// A capability-profile identity described more than one profile.
    DuplicateCapabilityProfileId,
    /// A verification-record identity appeared more than once in trusted bootstrap.
    DuplicateCapabilityVerification,
    /// The availability observation is future-dated, empty-lived, or expired.
    StaleAvailabilitySnapshot,
    /// The requirement omitted an explicit hard locality or trust-domain set.
    IncompleteHardRequirement,
    /// Canonical digest encoding failed.
    Encoding(CanonicalError),
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateResource => formatter.write_str("duplicate execution-resource identity"),
            Self::DuplicateCapabilityProfile => {
                formatter.write_str("duplicate execution-resource capability profile")
            }
            Self::DuplicateCapabilityProfileId => {
                formatter.write_str("duplicate capability-profile identity")
            }
            Self::DuplicateCapabilityVerification => {
                formatter.write_str("duplicate capability-verification identity")
            }
            Self::StaleAvailabilitySnapshot => {
                formatter.write_str("availability snapshot is invalid or stale")
            }
            Self::IncompleteHardRequirement => {
                formatter.write_str("routing requirement omits locality or trust-domain bounds")
            }
            Self::Encoding(_) => formatter.write_str("routing input cannot be encoded"),
        }
    }
}

impl std::error::Error for RoutingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(source) => Some(source),
            _ => None,
        }
    }
}

/// Deterministic first-proof router.
pub struct Router;

impl Router {
    /// Filter every hard constraint, then rank survivors by ordered preferences.
    ///
    /// A zero-candidate result is an explicit [`RoutingOutcome::Escalate`],
    /// never a best-effort assignment to an ineligible resource.
    /// `trusted_verifications` is a host-bootstrap authority boundary: records
    /// must come from the institution's admitted verification store, never the
    /// work requester or resource being routed.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError`] for duplicate registry identities, a stale
    /// availability snapshot, incomplete hard locality/trust bounds, or a
    /// canonical encoding failure.
    ///
    /// Time: O((r + p + v) log(r + p + v) + r log r), where r is resources,
    /// p is profiles, and v is trusted verification records. Space: O(r + p + v).
    pub fn route(
        requirement: &ExecutionRequirement,
        resources: impl IntoIterator<Item = ExecutionResource>,
        profiles: impl IntoIterator<Item = CapabilityProfile>,
        trusted_verifications: impl IntoIterator<Item = CapabilityVerificationRecord>,
        snapshot: &AvailabilitySnapshot,
        now: Timestamp,
    ) -> Result<RoutingDecision, RoutingError> {
        if requirement.allowed_localities.is_empty() || requirement.allowed_trust_domains.is_empty()
        {
            return Err(RoutingError::IncompleteHardRequirement);
        }
        if snapshot.observed_at > now
            || snapshot.expires_at <= snapshot.observed_at
            || now >= snapshot.expires_at
        {
            return Err(RoutingError::StaleAvailabilitySnapshot);
        }

        let mut resource_registry = BTreeMap::new();
        for resource in resources {
            if resource_registry
                .insert(resource.id.clone(), resource)
                .is_some()
            {
                return Err(RoutingError::DuplicateResource);
            }
        }
        let mut profile_registry = BTreeMap::new();
        let mut profile_ids = BTreeSet::new();
        for profile in profiles {
            if !profile_ids.insert(profile.id.clone()) {
                return Err(RoutingError::DuplicateCapabilityProfileId);
            }
            if profile_registry
                .insert(profile.resource.clone(), profile)
                .is_some()
            {
                return Err(RoutingError::DuplicateCapabilityProfile);
            }
        }
        let mut verification_registry = BTreeMap::new();
        for verification in trusted_verifications {
            if verification_registry
                .insert(verification.id.clone(), verification)
                .is_some()
            {
                return Err(RoutingError::DuplicateCapabilityVerification);
            }
        }

        let requirement_digest = requirement.digest().map_err(RoutingError::Encoding)?;
        let availability_snapshot_digest = snapshot.digest().map_err(RoutingError::Encoding)?;
        let mut rejected_resources = BTreeMap::new();
        let mut eligible = Vec::new();

        for resource in resource_registry.values() {
            let mut reasons = BTreeSet::new();
            let profile = profile_registry.get(&resource.id);
            let mut verification_expires_at = None;
            let mut independently_verified = false;
            if !snapshot.available_resources.contains(&resource.id) {
                reasons.insert(RoutingRejection::Unavailable);
            }
            match profile {
                None => {
                    reasons.insert(RoutingRejection::MissingCapabilityProfile);
                }
                Some(profile) => {
                    let resource_digest = resource.digest().map_err(RoutingError::Encoding)?;
                    if profile.resource_digest != resource_digest {
                        reasons.insert(RoutingRejection::ResourceDigestMismatch);
                    }
                    if !profile.task_classes.contains(&requirement.task_class) {
                        reasons.insert(RoutingRejection::UnsupportedTaskClass);
                    }
                    if !requirement
                        .required_capabilities
                        .is_subset(&profile.capabilities)
                    {
                        reasons.insert(RoutingRejection::MissingCapability);
                    }
                    match verification_registry.get(&profile.verification) {
                        None => {
                            reasons.insert(RoutingRejection::VerifierNotAdmitted);
                        }
                        Some(verification) => {
                            let verification_digest =
                                verification.digest().map_err(RoutingError::Encoding)?;
                            let exact_claim = verification_digest == profile.verification_digest
                                && verification.profile == profile.id
                                && verification.resource == profile.resource
                                && verification.resource_digest == profile.resource_digest
                                && verification.task_classes == profile.task_classes
                                && verification.capabilities == profile.capabilities;
                            if exact_claim {
                                verification_expires_at = Some(verification.expires_at);
                                if verification.evidence.is_empty()
                                    || verification.observed_at > now
                                    || verification.expires_at <= verification.observed_at
                                    || now >= verification.expires_at
                                {
                                    reasons.insert(RoutingRejection::StaleCapabilityEvidence);
                                }
                                let human_self_verification = matches!(
                                    &resource.descriptor,
                                    ExecutionResourceDescriptor::Human { principal }
                                        if principal == &verification.verifier
                                );
                                if verification.verifier_control_domain == resource.control_domain
                                    || human_self_verification
                                {
                                    reasons.insert(RoutingRejection::SelfVerifiedCapability);
                                    reasons.insert(RoutingRejection::IndependentEvidenceMissing);
                                } else {
                                    independently_verified = true;
                                }
                            } else {
                                reasons.insert(RoutingRejection::VerifierNotAdmitted);
                            }
                        }
                    }
                }
            }
            if !requirement
                .required_effects
                .is_subset(&resource.allowed_effects)
            {
                reasons.insert(RoutingRejection::MissingEffect);
            }
            if !requirement
                .data_classes
                .is_subset(&resource.allowed_data_classes)
            {
                reasons.insert(RoutingRejection::DataClassForbidden);
            }
            if !requirement.allowed_localities.contains(&resource.locality) {
                reasons.insert(RoutingRejection::LocalityForbidden);
            }
            if !requirement
                .allowed_trust_domains
                .contains(&resource.trust_domain)
            {
                reasons.insert(RoutingRejection::TrustDomainForbidden);
            }
            if resource.max_context_tokens < requirement.minimum_context_tokens {
                reasons.insert(RoutingRejection::InsufficientContext);
            }
            if requirement
                .maximum_cost_microunits
                .is_some_and(|maximum| resource.estimated_cost_microunits > maximum)
            {
                reasons.insert(RoutingRejection::CostExceeded);
            }
            if requirement
                .maximum_latency_ms
                .is_some_and(|maximum| resource.estimated_latency_ms > maximum)
            {
                reasons.insert(RoutingRejection::LatencyExceeded);
            }
            if requirement.deterministic_only
                && (!matches!(
                    &resource.descriptor,
                    ExecutionResourceDescriptor::DeterministicTool { .. }
                ) || !independently_verified)
            {
                reasons.insert(RoutingRejection::DeterministicToolRequired);
            }

            if reasons.is_empty() {
                if let Some(profile) = profile {
                    eligible.push((resource, profile, verification_expires_at));
                }
            } else {
                rejected_resources.insert(resource.id.clone(), reasons);
            }
        }

        eligible
            .sort_by(|left, right| compare_resources(left.0, right.0, &requirement.preferences));
        let eligible_resources = eligible
            .iter()
            .map(|(resource, _, _)| resource.id.clone())
            .collect();
        let (outcome, expires_at) = if let Some((resource, profile, verification_expiry)) =
            eligible.first()
        {
            (
                RoutingOutcome::Selected {
                    resource: resource.id.clone(),
                    resource_digest: resource.digest().map_err(RoutingError::Encoding)?,
                    adapter: resource.adapter.clone(),
                    trust_domain: resource.trust_domain.clone(),
                    control_domain: resource.control_domain.clone(),
                    locality: resource.locality.clone(),
                    capability_profile: profile.id.clone(),
                    capability_profile_digest: profile.digest().map_err(RoutingError::Encoding)?,
                },
                snapshot
                    .expires_at
                    .min(verification_expiry.unwrap_or(snapshot.expires_at)),
            )
        } else {
            (RoutingOutcome::Escalate, snapshot.expires_at)
        };

        Ok(RoutingDecision {
            id: RoutingDecisionId::new(),
            requirement_digest,
            availability_snapshot_digest,
            expires_at,
            outcome,
            eligible_resources,
            rejected_resources,
            preference_order: requirement.preferences.clone(),
            independent_verification_required: requirement.require_independent_result_verification,
        })
    }
}

#[cfg(test)]
#[path = "routing/tests.rs"]
mod tests;
