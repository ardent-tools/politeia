//! Generation-bound operational policy, routing, and deterministic execution.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::{Future, ready},
};

use jiff::Timestamp;
use politeia_core::canonical::{CanonicalError, to_canonical_bytes};
use politeia_core::{
    AdapterId, BudgetReservationId, CapabilityVerificationId, DataClass, Delegation, Digest,
    Effect, EffectLeaseId, EvidenceId, ExecutionLocality, ExecutionResourceId, InstitutionId,
    InstitutionWorkspaceId, OperationId, OperationSpec, PrincipalId, RoutingDecisionId,
    RuntimeGenerationId,
    evidence::{EvidenceRequest, TrustedEvidenceRegistry},
    trust::{AdmissionKind, Admitted, SignedAdmissionWire},
};
use politeia_evidence::{
    assurance::{
        ActivationProof, AuthorizedControlRun, ControlRun, VERIFY_POLICY_CONTROL_ACTION,
        VerifiedActivation, policy_control_resource,
    },
    authority::{AuthorityContext, DirectGrant, institution_audience},
};
use politeia_policy::operational::{
    OperationalPolicyRegistry, PublicDetectorCalibration, operation_scope,
};
use politeia_policy::{PolicyDecision, evaluate::EvaluationEvidence};
use politeia_runtime::{
    AuthorizationLedger, AuthorizedEffect, Dispatcher, DispatcherConfig, EffectPort,
    OperationIntent, PolicyDecisionPoint,
    routing::{
        AvailabilitySnapshot, CapabilityProfile, CapabilityVerificationRecord, ExecutionAssignment,
        ExecutionRequirement, ExecutionResource, ExecutionResourceDescriptor, Router,
        RoutingDecision, RoutingError,
    },
};
use politeia_storage::{
    CanonicalPayload, EvidenceAdmission, OperationOutboxMessage, PostgresAuthorizationLedger,
    ScopedCommit,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{CoordinatorError, service::PoliteiadService};

/// Stable semantic name of the public deterministic operation in the first slice.
pub const RESOURCE_MANIFEST_OPERATION: &str = "derive_resource_manifest";
/// Exact semantic action implemented by the bounded manifest handler.
pub const RESOURCE_MANIFEST_ACTION: &str = "derive-resource-manifest";
/// Exact completion evidence obligation discharged by the retained receipt.
pub const OPERATION_RECEIPT_OBLIGATION: &str = "operation-receipt";
/// Stable semantic name of approved institutional-context compilation.
pub const COMPILE_CONTEXT_OPERATION: &str = "compile_institutional_context";
/// Stable semantic name of active-generation capability discovery.
pub const DISCOVER_CAPABILITIES_OPERATION: &str = "discover_institutional_capabilities";
/// Stable semantic name of descriptor-bounded source capture under an active generation.
pub const CAPTURE_SOURCE_OPERATION: &str = "capture_authorized_source";
/// Exact direct-owner action that authorizes one capability verification.
pub const VERIFY_EXECUTION_CAPABILITY_ACTION: &str = "verify-execution-capability";
/// Exact signed-evidence method for the reproducible public capability probe.
pub const CAPABILITY_QUALIFICATION_METHOD: &str = "politeia.public-capability-qualification.v1";
/// Exact signed-evidence method for a reproduced public detector calibration.
pub const DETECTOR_CALIBRATION_METHOD: &str = "politeia.public-detector-calibration.v1";
/// Bounded task class demonstrated by the installed local-handler probe.
pub const BOUNDED_LOCAL_OPERATION_TASK_CLASS: &str = "politeia.bounded-local-operation.v1";
/// Capability demonstrated by the installed deterministic manifest probe.
pub const BOUNDED_LOCAL_OPERATION_CAPABILITY: &str = "dispatcher-mediated-deterministic-handler";
/// Known-good public resource exercised by capability qualification.
pub const CAPABILITY_PROBE_KNOWN_GOOD_RESOURCE: &str = "public:capability-probe";

/// Derive the singleton delegation resource for an exact capability verification.
///
/// # Errors
///
/// Returns a canonical error when the verification record cannot be digested.
pub fn capability_verification_resource(
    verification: &CapabilityVerificationRecord,
) -> Result<String, CanonicalError> {
    verification
        .digest()
        .map(|digest| format!("capability-verification:{}", digest.as_str()))
}

/// Signed, currently delegated proof behind one declared capability verification.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityVerificationEvidence {
    /// Exact verifier-signed record declared by the execution registry.
    pub verification: SignedAdmissionWire<CapabilityVerificationRecord>,
    /// Current direct owner grant for this exact verification digest.
    pub authority: SignedAdmissionWire<Delegation>,
}

/// Reproducible public qualification behind one capability verification.
///
/// The local case contains the actual output of the installed deterministic
/// manifest algorithm and an input that must cross its declared count bound.
/// An ineligible reference resource may declare no executable claims; that
/// empty claim is retained explicitly rather than dressing metadata up as a
/// successful probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityQualificationEvidence {
    /// Qualification payload schema.
    pub schema: String,
    /// Exact verification record whose claims this payload demonstrates.
    pub verification: CapabilityVerificationId,
    /// Immutable resource definition covered by the verification.
    pub resource: ExecutionResource,
    /// Exact profile whose claims are copied into the verification record.
    pub profile: CapabilityProfile,
    /// Concrete probe result, or an explicit absence of executable claims.
    pub probe: CapabilityQualificationProbe,
}

/// Actual public probe retained by capability qualification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityQualificationProbe {
    /// The deterministic resource-manifest handler accepted a known-good input
    /// and refused an input just beyond its declared resource-count bound.
    ResourceManifest {
        /// Exact registered handler contract exercised by the probe.
        operation: Box<RegisteredOperation>,
        /// Public known-good input supplied to the real manifest algorithm.
        known_good_resources: BTreeSet<String>,
        /// Actual deterministic output observed for the known-good input.
        known_good_manifest: ResourceManifest,
        /// Public planted input that exceeds the handler's count bound.
        planted_resources: BTreeSet<String>,
        /// Typed refusal returned by the real algorithm for the planted input.
        planted_refusal: ResourceManifestProbeRefusal,
    },
    /// This profile deliberately asserts no task class or capability.
    NoExecutableClaims,
}

/// A stable refusal produced by the public manifest qualification algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceManifestProbeRefusal {
    /// The input contains more resource identities than the handler permits.
    ResourceCountExceeded,
    /// The input contains more UTF-8 resource bytes than the handler permits.
    ResourceBytesExceeded,
    /// A platform integer boundary prevented a faithful size calculation.
    SizeUnrepresentable,
}

/// Capability-specific evidence admission carried by commissioning transport.
///
/// This cannot insert arbitrary evidence: the daemon re-admits the exact
/// verification and grant, reproduces `qualification`, and accepts only the
/// evidence IDs and producer binding named by that verification.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEvidenceSubmission {
    /// Verifier-signed capability record later declared by a generation.
    pub verification: SignedAdmissionWire<CapabilityVerificationRecord>,
    /// Already admitted direct owner grant for this exact verification digest.
    pub authority: SignedAdmissionWire<Delegation>,
    /// Signed evidence records whose IDs exactly equal `verification.evidence`.
    pub evidence: Vec<SignedAdmissionWire<EvidenceRequest>>,
    /// Public probe payload whose canonical digest every evidence record signs.
    pub qualification: CapabilityQualificationEvidence,
}

/// Narrow commissioning input for one reproduced public detector calibration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectorCalibrationEvidenceSubmission {
    /// Exact canonical policy artifact under the owner-signed workspace digest.
    pub policy_bytes: Vec<u8>,
    /// Actual known-good and planted-violation detector output.
    pub calibration: PublicDetectorCalibration,
    /// Already admitted direct owner grant for verifying this exact control.
    pub authority: SignedAdmissionWire<Delegation>,
    /// Verifier-signed retained evidence for this exact calibration digest.
    pub evidence: SignedAdmissionWire<EvidenceRequest>,
}

/// Signed assurance material accompanying one principal-authenticated operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationalControlEvidence {
    /// Public detector output signed by its independently delegated producer.
    pub run: SignedAdmissionWire<ControlRun>,
    /// Exact durable direct grant under which the producer ran the detector.
    pub run_authority: SignedAdmissionWire<Delegation>,
    /// Known-good and planted-violation exercise signed by another verifier.
    pub activation: SignedAdmissionWire<ActivationProof>,
    /// Exact durable direct grant under which that verifier attested activation.
    pub activation_authority: SignedAdmissionWire<Delegation>,
}

/// Complete untrusted ingress document for one active-generation operation.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationSubmission {
    /// Exact operation intent signed by the requesting principal.
    pub intent: SignedAdmissionWire<OperationIntent>,
    /// Time-bounded availability observation used by requirement-first routing.
    pub availability: AvailabilitySnapshot,
    /// Claimed routing receipt; every field except its inert ID is recomputed.
    pub routing: RoutingDecision,
    /// Signed and currently delegated evidence for every capability claim used by routing.
    pub capability_verifications: Vec<CapabilityVerificationEvidence>,
    /// Complete independently authorized control evidence required by policy.
    pub assurance: Vec<OperationalControlEvidence>,
}

/// Deterministic output of the installed bounded manifest operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceManifest {
    /// Exact operation contract whose local handler produced this artifact.
    pub operation: OperationId,
    /// Canonically ordered resource identities covered by the artifact.
    pub resources: Vec<String>,
    /// Number of exact resource identities covered.
    pub resource_count: u32,
    /// Digest of the canonical manifest subject.
    pub manifest_digest: Digest,
}

/// Honest terminal state retained in a daemon-derived unsigned receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationCompletionOutcome {
    /// The protected local port returned a concrete manifest.
    Succeeded {
        /// Exact deterministic port result.
        manifest: ResourceManifest,
    },
}

/// Canonical, unsigned receipt derived from signed inputs and a consumed lease.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReceipt {
    /// Receipt schema identity.
    pub schema: String,
    /// Unique identity of this immutable completion record.
    pub id: Uuid,
    /// Institution under which the operation ran.
    pub institution: InstitutionId,
    /// Workspace under which the operation ran.
    pub workspace: InstitutionWorkspaceId,
    /// Exact active generation checked again at reservation and claim.
    pub generation: RuntimeGenerationId,
    /// Unique dispatcher lease consumed immediately before the effect.
    pub lease: EffectLeaseId,
    /// Durable budget reservation completed by this receipt.
    pub reservation: BudgetReservationId,
    /// Original principal-signed intent wire.
    pub intent: SignedAdmissionWire<OperationIntent>,
    /// Normalized decision returned by the active generation's policy.
    pub decision: PolicyDecision,
    /// Recomputed requirement-first routing receipt.
    pub routing: RoutingDecision,
    /// Exact availability input bound into routing.
    pub availability: AvailabilitySnapshot,
    /// Signed capability-verification claims and their exact live owner grants.
    pub capability_verifications: Vec<CapabilityVerificationEvidence>,
    /// Signed detector and activation evidence consumed by policy.
    pub assurance: Vec<OperationalControlEvidence>,
    /// Selected resource assignment bound into the signed intent and lease.
    pub execution: ExecutionAssignment,
    /// Installed adapter reached only through the dispatcher.
    pub adapter: AdapterId,
    /// Trusted database instant observed after the protected port returned.
    pub completed_at: Timestamp,
    /// Concrete terminal result; missing effect completion remains no receipt.
    pub outcome: OperationCompletionOutcome,
}

/// Typed response projection for a durably completed operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationCompletion {
    /// Immutable receipt identity.
    pub receipt: Uuid,
    /// Digest of the exact canonical receipt bytes retained in PostgreSQL.
    pub receipt_digest: Digest,
    /// Durable reservation transitioned from claimed to completed.
    pub reservation: BudgetReservationId,
    /// Exact active generation under which the operation was admitted.
    pub generation: RuntimeGenerationId,
    /// Full recomputed routing receipt, including hard rejections.
    pub routing: RoutingDecision,
    /// Deterministic bounded operation result.
    pub manifest: ResourceManifest,
    /// Transactional outbox identity committed with the receipt.
    pub outbox: Uuid,
}

/// The installed public service handler bound to one exact operation contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstalledOperationHandler {
    /// Derive a deterministic manifest over the exact authorized resource set.
    ResourceManifest {
        /// Maximum resource identities accepted by the bounded handler.
        maximum_resources: u32,
        /// Maximum total UTF-8 bytes accepted across resource identities.
        maximum_resource_bytes: u64,
    },
    /// Compile authority-filtered institutional context.
    #[serde(deserialize_with = "deserialize_handler_unit")]
    CompileInstitutionalContext,
    /// Discover authority-filtered active-generation capabilities.
    #[serde(deserialize_with = "deserialize_handler_unit")]
    DiscoverInstitutionalCapabilities,
    /// Capture one descriptor-bounded source through the active dispatcher.
    #[serde(deserialize_with = "deserialize_handler_unit")]
    CaptureAuthorizedSource,
}

fn deserialize_handler_unit<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct NoFields;
    impl<'de> serde::de::Visitor<'de> for NoFields {
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
    deserializer.deserialize_map(NoFields)
}

impl InstalledOperationHandler {
    fn operation_name(&self) -> &'static str {
        match self {
            Self::ResourceManifest { .. } => RESOURCE_MANIFEST_OPERATION,
            Self::CompileInstitutionalContext => COMPILE_CONTEXT_OPERATION,
            Self::DiscoverInstitutionalCapabilities => DISCOVER_CAPABILITIES_OPERATION,
            Self::CaptureAuthorizedSource => CAPTURE_SOURCE_OPERATION,
        }
    }
}

/// One exact operation, hard routing requirement, and installed handler binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisteredOperation {
    /// Canonical semantic operation contract.
    pub spec: OperationSpec,
    /// Hard eligibility and ordered preference contract for execution routing.
    pub requirement: ExecutionRequirement,
    /// Public service implementation selected by this generation.
    pub handler: InstalledOperationHandler,
}

/// Why an installed deterministic handler cannot be bound to this daemon.
#[derive(Debug, PartialEq, Eq)]
pub enum ExecutableIdentityRefusal {
    /// The approved generation/workspace executable is not the daemon image.
    ApprovedExecutableMismatch,
    /// A deterministic resource names a different executable than approved.
    DescriptorExecutableMismatch,
}

impl std::fmt::Display for ExecutableIdentityRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApprovedExecutableMismatch => formatter.write_str(
                "approved executable component differs from the running daemon executable",
            ),
            Self::DescriptorExecutableMismatch => formatter.write_str(
                "deterministic resource descriptor differs from the approved daemon executable",
            ),
        }
    }
}

impl std::error::Error for ExecutableIdentityRefusal {}

fn validate_approved_executable_identity(
    approved: &Digest,
    running: &Digest,
) -> Result<(), ExecutableIdentityRefusal> {
    if approved != running {
        return Err(ExecutableIdentityRefusal::ApprovedExecutableMismatch);
    }
    Ok(())
}

fn validate_builtin_descriptor_identity(
    descriptor: &ExecutionResourceDescriptor,
    approved: &Digest,
) -> Result<(), ExecutableIdentityRefusal> {
    match descriptor {
        ExecutionResourceDescriptor::DeterministicTool {
            artifact_digest, ..
        } if artifact_digest == approved => Ok(()),
        _ => Err(ExecutableIdentityRefusal::DescriptorExecutableMismatch),
    }
}

impl CapabilityQualificationEvidence {
    /// Execute and capture the public qualification implied by exact registry
    /// objects.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityQualificationRefusal`] when the profile does not
    /// exactly bind the verification/resource or when its executable claims
    /// cannot be demonstrated by the installed deterministic handler.
    pub fn reproduce(
        verification: &CapabilityVerificationRecord,
        resource: &ExecutionResource,
        profile: &CapabilityProfile,
        manifest_operation: Option<&RegisteredOperation>,
    ) -> Result<Self, CapabilityQualificationRefusal> {
        validate_profile_binding(verification, resource, profile)?;
        let probe = if profile.task_classes.is_empty() && profile.capabilities.is_empty() {
            if manifest_operation.is_some() {
                return Err(CapabilityQualificationRefusal::UnexpectedManifestOperation);
            }
            CapabilityQualificationProbe::NoExecutableClaims
        } else {
            if profile.task_classes
                != BTreeSet::from([BOUNDED_LOCAL_OPERATION_TASK_CLASS.to_string()])
                || profile.capabilities
                    != BTreeSet::from([BOUNDED_LOCAL_OPERATION_CAPABILITY.to_string()])
                || !matches!(
                    &resource.descriptor,
                    ExecutionResourceDescriptor::DeterministicTool { .. }
                )
            {
                return Err(CapabilityQualificationRefusal::UnsupportedExecutableClaim);
            }
            let operation = manifest_operation
                .ok_or(CapabilityQualificationRefusal::ManifestOperationAbsent)?;
            let InstalledOperationHandler::ResourceManifest {
                maximum_resources,
                maximum_resource_bytes,
            } = &operation.handler
            else {
                return Err(CapabilityQualificationRefusal::ManifestOperationMismatch);
            };
            let known_good_resources =
                BTreeSet::from([CAPABILITY_PROBE_KNOWN_GOOD_RESOURCE.to_string()]);
            let known_good_manifest = derive_resource_manifest(
                &operation.spec,
                &known_good_resources,
                *maximum_resources,
                *maximum_resource_bytes,
            )?;
            let planted_count = maximum_resources
                .checked_add(1)
                .ok_or(CapabilityQualificationRefusal::ProbePopulationTooLarge)?;
            if planted_count > 1_024 {
                return Err(CapabilityQualificationRefusal::ProbePopulationTooLarge);
            }
            let planted_resources = (0..planted_count)
                .map(|index| format!("public:capability-probe:{index:04}"))
                .collect();
            let Err(planted_refusal) = derive_resource_manifest(
                &operation.spec,
                &planted_resources,
                *maximum_resources,
                *maximum_resource_bytes,
            ) else {
                return Err(CapabilityQualificationRefusal::ManifestOperationMismatch);
            };
            CapabilityQualificationProbe::ResourceManifest {
                operation: Box::new(operation.clone()),
                known_good_resources,
                known_good_manifest,
                planted_resources,
                planted_refusal,
            }
        };
        Ok(Self {
            schema: "politeia.capability-qualification.v1".to_string(),
            verification: verification.id.clone(),
            resource: resource.clone(),
            profile: profile.clone(),
            probe,
        })
    }

    /// Canonical digest signed by every evidence record for this qualification.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if the typed payload cannot be encoded.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        to_canonical_bytes(self).map(|bytes| Digest::blake3(&bytes))
    }
}

/// Authority-neutral capability view derived from an execution registry.
///
/// A learning coordinator must still filter this inventory through the
/// requester's admitted context authority before disclosing it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCapabilityInventory {
    /// Exact registered operation and requirement contracts.
    pub operations: Vec<RegisteredOperation>,
    /// Exact execution resources considered by routing.
    pub resources: Vec<ExecutionResource>,
    /// Evidence-backed profiles for those resources.
    pub profiles: Vec<CapabilityProfile>,
    /// Exact verification claims declared by the generation. Active routing
    /// separately requires their signed admission, live authority, and retained evidence.
    pub verifications: Vec<CapabilityVerificationRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct OperationalExecutionDocument {
    operations: Vec<RegisteredOperation>,
    resources: Vec<ExecutionResource>,
    profiles: Vec<CapabilityProfile>,
    verifications: Vec<CapabilityVerificationRecord>,
    available_resources: BTreeSet<ExecutionResourceId>,
}

/// Capability records admitted from installed signatures, current authority,
/// and durable evidence for one trusted routing decision.
///
/// This type has no public constructor or deserializer. Receiving the same
/// record metadata as the generation declares cannot construct routing trust.
#[derive(Clone, Debug)]
pub struct AdmittedCapabilityVerifications {
    records: Vec<CapabilityVerificationRecord>,
    authority_expires_at: Timestamp,
}

/// Immutable typed execution registry decoded from one verified generation.
#[derive(Clone, Debug)]
pub struct OperationalExecutionRegistry {
    document: OperationalExecutionDocument,
    digest: Digest,
}

impl OperationalExecutionRegistry {
    /// Normalize and validate exact registry inputs, then derive canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalRegistryRefusal`] for duplicate or incomplete
    /// identities, mismatched evidence, unsupported handler contracts, or a
    /// canonical encoding failure.
    pub fn new(
        mut operations: Vec<RegisteredOperation>,
        mut resources: Vec<ExecutionResource>,
        mut profiles: Vec<CapabilityProfile>,
        mut verifications: Vec<CapabilityVerificationRecord>,
        available_resources: BTreeSet<ExecutionResourceId>,
    ) -> Result<Self, OperationalRegistryRefusal> {
        operations.sort_by(|left, right| left.spec.name.cmp(&right.spec.name));
        resources.sort_by(|left, right| left.id.cmp(&right.id));
        profiles.sort_by(|left, right| left.id.cmp(&right.id));
        verifications.sort_by(|left, right| left.id.cmp(&right.id));
        let document = OperationalExecutionDocument {
            operations,
            resources,
            profiles,
            verifications,
            available_resources,
        };
        validate_execution_document(&document)?;
        let bytes = to_canonical_bytes(&document).map_err(OperationalRegistryRefusal::Canonical)?;
        Ok(Self {
            document,
            digest: Digest::blake3(&bytes),
        })
    }

    /// Decode exact artifact bytes only when their digest and canonical typed
    /// representation match the generation.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalRegistryRefusal`] for a substituted, malformed,
    /// noncanonical, or internally inconsistent document.
    pub fn from_artifact_bytes(
        bytes: &[u8],
        expected_digest: &Digest,
    ) -> Result<Self, OperationalRegistryRefusal> {
        if &Digest::blake3(bytes) != expected_digest {
            return Err(OperationalRegistryRefusal::ExecutionDigestMismatch);
        }
        let document: OperationalExecutionDocument = serde_json::from_slice(bytes)
            .map_err(|error| OperationalRegistryRefusal::Encoding(error.to_string()))?;
        validate_execution_document(&document)?;
        let canonical =
            to_canonical_bytes(&document).map_err(OperationalRegistryRefusal::Canonical)?;
        if canonical != bytes {
            return Err(OperationalRegistryRefusal::NonCanonicalArtifact);
        }
        Ok(Self {
            document,
            digest: expected_digest.clone(),
        })
    }

    /// Return canonical artifact bytes for generation publication.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding error if the admitted document cannot be represented.
    pub fn artifact_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        to_canonical_bytes(&self.document)
    }

    /// Digest of the exact canonical registry artifact.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Resolve one stable operation name from this generation.
    pub fn operation_named(&self, name: &str) -> Option<&RegisteredOperation> {
        self.document
            .operations
            .binary_search_by(|operation| operation.spec.name.as_str().cmp(name))
            .ok()
            .map(|index| &self.document.operations[index])
    }

    /// Resolve and compare an exact caller-presented operation contract.
    pub fn exact_operation(&self, operation: &OperationSpec) -> Option<&RegisteredOperation> {
        self.operation_named(&operation.name)
            .filter(|registered| registered.spec == *operation)
    }

    /// Return the authority-neutral capability inventory for filtered discovery.
    pub fn capability_inventory(&self) -> ExecutionCapabilityInventory {
        ExecutionCapabilityInventory {
            operations: self.document.operations.clone(),
            resources: self.document.resources.clone(),
            profiles: self.document.profiles.clone(),
            verifications: self.document.verifications.clone(),
        }
    }

    /// Exact resource identities the installed generation declares reachable.
    pub fn available_resources(&self) -> &BTreeSet<ExecutionResourceId> {
        &self.document.available_resources
    }

    /// Resolve one exact execution resource from this generation.
    pub fn resource(&self, id: &ExecutionResourceId) -> Option<&ExecutionResource> {
        self.document
            .resources
            .binary_search_by(|resource| resource.id.cmp(id))
            .ok()
            .map(|index| &self.document.resources[index])
    }

    /// Reproduce the public qualification expected for one declared
    /// capability verification.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityQualificationRefusal`] if registry identities do
    /// not bind exactly or the executable claim cannot reproduce its probe.
    pub fn capability_qualification(
        &self,
        verification: &CapabilityVerificationRecord,
    ) -> Result<CapabilityQualificationEvidence, CapabilityQualificationRefusal> {
        let profile = self
            .document
            .profiles
            .iter()
            .find(|profile| profile.verification == verification.id)
            .ok_or(CapabilityQualificationRefusal::ProfileAbsent)?;
        let resource = self
            .resource(&verification.resource)
            .ok_or(CapabilityQualificationRefusal::ResourceAbsent)?;
        let manifest = (!profile.task_classes.is_empty() || !profile.capabilities.is_empty())
            .then(|| self.operation_named(RESOURCE_MANIFEST_OPERATION))
            .flatten();
        CapabilityQualificationEvidence::reproduce(verification, resource, profile, manifest)
    }

    /// Reproduce a routing decision with a caller-selected inert identity.
    ///
    /// The caller selects only the receipt identity so it can sign the resulting
    /// assignment. Every eligibility, rejection, selection, and expiry field is
    /// recomputed from the generation registry and exact availability snapshot.
    ///
    /// # Errors
    ///
    /// Returns a refusal when the operation is not exact, the availability set
    /// differs from the generation declaration, or requirement-first routing fails.
    pub fn route_with_id(
        &self,
        operation: &OperationSpec,
        decision_id: RoutingDecisionId,
        snapshot: &AvailabilitySnapshot,
        admitted_verifications: &AdmittedCapabilityVerifications,
        now: Timestamp,
    ) -> Result<RoutingDecision, OperationalRegistryRefusal> {
        let registered = self
            .exact_operation(operation)
            .ok_or(OperationalRegistryRefusal::UnknownOperation)?;
        if snapshot.available_resources != self.document.available_resources {
            return Err(OperationalRegistryRefusal::AvailabilityMismatch);
        }
        if admitted_verifications.records != self.document.verifications {
            return Err(OperationalRegistryRefusal::CapabilityBindingMismatch);
        }
        let mut decision = Router::route(
            &registered.requirement,
            self.document.resources.clone(),
            self.document.profiles.clone(),
            admitted_verifications.records.clone(),
            snapshot,
            now,
        )
        .map_err(OperationalRegistryRefusal::Routing)?;
        decision.id = decision_id;
        Ok(decision)
    }
}

/// Policy and execution semantics loaded from one exact active generation.
#[derive(Clone, Debug)]
pub struct ActiveOperationalRegistry {
    generation: RuntimeGenerationId,
    policy: OperationalPolicyRegistry,
    execution: OperationalExecutionRegistry,
}

impl ActiveOperationalRegistry {
    fn new(
        generation: RuntimeGenerationId,
        policy: OperationalPolicyRegistry,
        execution: OperationalExecutionRegistry,
        executable_digest: &Digest,
    ) -> Result<Self, OperationalRegistryRefusal> {
        let operation_scopes: BTreeSet<_> = execution
            .document
            .operations
            .iter()
            .map(|operation| operation_scope(&operation.spec))
            .collect();
        let policy_scopes: BTreeSet<_> = policy
            .bindings()
            .iter()
            .map(|binding| binding.scope.clone())
            .collect();
        if operation_scopes != policy_scopes {
            return Err(OperationalRegistryRefusal::PolicyCoverageMismatch);
        }
        for resource in &execution.document.resources {
            if matches!(
                resource.descriptor,
                ExecutionResourceDescriptor::DeterministicTool { .. }
            ) {
                validate_builtin_descriptor_identity(&resource.descriptor, executable_digest)
                    .map_err(OperationalRegistryRefusal::ExecutableIdentity)?;
            }
        }
        Ok(Self {
            generation,
            policy,
            execution,
        })
    }

    /// Exact active runtime-generation identity.
    pub fn generation(&self) -> &RuntimeGenerationId {
        &self.generation
    }

    /// Policy decoded from this generation's freshly verified bytes.
    pub fn policy(&self) -> &OperationalPolicyRegistry {
        &self.policy
    }

    /// Execution registry decoded from this generation's freshly verified bytes.
    pub fn execution(&self) -> &OperationalExecutionRegistry {
        &self.execution
    }
}

/// Fully admitted active-operation inputs ready for one shared Dispatcher.
///
/// Construction is private to the service admission path. Adjacent typed
/// handlers may inspect the exact bound values and supply their own installed
/// effect port without repeating policy, capability, routing, or grant logic.
pub(crate) struct AdmittedOperationalSubmission {
    registry: ActiveOperationalRegistry,
    registered: RegisteredOperation,
    signed_intent: SignedAdmissionWire<OperationIntent>,
    intent: Admitted<OperationIntent>,
    operation_chain: Vec<Delegation>,
    policy: AdmittedOperationalDecision,
    availability: AvailabilitySnapshot,
    routing: RoutingDecision,
    assignment: ExecutionAssignment,
    capability_verifications: Vec<CapabilityVerificationEvidence>,
    assurance: Vec<OperationalControlEvidence>,
    admission_revision: i64,
    admitted_at: Timestamp,
    authorization_expires_at: Timestamp,
}

impl AdmittedOperationalSubmission {
    /// Exact active registry from freshly reverified generation bytes.
    pub(crate) fn registry(&self) -> &ActiveOperationalRegistry {
        &self.registry
    }

    /// Registered operation and installed handler named by the signed intent.
    pub(crate) fn registered(&self) -> &RegisteredOperation {
        &self.registered
    }

    /// Authenticated operation intent supplied to Dispatcher authorization.
    pub(crate) fn intent(&self) -> &OperationIntent {
        self.intent.payload()
    }

    /// Normalized active-policy decision for the exact admitted intent.
    pub(crate) fn decision(&self) -> &PolicyDecision {
        self.policy.decision()
    }

    /// Original signed intent retained in completion evidence.
    pub(crate) fn signed_intent(&self) -> &SignedAdmissionWire<OperationIntent> {
        &self.signed_intent
    }

    /// Recomputed exact routing decision.
    pub(crate) fn routing(&self) -> &RoutingDecision {
        &self.routing
    }

    /// Selected resource assignment bound by the signed intent.
    pub(crate) fn assignment(&self) -> &ExecutionAssignment {
        &self.assignment
    }

    /// Availability snapshot bound by the routing receipt.
    pub(crate) fn availability(&self) -> &AvailabilitySnapshot {
        &self.availability
    }

    /// Signed capability evidence admitted before routing.
    pub(crate) fn capability_verifications(&self) -> &[CapabilityVerificationEvidence] {
        &self.capability_verifications
    }

    /// Signed public-control evidence admitted before policy evaluation.
    pub(crate) fn assurance(&self) -> &[OperationalControlEvidence] {
        &self.assurance
    }

    /// Durable revision from the coherent selection/admission snapshot.
    pub(crate) fn admission_revision(&self) -> i64 {
        self.admission_revision
    }

    /// Build the only dispatcher configuration for these admitted inputs.
    pub(crate) fn dispatcher<P: EffectPort>(
        &self,
        port: P,
        ledger: PostgresAuthorizationLedger,
    ) -> Result<
        Dispatcher<AdmittedOperationalDecision, P, PostgresAuthorizationLedger>,
        CoordinatorError,
    > {
        let maximum_ttl = jiff::SignedDuration::from_mins(5).min(
            self.authorization_expires_at
                .duration_since(self.admitted_at),
        );
        let config = DispatcherConfig::new(
            self.registry.policy().bundle().clone(),
            self.registry.policy().digest().clone(),
            self.registry.generation().clone(),
            format!(
                "operational:{}",
                self.registry.generation().digest().as_str()
            ),
            maximum_ttl,
            self.operation_chain.clone(),
            [self.registered.spec.clone()],
        )
        .and_then(|config| config.with_trusted_routing_decisions([self.routing.clone()]))
        .map_err(operational_refusal)?;
        Ok(Dispatcher::new(
            self.policy.clone(),
            port,
            ledger.with_workspace_revision(self.admission_revision),
            config,
        ))
    }
}

impl PoliteiadService {
    /// Load the sole active-generation pointer, reverify the immutable bundle,
    /// and decode its exact canonical operational registries.
    pub(crate) async fn active_operational_registry(
        &self,
    ) -> Result<ActiveOperationalRegistry, CoordinatorError> {
        let active = self
            .storage()
            .load_active_generation(self.scope())
            .await
            .map_err(|error| operational_refusal(error.to_string()))?
            .ok_or_else(|| operational_refusal("no runtime generation is active"))?;
        self.operational_registry_for_generation(&active).await
    }

    /// Reverify and decode one exact generation selected by a coherent durable snapshot.
    pub(crate) async fn operational_registry_for_generation(
        &self,
        active: &Digest,
    ) -> Result<ActiveOperationalRegistry, CoordinatorError> {
        let artifact = self.verified_generation(active).await?;
        let generation = artifact.generation();
        if generation.id().digest() != active {
            return Err(operational_refusal(
                "active generation identity differs from its verified artifact",
            ));
        }
        let inputs = generation.inputs();
        let executable_digest = inputs
            .approved
            .component_digests
            .get("executable")
            .ok_or_else(|| operational_refusal("generation has no executable component"))?
            .clone();
        // Reread and rehash the exact component now, rather than accepting the
        // immutable bundle verification from an earlier filesystem read.
        artifact
            .component_bytes("executable")
            .map_err(|error| operational_refusal(error.to_string()))?;
        validate_approved_executable_identity(&executable_digest, self.running_executable_digest())
            .map_err(OperationalRegistryRefusal::ExecutableIdentity)
            .map_err(|error| operational_refusal(error.to_string()))?;
        let policy_bytes = artifact
            .policy_bytes()
            .map_err(|error| operational_refusal(error.to_string()))?;
        let policy = OperationalPolicyRegistry::from_artifact_bytes(
            &policy_bytes,
            &inputs.policy_bundle,
            &inputs.policy_digest,
        )
        .map_err(|error| operational_refusal(error.to_string()))?;
        let execution_bytes = artifact
            .execution_registry_bytes()
            .map_err(|error| operational_refusal(error.to_string()))?;
        let execution_digest = inputs
            .approved
            .component_digests
            .get("execution_registry")
            .ok_or_else(|| operational_refusal("generation has no execution registry"))?;
        let execution =
            OperationalExecutionRegistry::from_artifact_bytes(&execution_bytes, execution_digest)
                .map_err(|error| operational_refusal(error.to_string()))?;
        ActiveOperationalRegistry::new(
            generation.id().clone(),
            policy,
            execution,
            &executable_digest,
        )
        .map_err(|error| operational_refusal(error.to_string()))
    }

    /// Reproduce and durably admit evidence for one exact capability record.
    ///
    /// The authority must already be present as a live direct owner grant.
    /// Its liveness is checked again inside the same transaction that retains
    /// the signed evidence, closing the revocation race between admission and
    /// commit.
    pub(crate) async fn admit_capability_evidence(
        &self,
        submission: CapabilityEvidenceSubmission,
    ) -> Result<crate::OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let now = PostgresAuthorizationLedger::new(self.storage().clone(), self.scope().clone())
            .observed_at()
            .await
            .map_err(operational_refusal)?;
        let verification = self
            .anchors()
            .admit_expected(AdmissionKind::Verification, submission.verification.clone())
            .map_err(operational_refusal)?;
        if verification.signer() != &verification.payload().verifier
            || verification.payload().observed_at > now
            || verification.payload().expires_at <= now
        {
            return Err(operational_refusal(
                "capability verification signer or validity interval is invalid",
            ));
        }
        let authority = self.admit_exact_direct_authority(
            &durable,
            &submission.authority,
            verification.signer(),
        )?;
        let authority_resource = capability_verification_resource(verification.payload())
            .map_err(operational_refusal)?;
        DirectGrant::admit(
            &authority,
            &AuthorityContext::new(
                self.workspace().institution.clone(),
                self.workspace().id.clone(),
                durable.owner.clone(),
                now,
            ),
            verification.signer(),
            VERIFY_EXECUTION_CAPABILITY_ACTION,
            &authority_resource,
        )
        .map_err(operational_refusal)?;

        if !submission.qualification.profile.task_classes.is_empty()
            || !submission.qualification.profile.capabilities.is_empty()
        {
            let approved_executable = self
                .workspace()
                .approved_generation
                .component_digests
                .get("executable")
                .ok_or_else(|| {
                    operational_refusal("workspace has no approved executable component")
                })?;
            validate_approved_executable_identity(
                approved_executable,
                self.running_executable_digest(),
            )
            .map_err(operational_refusal)?;
            validate_builtin_descriptor_identity(
                &submission.qualification.resource.descriptor,
                approved_executable,
            )
            .map_err(operational_refusal)?;
        }

        let reproduced = CapabilityQualificationEvidence::reproduce(
            verification.payload(),
            &submission.qualification.resource,
            &submission.qualification.profile,
            match &submission.qualification.probe {
                CapabilityQualificationProbe::ResourceManifest { operation, .. } => {
                    Some(operation.as_ref())
                }
                CapabilityQualificationProbe::NoExecutableClaims => None,
            },
        )
        .map_err(operational_refusal)?;
        if reproduced != submission.qualification {
            return Err(operational_refusal(
                "capability qualification differs from the reproduced public probe",
            ));
        }
        let qualification_digest = reproduced.digest().map_err(operational_refusal)?;
        let expected_ids = &verification.payload().evidence;
        let supplied_ids: BTreeSet<_> = submission
            .evidence
            .iter()
            .map(|wire| wire.payload.id.clone())
            .collect();
        if expected_ids.is_empty()
            || supplied_ids.len() != submission.evidence.len()
            || &supplied_ids != expected_ids
        {
            return Err(operational_refusal(
                "capability evidence IDs differ from the signed verification",
            ));
        }
        let evidence = submission
            .evidence
            .iter()
            .map(|wire| {
                let admitted = self
                    .anchors()
                    .admit_expected(AdmissionKind::Evidence, wire.clone())
                    .map_err(operational_refusal)?;
                let payload = admitted.payload();
                if admitted.signer() != verification.signer()
                    || payload.subject
                        != verification
                            .payload()
                            .digest()
                            .map_err(operational_refusal)?
                    || payload.producer_delegation != authority.payload().id
                    || payload.method != CAPABILITY_QUALIFICATION_METHOD
                    || payload.payload_digest != qualification_digest
                    || payload.observed_at > verification.payload().observed_at
                    || payload.independence
                        != politeia_core::evidence::IndependenceClass::IndependentAgent
                {
                    return Err(operational_refusal(
                        "capability evidence does not bind the reproduced probe, verifier, and authority",
                    ));
                }
                Ok(EvidenceAdmission {
                    id: payload.id.clone(),
                    record: crate::service::signed_wire_record(wire)?,
                })
            })
            .collect::<Result<Vec<_>, CoordinatorError>>()?;
        if supplied_ids
            .iter()
            .any(|id| durable.evidence.contains_key(id))
        {
            return Err(operational_refusal(
                "capability evidence is already durably admitted",
            ));
        }
        let transition = crate::service::signed_wire_record(&submission.verification)?;
        let receipt = self
            .storage()
            .commit_authorized(
                &ScopedCommit {
                    scope: self.scope().clone(),
                    expected_revision: durable.revision,
                    model: durable.model,
                    model_kind: "capability_evidence".to_string(),
                    transition,
                    state: Vec::new(),
                    evidence,
                    outbox: Vec::new(),
                },
                std::slice::from_ref(&authority),
            )
            .await
            .map_err(|error| operational_refusal(error.to_string()))?;
        Ok(crate::OperationResult::Coordinated {
            result: serde_json::json!({
                "verification": verification.payload().id,
                "qualification": qualification_digest,
                "evidence": supplied_ids,
                "revision": receipt.revision,
                "admitted": true,
            }),
            evidence_refs: supplied_ids.iter().map(|id| id.0.to_string()).collect(),
        })
    }

    /// Reproduce and retain one verifier-signed public detector calibration.
    pub(crate) async fn admit_detector_calibration_evidence(
        &self,
        submission: DetectorCalibrationEvidenceSubmission,
    ) -> Result<crate::OperationResult, CoordinatorError> {
        let durable = self.durable_snapshot().await?;
        let now = PostgresAuthorizationLedger::new(self.storage().clone(), self.scope().clone())
            .observed_at()
            .await
            .map_err(operational_refusal)?;
        let policy = OperationalPolicyRegistry::from_artifact_bytes(
            &submission.policy_bytes,
            &self.workspace().policy_bundle,
            &self.workspace().policy_digest,
        )
        .map_err(operational_refusal)?;
        let reproduced = policy
            .calibrate_detector(&submission.calibration.control)
            .map_err(operational_refusal)?;
        if reproduced != submission.calibration {
            return Err(operational_refusal(
                "detector calibration differs from actual public detector output",
            ));
        }
        let evidence = self
            .anchors()
            .admit_expected(AdmissionKind::Evidence, submission.evidence.clone())
            .map_err(operational_refusal)?;
        let authority =
            self.admit_exact_direct_authority(&durable, &submission.authority, evidence.signer())?;
        DirectGrant::admit(
            &authority,
            &AuthorityContext::new(
                self.workspace().institution.clone(),
                self.workspace().id.clone(),
                durable.owner.clone(),
                now,
            ),
            evidence.signer(),
            VERIFY_POLICY_CONTROL_ACTION,
            &policy_control_resource(&submission.calibration.control),
        )
        .map_err(operational_refusal)?;
        let calibration_digest = reproduced.digest().map_err(operational_refusal)?;
        if evidence.payload().subject != calibration_digest
            || evidence.payload().producer_delegation != authority.payload().id
            || evidence.payload().method != DETECTOR_CALIBRATION_METHOD
            || evidence.payload().payload_digest != calibration_digest
            || evidence.payload().observed_at > now
            || evidence.payload().independence
                != politeia_core::evidence::IndependenceClass::IndependentAgent
            || durable.evidence.contains_key(&evidence.payload().id)
        {
            return Err(operational_refusal(
                "detector calibration evidence does not bind its public report and live verifier",
            ));
        }
        let transition = crate::service::signed_wire_record(&submission.evidence)?;
        let receipt = self
            .storage()
            .commit_authorized(
                &ScopedCommit {
                    scope: self.scope().clone(),
                    expected_revision: durable.revision,
                    model: durable.model,
                    model_kind: "detector_calibration_evidence".to_string(),
                    transition: transition.clone(),
                    state: Vec::new(),
                    evidence: vec![EvidenceAdmission {
                        id: evidence.payload().id.clone(),
                        record: transition,
                    }],
                    outbox: Vec::new(),
                },
                std::slice::from_ref(&authority),
            )
            .await
            .map_err(|error| operational_refusal(error.to_string()))?;
        Ok(crate::OperationResult::Coordinated {
            result: serde_json::json!({
                "control": submission.calibration.control,
                "calibration": calibration_digest,
                "evidence": evidence.payload().id,
                "revision": receipt.revision,
                "admitted": true,
            }),
            evidence_refs: vec![evidence.payload().id.0.to_string()],
        })
    }

    /// Admit one complete active-generation submission for a typed effect port.
    ///
    /// This is the shared authority seam for the manifest, source-capture, and
    /// learning handlers. It authenticates the principal intent, binds it to
    /// one coherent workspace snapshot, admits capability evidence, reproduces
    /// routing, and evaluates the complete active policy.
    pub(crate) async fn admit_operational_submission(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        mut submission: OperationSubmission,
    ) -> Result<AdmittedOperationalSubmission, CoordinatorError> {
        submission
            .assurance
            .sort_by(|left, right| left.run.payload.control.cmp(&right.run.payload.control));
        submission.capability_verifications.sort_by(|left, right| {
            left.verification
                .payload
                .id
                .cmp(&right.verification.payload.id)
        });
        let signed_intent = submission.intent.clone();
        let admitted_intent = self
            .anchors()
            .admit_expected(AdmissionKind::OperationIntent, submission.intent)
            .map_err(operational_refusal)?;
        if admitted_intent.signer() != &admitted_intent.payload().principal {
            return Err(operational_refusal(
                "operation intent signer is not its requesting principal",
            ));
        }
        let active = durable
            .active_generation
            .as_ref()
            .ok_or_else(|| operational_refusal("no runtime generation is active"))?;
        let registry = self.operational_registry_for_generation(active).await?;
        let registered = registry
            .execution()
            .exact_operation(&admitted_intent.payload().operation)
            .ok_or_else(|| {
                operational_refusal("signed intent operation differs from the active registry")
            })?
            .clone();
        let ledger = PostgresAuthorizationLedger::new(self.storage().clone(), self.scope().clone());
        let now = ledger.observed_at().await.map_err(operational_refusal)?;
        let admitted_capabilities = self.admit_capability_verifications(
            durable,
            registry.execution(),
            &submission.capability_verifications,
            now,
        )?;
        let routing = registry
            .execution()
            .route_with_id(
                &registered.spec,
                submission.routing.id.clone(),
                &submission.availability,
                &admitted_capabilities,
                now,
            )
            .map_err(operational_refusal)?;
        if routing != submission.routing {
            return Err(operational_refusal(
                "submitted routing receipt differs from deterministic active routing",
            ));
        }
        let assignment = routing
            .assignment()
            .map_err(operational_refusal)?
            .ok_or_else(|| {
                operational_refusal("routing selected no eligible execution resource")
            })?;
        if admitted_intent.payload().execution.as_ref() != Some(&assignment) {
            return Err(operational_refusal(
                "signed intent does not bind the exact selected routing assignment",
            ));
        }
        let operation_chain = self
            .admit_durable_delegation_chain(
                durable,
                &admitted_intent.payload().delegation_chain,
                admitted_intent.signer(),
            )?
            .into_iter()
            .map(Admitted::into_payload)
            .collect();
        let policy = self.admit_operational_decision(
            durable,
            &registry,
            admitted_intent.payload(),
            &submission.assurance,
            now,
        )?;
        let authorization_expires_at = policy
            .expires_at
            .min(admitted_capabilities.authority_expires_at);
        Ok(AdmittedOperationalSubmission {
            registry,
            registered,
            signed_intent,
            intent: admitted_intent,
            operation_chain,
            policy,
            availability: submission.availability,
            routing,
            assignment,
            capability_verifications: submission.capability_verifications,
            assurance: submission.assurance,
            admission_revision: durable.revision,
            admitted_at: now,
            authorization_expires_at,
        })
    }

    /// Authenticate, authorize, route, execute, and durably complete one
    /// principal-signed operation under the exact active generation.
    pub(crate) async fn handle_operation(
        &self,
        request: Value,
    ) -> Result<crate::OperationResult, CoordinatorError> {
        let submission: OperationSubmission = serde_json::from_value(request).map_err(|error| {
            operational_refusal(format!("operation submission is malformed: {error}"))
        })?;
        let durable = self.durable_snapshot().await?;
        let admitted = self
            .admit_operational_submission(&durable, submission)
            .await?;
        let (maximum_resources, maximum_resource_bytes) = match &admitted.registered().handler {
            InstalledOperationHandler::ResourceManifest {
                maximum_resources,
                maximum_resource_bytes,
            } => (*maximum_resources, *maximum_resource_bytes),
            _ => {
                return Err(operational_refusal(
                    "operation is installed behind another typed service boundary",
                ));
            }
        };
        let selected_resource = admitted
            .registry()
            .execution()
            .resource(&admitted.assignment().resource)
            .ok_or_else(|| operational_refusal("selected execution resource is absent"))?;
        if !matches!(
            selected_resource.descriptor,
            ExecutionResourceDescriptor::DeterministicTool { .. }
        ) || selected_resource.locality != ExecutionLocality::ClientLocal
            || selected_resource.trust_domain != self.workspace().trust_domain
        {
            return Err(operational_refusal(
                "installed manifest handler requires a deterministic client-local resource in the workspace trust domain",
            ));
        }
        let port = ResourceManifestPort {
            operation: admitted.registered().spec.clone(),
            resources: admitted.intent().resources.clone(),
            assignment: admitted.assignment().clone(),
            adapter: selected_resource.adapter.clone(),
            audience: institution_audience(&self.workspace().institution),
            maximum_resources,
            maximum_resource_bytes,
        };
        let dispatcher = admitted.dispatcher(
            port,
            PostgresAuthorizationLedger::new(self.storage().clone(), self.scope().clone()),
        )?;
        let lease = dispatcher
            .authorize(admitted.intent())
            .await
            .map_err(|error| operational_refusal(error.to_string()))?;
        let manifest = dispatcher
            .execute(&lease)
            .await
            .map_err(|error| operational_refusal(error.to_string()))?;

        let completed_at =
            PostgresAuthorizationLedger::new(self.storage().clone(), self.scope().clone())
                .observed_at()
                .await
                .map_err(|error| operational_refusal(error.to_string()))?;
        let receipt_id = Uuid::now_v7();
        let receipt = OperationReceipt {
            schema: "politeia.operation-receipt.v1".to_string(),
            id: receipt_id,
            institution: self.workspace().institution.clone(),
            workspace: self.workspace().id.clone(),
            generation: admitted.registry().generation().clone(),
            lease: lease.id().clone(),
            reservation: lease.reservation_id().clone(),
            intent: admitted.signed_intent().clone(),
            decision: lease.decision().clone(),
            routing: admitted.routing().clone(),
            availability: admitted.availability().clone(),
            capability_verifications: admitted.capability_verifications().to_vec(),
            assurance: admitted.assurance().to_vec(),
            execution: admitted.assignment().clone(),
            adapter: selected_resource.adapter.clone(),
            completed_at,
            outcome: OperationCompletionOutcome::Succeeded {
                manifest: manifest.clone(),
            },
        };
        let canonical_receipt = CanonicalPayload::from_serializable(&receipt)
            .map_err(|error| operational_refusal(error.to_string()))?;
        let outbox_id = Uuid::now_v7();
        self.storage()
            .record_completion_with_outbox(
                self.scope(),
                lease.reservation_id(),
                &canonical_receipt,
                &[OperationOutboxMessage {
                    id: outbox_id,
                    topic: "politeia.operation.completed.v1".to_string(),
                    payload: canonical_receipt.clone(),
                }],
            )
            .await
            .map_err(|error| operational_refusal(error.to_string()))?;
        let completion = OperationCompletion {
            receipt: receipt_id,
            receipt_digest: canonical_receipt.digest().clone(),
            reservation: lease.reservation_id().clone(),
            generation: admitted.registry().generation().clone(),
            routing: admitted.routing().clone(),
            manifest,
            outbox: outbox_id,
        };
        let evidence_refs = receipt
            .assurance
            .iter()
            .flat_map(|evidence| {
                [
                    evidence.run.payload.id.0.to_string(),
                    evidence.activation.payload.id.0.to_string(),
                ]
            })
            .collect();
        Ok(crate::OperationResult::Coordinated {
            result: serde_json::to_value(completion).map_err(operational_refusal)?,
            evidence_refs,
        })
    }

    fn admit_exact_direct_authority(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        wire: &SignedAdmissionWire<Delegation>,
        subject: &PrincipalId,
    ) -> Result<Admitted<Delegation>, CoordinatorError> {
        let persisted = durable
            .delegations
            .get(&wire.payload.id)
            .ok_or_else(|| operational_refusal("assurance authority is not durably admitted"))?;
        if &persisted.wire != wire {
            return Err(operational_refusal(
                "assurance authority differs from its durable signed wire",
            ));
        }
        let mut chain = self.admit_durable_delegation_chain(
            durable,
            std::slice::from_ref(&wire.payload),
            subject,
        )?;
        if chain.len() != 1 {
            return Err(operational_refusal(
                "assurance authority is not a direct owner grant",
            ));
        }
        chain
            .pop()
            .ok_or_else(|| operational_refusal("assurance authority is absent"))
    }

    /// Re-admit signed public-control evidence and evaluate one exact intent
    /// into an opaque decision point suitable for the shared dispatcher.
    ///
    /// The adjacent service boundary must first derive `intent` from its own
    /// authenticated request. Every control and verifier grant is resolved
    /// against the supplied coherent durable snapshot at `at`.
    pub(crate) fn admit_operational_decision(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        registry: &ActiveOperationalRegistry,
        intent: &OperationIntent,
        assurance: &[OperationalControlEvidence],
        at: Timestamp,
    ) -> Result<AdmittedOperationalDecision, CoordinatorError> {
        if registry
            .execution()
            .exact_operation(&intent.operation)
            .is_none()
        {
            return Err(operational_refusal(
                "policy request operation differs from the active registry",
            ));
        }
        let required_controls: BTreeSet<_> = registry
            .policy()
            .bindings()
            .iter()
            .filter(|binding| binding.scope == operation_scope(&intent.operation))
            .flat_map(|binding| binding.detector_ids.iter().cloned())
            .collect();
        if required_controls.is_empty() || assurance.len() != required_controls.len() {
            return Err(operational_refusal(
                "operation assurance does not exactly cover active policy controls",
            ));
        }

        let mut run_admissions = Vec::with_capacity(assurance.len());
        let mut run_authorities = Vec::with_capacity(assurance.len());
        let mut activation_admissions = Vec::with_capacity(assurance.len());
        let mut activation_authorities = Vec::with_capacity(assurance.len());
        let mut supplied_controls = BTreeSet::new();
        let mut run_producers = BTreeSet::new();
        let mut activation_verifiers = BTreeSet::new();
        let mut authority_expires_at: Option<Timestamp> = None;
        for evidence in assurance {
            let run = self
                .anchors()
                .admit_expected(AdmissionKind::ControlRun, evidence.run.clone())
                .map_err(operational_refusal)?;
            let activation = self
                .anchors()
                .admit_expected(AdmissionKind::ActivationProof, evidence.activation.clone())
                .map_err(operational_refusal)?;
            if run.payload().control != activation.payload().control
                || !supplied_controls.insert(run.payload().control.clone())
            {
                return Err(operational_refusal(
                    "operation assurance has an ambiguous control pairing",
                ));
            }
            if run.signer() == &intent.principal
                || activation.signer() == &intent.principal
                || run.signer() == activation.signer()
            {
                return Err(operational_refusal(
                    "requester, control producer, and activation verifier must be distinct",
                ));
            }
            run_producers.insert(run.signer().clone());
            activation_verifiers.insert(activation.signer().clone());
            let run_authority =
                self.admit_exact_direct_authority(durable, &evidence.run_authority, run.signer())?;
            let activation_authority = self.admit_exact_direct_authority(
                durable,
                &evidence.activation_authority,
                activation.signer(),
            )?;
            let calibration = registry
                .policy()
                .calibrate_detector(&activation.payload().control)
                .map_err(operational_refusal)?;
            let calibration_digest = calibration.digest().map_err(operational_refusal)?;
            let retained_wire =
                Self::durable_evidence_wire(durable, &activation.payload().retained_evidence)?;
            let retained = self
                .anchors()
                .admit_expected(AdmissionKind::Evidence, retained_wire)
                .map_err(operational_refusal)?;
            if retained.signer() != activation.signer()
                || retained.payload().subject != calibration_digest
                || retained.payload().producer_delegation != activation_authority.payload().id
                || retained.payload().method != DETECTOR_CALIBRATION_METHOD
                || retained.payload().payload_digest != calibration_digest
                || retained.payload().observed_at > activation.payload().proved_at
                || retained.payload().independence
                    != politeia_core::evidence::IndependenceClass::IndependentAgent
            {
                return Err(operational_refusal(
                    "activation proof does not resolve its retained public calibration evidence",
                ));
            }
            let authorization = direct_grant_authorization_digest(run_authority.payload())
                .map_err(operational_refusal)?;
            if run.payload().authorization != authorization {
                return Err(operational_refusal(
                    "control run authorization digest differs from its durable direct grant",
                ));
            }
            for expires_at in [
                run_authority.payload().expires_at,
                activation_authority.payload().expires_at,
            ] {
                authority_expires_at = Some(
                    authority_expires_at.map_or(expires_at, |current| current.min(expires_at)),
                );
            }
            run_admissions.push(run);
            run_authorities.push(run_authority);
            activation_admissions.push(activation);
            activation_authorities.push(activation_authority);
        }
        if supplied_controls != required_controls
            || !run_producers.is_disjoint(&activation_verifiers)
        {
            return Err(operational_refusal(
                "operation assurance is incomplete or lacks independent activation",
            ));
        }

        let context = AuthorityContext::new(
            self.workspace().institution.clone(),
            self.workspace().id.clone(),
            durable.owner.clone(),
            at,
        );
        let authorized_runs = run_admissions
            .iter()
            .zip(&run_authorities)
            .map(|(run, authority)| {
                AuthorizedControlRun::admit(run, authority, &context).map_err(operational_refusal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let verified_activations = activation_admissions
            .iter()
            .zip(&activation_authorities)
            .map(|(proof, authority)| {
                VerifiedActivation::admit(proof, authority, &context).map_err(operational_refusal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let intent_digest = intent.digest().map_err(operational_refusal)?;
        let request = politeia_policy::operational::OperationalEvaluationRequest {
            institution: self.workspace().institution.clone(),
            workspace: self.workspace().id.clone(),
            intent_digest: intent_digest.clone(),
            principal: intent.principal.clone(),
            operation: intent.operation.clone(),
            resources: intent.resources.clone(),
            at,
        };
        for run in &authorized_runs {
            registry
                .policy()
                .validate_control_run(&request, run.run())
                .map_err(operational_refusal)?;
        }
        for activation in &verified_activations {
            registry
                .policy()
                .validate_activation_proof(activation.proof())
                .map_err(operational_refusal)?;
        }
        let decision = registry
            .policy()
            .evaluate(
                &request,
                &EvaluationEvidence::new(&authorized_runs, &verified_activations, &[]),
            )
            .map_err(operational_refusal)?;
        Ok(AdmittedOperationalDecision {
            intent: intent_digest,
            decision,
            expires_at: authority_expires_at.ok_or_else(|| {
                operational_refusal("operation assurance authority expiry is absent")
            })?,
        })
    }

    fn admit_capability_verifications(
        &self,
        durable: &politeia_storage::WorkspaceSnapshot,
        registry: &OperationalExecutionRegistry,
        submitted: &[CapabilityVerificationEvidence],
        at: Timestamp,
    ) -> Result<AdmittedCapabilityVerifications, CoordinatorError> {
        let context = AuthorityContext::new(
            self.workspace().institution.clone(),
            self.workspace().id.clone(),
            durable.owner.clone(),
            at,
        );
        let mut identities = BTreeSet::new();
        let mut records = Vec::with_capacity(submitted.len());
        let mut authority_expires_at: Option<Timestamp> = None;
        for evidence in submitted {
            let verification = self
                .anchors()
                .admit_expected(AdmissionKind::Verification, evidence.verification.clone())
                .map_err(operational_refusal)?;
            if verification.signer() != &verification.payload().verifier
                || !identities.insert(verification.payload().id.clone())
            {
                return Err(operational_refusal(
                    "capability verification signer or identity is ambiguous",
                ));
            }
            let authority = self.admit_exact_direct_authority(
                durable,
                &evidence.authority,
                verification.signer(),
            )?;
            let authority_resource = capability_verification_resource(verification.payload())
                .map_err(operational_refusal)?;
            DirectGrant::admit(
                &authority,
                &context,
                verification.signer(),
                VERIFY_EXECUTION_CAPABILITY_ACTION,
                &authority_resource,
            )
            .map_err(operational_refusal)?;
            authority_expires_at = Some(
                authority_expires_at.map_or(authority.payload().expires_at, |current| {
                    current.min(authority.payload().expires_at)
                }),
            );

            let verification_digest = verification
                .payload()
                .digest()
                .map_err(operational_refusal)?;
            let qualification_digest = registry
                .capability_qualification(verification.payload())
                .and_then(|qualification| {
                    qualification
                        .digest()
                        .map_err(CapabilityQualificationRefusal::Canonical)
                })
                .map_err(operational_refusal)?;
            let evidence_wires = verification
                .payload()
                .evidence
                .iter()
                .map(|id| Self::durable_evidence_wire(durable, id))
                .collect::<Result<Vec<_>, _>>()?;
            let admitted_evidence =
                TrustedEvidenceRegistry::admit_signed(self.anchors(), evidence_wires)
                    .map_err(operational_refusal)?;
            for id in &verification.payload().evidence {
                let record = admitted_evidence.resolve(id).ok_or_else(|| {
                    operational_refusal("capability verification evidence is absent")
                })?;
                if record.subject != verification_digest
                    || record.producer != *verification.signer()
                    || record.producer_delegation != authority.payload().id
                    || record.method != CAPABILITY_QUALIFICATION_METHOD
                    || record.payload_digest != qualification_digest
                    || record.observed_at > verification.payload().observed_at
                    || record.independence
                        != politeia_core::evidence::IndependenceClass::IndependentAgent
                {
                    return Err(operational_refusal(
                        "capability verification evidence does not bind its signed verifier and current authority",
                    ));
                }
            }
            records.push(verification.into_payload());
        }
        records.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(AdmittedCapabilityVerifications {
            records,
            authority_expires_at: authority_expires_at.ok_or_else(|| {
                operational_refusal("capability verification authority expiry is absent")
            })?,
        })
    }

    fn durable_evidence_wire(
        durable: &politeia_storage::WorkspaceSnapshot,
        id: &EvidenceId,
    ) -> Result<SignedAdmissionWire<EvidenceRequest>, CoordinatorError> {
        let stored = durable
            .evidence
            .get(id)
            .ok_or_else(|| operational_refusal("capability evidence is not durably retained"))?;
        let wire: SignedAdmissionWire<EvidenceRequest> = serde_json::from_slice(stored.payload())
            .map_err(|error| {
            operational_refusal(format!("durable capability evidence is malformed: {error}"))
        })?;
        if wire.payload.id != *id
            || wire.signer != *stored.signer()
            || wire.signature != stored.signature()
        {
            return Err(operational_refusal(
                "capability evidence differs from its durable signed record",
            ));
        }
        Ok(wire)
    }
}

/// Opaque result of installed-anchor admission and complete active-policy evaluation.
///
/// It implements the shared dispatcher policy point while refusing any intent
/// other than the exact one whose signed assurance was evaluated.
#[derive(Clone, Debug)]
pub(crate) struct AdmittedOperationalDecision {
    intent: Digest,
    decision: PolicyDecision,
    expires_at: Timestamp,
}

impl AdmittedOperationalDecision {
    /// Inspect the normalized decision without weakening its dispatcher binding.
    pub(crate) fn decision(&self) -> &PolicyDecision {
        &self.decision
    }
}

impl PolicyDecisionPoint for AdmittedOperationalDecision {
    type Error = OperationalDecisionError;

    fn decide(
        &self,
        intent: &OperationIntent,
    ) -> impl Future<Output = Result<PolicyDecision, Self::Error>> + Send {
        ready((|| {
            let actual = intent
                .digest()
                .map_err(|error| OperationalDecisionError(error.to_string()))?;
            if actual != self.intent {
                return Err(OperationalDecisionError(
                    "dispatcher intent differs from the admitted policy decision".to_string(),
                ));
            }
            Ok(self.decision.clone())
        })())
    }
}

#[derive(Debug)]
pub(crate) struct OperationalDecisionError(String);

impl std::fmt::Display for OperationalDecisionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for OperationalDecisionError {}

struct ResourceManifestPort {
    operation: OperationSpec,
    resources: BTreeSet<String>,
    assignment: ExecutionAssignment,
    adapter: AdapterId,
    audience: String,
    maximum_resources: u32,
    maximum_resource_bytes: u64,
}

impl EffectPort for ResourceManifestPort {
    type Output = ResourceManifest;
    type Error = ResourceManifestError;

    fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    fn audience(&self) -> &str {
        &self.audience
    }

    fn execute<'lease>(
        &'lease self,
        invocation: AuthorizedEffect<'lease>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'lease {
        ready((|| {
            let lease = invocation.lease();
            if lease.operation() != &self.operation
                || lease.resources() != &self.resources
                || lease.execution() != Some(&self.assignment)
                || lease.effects() != &BTreeSet::from([Effect::CreateArtifact])
            {
                return Err(ResourceManifestError(
                    "manifest lease differs from the installed bounded handler".to_string(),
                ));
            }
            derive_resource_manifest(
                &self.operation,
                &self.resources,
                self.maximum_resources,
                self.maximum_resource_bytes,
            )
            .map_err(|error| ResourceManifestError(error.to_string()))
        })())
    }
}

pub(crate) fn derive_resource_manifest(
    operation: &OperationSpec,
    resources: &BTreeSet<String>,
    maximum_resources: u32,
    maximum_resource_bytes: u64,
) -> Result<ResourceManifest, ResourceManifestProbeRefusal> {
    let resource_count = u32::try_from(resources.len())
        .map_err(|_| ResourceManifestProbeRefusal::SizeUnrepresentable)?;
    if resource_count > maximum_resources {
        return Err(ResourceManifestProbeRefusal::ResourceCountExceeded);
    }
    let resource_bytes = resources.iter().try_fold(0_u64, |total, resource| {
        let length = u64::try_from(resource.len())
            .map_err(|_| ResourceManifestProbeRefusal::SizeUnrepresentable)?;
        total
            .checked_add(length)
            .ok_or(ResourceManifestProbeRefusal::SizeUnrepresentable)
    })?;
    if resource_bytes > maximum_resource_bytes {
        return Err(ResourceManifestProbeRefusal::ResourceBytesExceeded);
    }
    let resources: Vec<_> = resources.iter().cloned().collect();
    let manifest_digest = Digest::blake3(
        &to_canonical_bytes(&ResourceManifestSubject {
            schema: "politeia.resource-manifest.v1",
            operation: &operation.id,
            resources: &resources,
        })
        .map_err(|_| ResourceManifestProbeRefusal::SizeUnrepresentable)?,
    );
    Ok(ResourceManifest {
        operation: operation.id.clone(),
        resources,
        resource_count,
        manifest_digest,
    })
}

#[derive(Serialize)]
struct ResourceManifestSubject<'a> {
    schema: &'static str,
    operation: &'a OperationId,
    resources: &'a [String],
}

#[derive(Debug)]
struct ResourceManifestError(String);

impl std::fmt::Display for ResourceManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ResourceManifestError {}

impl std::fmt::Display for ResourceManifestProbeRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ResourceCountExceeded => "manifest resource count exceeds the installed bound",
            Self::ResourceBytesExceeded => "manifest resource bytes exceed the installed bound",
            Self::SizeUnrepresentable => "manifest resource size cannot be represented",
        })
    }
}

impl std::error::Error for ResourceManifestProbeRefusal {}

fn validate_profile_binding(
    verification: &CapabilityVerificationRecord,
    resource: &ExecutionResource,
    profile: &CapabilityProfile,
) -> Result<(), CapabilityQualificationRefusal> {
    let resource_digest = resource
        .digest()
        .map_err(CapabilityQualificationRefusal::Canonical)?;
    let verification_digest = verification
        .digest()
        .map_err(CapabilityQualificationRefusal::Canonical)?;
    if verification.resource != resource.id
        || verification.resource_digest != resource_digest
        || verification.profile != profile.id
        || profile.resource != resource.id
        || profile.resource_digest != resource_digest
        || profile.verification != verification.id
        || profile.verification_digest != verification_digest
        || verification.task_classes != profile.task_classes
        || verification.capabilities != profile.capabilities
    {
        return Err(CapabilityQualificationRefusal::BindingMismatch);
    }
    Ok(())
}

fn validate_execution_document(
    document: &OperationalExecutionDocument,
) -> Result<(), OperationalRegistryRefusal> {
    if document.operations.is_empty()
        || document.resources.is_empty()
        || document.profiles.is_empty()
        || document.verifications.is_empty()
        || document.available_resources.is_empty()
    {
        return Err(OperationalRegistryRefusal::EmptyRegistry);
    }

    let mut operation_ids = BTreeSet::<OperationId>::new();
    let mut operation_names = BTreeSet::new();
    let mut previous_name: Option<&str> = None;
    for operation in &document.operations {
        if operation.spec.name.trim().is_empty()
            || previous_name.is_some_and(|previous| previous >= operation.spec.name.as_str())
            || !operation_ids.insert(operation.spec.id.clone())
            || !operation_names.insert(operation.spec.name.clone())
        {
            return Err(OperationalRegistryRefusal::AmbiguousOperation);
        }
        previous_name = Some(&operation.spec.name);
        let requirement = operation
            .requirement
            .digest()
            .map_err(OperationalRegistryRefusal::Canonical)?;
        if operation.spec.execution_requirement.as_ref() != Some(&requirement)
            || operation.handler.operation_name() != operation.spec.name
            || operation.spec.actions.is_empty()
            || operation.spec.effects.is_empty()
            || operation.spec.evidence_obligations.is_empty()
        {
            return Err(OperationalRegistryRefusal::OperationContractMismatch);
        }
        if let InstalledOperationHandler::ResourceManifest {
            maximum_resources,
            maximum_resource_bytes,
        } = &operation.handler
        {
            if *maximum_resources == 0
                || *maximum_resource_bytes == 0
                || !operation.requirement.deterministic_only
                || operation.spec.actions != BTreeSet::from([RESOURCE_MANIFEST_ACTION.to_string()])
                || operation.spec.effects != BTreeSet::from([Effect::CreateArtifact])
                || operation.spec.data_classes != BTreeSet::from([DataClass::Public])
                || operation.spec.evidence_obligations
                    != vec![OPERATION_RECEIPT_OBLIGATION.to_string()]
            {
                return Err(OperationalRegistryRefusal::OperationContractMismatch);
            }
        }
    }

    let mut resources = BTreeMap::new();
    for resource in &document.resources {
        if resources.insert(resource.id.clone(), resource).is_some() {
            return Err(OperationalRegistryRefusal::AmbiguousResource);
        }
    }
    if !document
        .available_resources
        .iter()
        .all(|resource| resources.contains_key(resource))
    {
        return Err(OperationalRegistryRefusal::AvailabilityMismatch);
    }

    let mut profiles = BTreeMap::new();
    let mut profile_ids = BTreeSet::new();
    for profile in &document.profiles {
        if !profile_ids.insert(profile.id.clone())
            || profiles.insert(profile.resource.clone(), profile).is_some()
        {
            return Err(OperationalRegistryRefusal::AmbiguousProfile);
        }
        let resource = resources
            .get(&profile.resource)
            .ok_or(OperationalRegistryRefusal::CapabilityBindingMismatch)?;
        if profile.resource_digest
            != resource
                .digest()
                .map_err(OperationalRegistryRefusal::Canonical)?
        {
            return Err(OperationalRegistryRefusal::CapabilityBindingMismatch);
        }
    }
    if profiles.keys().ne(resources.keys()) {
        return Err(OperationalRegistryRefusal::CapabilityBindingMismatch);
    }

    let mut verifications = BTreeMap::new();
    for verification in &document.verifications {
        if verifications
            .insert(verification.id.clone(), verification)
            .is_some()
        {
            return Err(OperationalRegistryRefusal::AmbiguousVerification);
        }
    }
    let referenced_verifications: BTreeSet<_> = document
        .profiles
        .iter()
        .map(|profile| profile.verification.clone())
        .collect();
    if referenced_verifications.len() != document.verifications.len()
        || !referenced_verifications
            .iter()
            .all(|id| verifications.contains_key(id))
    {
        return Err(OperationalRegistryRefusal::CapabilityBindingMismatch);
    }
    for profile in &document.profiles {
        let verification = verifications
            .get(&profile.verification)
            .ok_or(OperationalRegistryRefusal::CapabilityBindingMismatch)?;
        if verification
            .digest()
            .map_err(OperationalRegistryRefusal::Canonical)?
            != profile.verification_digest
            || verification.profile != profile.id
            || verification.resource != profile.resource
            || verification.resource_digest != profile.resource_digest
            || verification.task_classes != profile.task_classes
            || verification.capabilities != profile.capabilities
            || verification.evidence.is_empty()
        {
            return Err(OperationalRegistryRefusal::CapabilityBindingMismatch);
        }
    }
    Ok(())
}

fn operational_refusal(reason: impl std::fmt::Display) -> CoordinatorError {
    CoordinatorError::Refused(format!("active operational registry refused: {reason}"))
}

/// Why a capability claim could not be tied to a reproducible public probe.
#[derive(Debug)]
#[non_exhaustive]
pub enum CapabilityQualificationRefusal {
    /// Verification, resource, and profile identities or digests differ.
    BindingMismatch,
    /// The execution registry does not contain the verification's resource.
    ResourceAbsent,
    /// The execution registry does not contain the verification's profile.
    ProfileAbsent,
    /// A non-empty executable claim is outside the public probe's narrow contract.
    UnsupportedExecutableClaim,
    /// An executable claim did not supply the resource-manifest operation.
    ManifestOperationAbsent,
    /// A supplied operation is not the installed resource-manifest handler.
    ManifestOperationMismatch,
    /// An empty capability claim improperly supplied an executable operation.
    UnexpectedManifestOperation,
    /// A declared bound is too large for the finite public planted probe.
    ProbePopulationTooLarge,
    /// The real manifest algorithm refused an input required to be known-good.
    ManifestProbe(ResourceManifestProbeRefusal),
    /// A canonical typed payload could not be encoded.
    Canonical(CanonicalError),
}

impl From<ResourceManifestProbeRefusal> for CapabilityQualificationRefusal {
    fn from(value: ResourceManifestProbeRefusal) -> Self {
        Self::ManifestProbe(value)
    }
}

impl std::fmt::Display for CapabilityQualificationRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindingMismatch => formatter
                .write_str("capability verification, resource, and profile do not bind exactly"),
            Self::ResourceAbsent => {
                formatter.write_str("capability resource is absent from the execution registry")
            }
            Self::ProfileAbsent => {
                formatter.write_str("capability profile is absent from the execution registry")
            }
            Self::UnsupportedExecutableClaim => {
                formatter.write_str("capability claim is outside the public probe contract")
            }
            Self::ManifestOperationAbsent => {
                formatter.write_str("resource-manifest probe operation is absent")
            }
            Self::ManifestOperationMismatch => {
                formatter.write_str("capability probe operation is not the manifest handler")
            }
            Self::UnexpectedManifestOperation => {
                formatter.write_str("an empty capability claim supplied an executable operation")
            }
            Self::ProbePopulationTooLarge => {
                formatter.write_str("capability probe population is not safely bounded")
            }
            Self::ManifestProbe(source) => write!(formatter, "capability probe failed: {source}"),
            Self::Canonical(_) => {
                formatter.write_str("capability qualification cannot be encoded canonically")
            }
        }
    }
}

impl std::error::Error for CapabilityQualificationRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ManifestProbe(source) => Some(source),
            Self::Canonical(source) => Some(source),
            _ => None,
        }
    }
}

/// Digest the exact direct-owner delegation that authorizes one control run.
///
/// [`AuthorizedControlRun`] proves the grant is semantically adequate, but a
/// signed run must also bind the particular admitted grant rather than merely
/// any grant with identical authority axes.
pub(crate) fn direct_grant_authorization_digest(
    grant: &Delegation,
) -> Result<Digest, CanonicalError> {
    to_canonical_bytes(grant).map(|bytes| Digest::blake3(&bytes))
}

/// Why exact execution-registry admission or routing failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum OperationalRegistryRefusal {
    /// Artifact bytes do not have the generation-approved digest.
    ExecutionDigestMismatch,
    /// The generation or selected deterministic resource does not bind this daemon executable.
    ExecutableIdentity(ExecutableIdentityRefusal),
    /// A required registry population is empty.
    EmptyRegistry,
    /// Operation identities, names, or canonical ordering are ambiguous.
    AmbiguousOperation,
    /// An operation's requirement or handler does not match its exact spec.
    OperationContractMismatch,
    /// An execution-resource identity is duplicated.
    AmbiguousResource,
    /// A capability profile identity or resource assignment is duplicated.
    AmbiguousProfile,
    /// A capability-verification identity is duplicated.
    AmbiguousVerification,
    /// Resource, profile, and independent-verification identities do not bind.
    CapabilityBindingMismatch,
    /// Availability names an absent resource or differs from the generation.
    AvailabilityMismatch,
    /// Policy operation scopes and executable operations are not the same set.
    PolicyCoverageMismatch,
    /// An operation is absent or differs from the generation registry.
    UnknownOperation,
    /// Artifact JSON is malformed or contains unsupported fields.
    Encoding(String),
    /// Artifact JSON is typed but is not its canonical byte representation.
    NonCanonicalArtifact,
    /// Canonical typed identity derivation failed.
    Canonical(CanonicalError),
    /// Requirement-first routing failed.
    Routing(RoutingError),
}

impl std::fmt::Display for OperationalRegistryRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ExecutionDigestMismatch => {
                "execution registry digest differs from the active generation"
            }
            Self::ExecutableIdentity(error) => return write!(formatter, "{error}"),
            Self::EmptyRegistry => "execution registry has an empty required population",
            Self::AmbiguousOperation => "execution registry operation identity is ambiguous",
            Self::OperationContractMismatch => {
                "registered operation does not bind its requirement and installed handler"
            }
            Self::AmbiguousResource => "execution resource identity is ambiguous",
            Self::AmbiguousProfile => "capability profile identity is ambiguous",
            Self::AmbiguousVerification => "capability verification identity is ambiguous",
            Self::CapabilityBindingMismatch => {
                "execution resource capability evidence does not bind exactly"
            }
            Self::AvailabilityMismatch => {
                "execution availability differs from the generation registry"
            }
            Self::PolicyCoverageMismatch => {
                "operational policy scopes differ from registered operations"
            }
            Self::UnknownOperation => "operation is absent or substituted",
            Self::Encoding(_) => "execution registry artifact is malformed",
            Self::NonCanonicalArtifact => "execution registry artifact bytes are not canonical",
            Self::Canonical(_) => "execution registry identity cannot be encoded",
            Self::Routing(_) => "execution registry could not produce a routing decision",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OperationalRegistryRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::ExecutableIdentity(error) => Some(error),
            Self::Routing(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "the fixture must fail loudly if canonical grant binding changes"
    )]

    use std::collections::{BTreeMap, BTreeSet};

    use jiff::{SignedDuration, Timestamp};
    use politeia_core::{
        AdapterId, CapabilityProfileId, CapabilityVerificationId, DataClass, DelegationId, Digest,
        Effect, EvidenceId, ExecutionResourceId, OperationId, PolicyBundleId, PrincipalId,
        ResourceBudget, RuntimeGenerationId, institution::TrustDomainId,
    };
    use politeia_policy::{
        Consequence, DetectorSpec, EvidenceClass, PolicyBinding,
        hardening::{BindingAuthority, HardeningLadder, HardeningState},
        operational::{
            OperationalDetector, OperationalPolicyRegistry, PublicDetectorRule, operation_scope,
        },
    };
    use politeia_runtime::routing::{
        CapabilityProfile, CapabilityVerificationRecord, ExecutionRequirement, ExecutionResource,
        ExecutionResourceDescriptor, SoftPreference,
    };

    use super::{
        ActiveOperationalRegistry, BOUNDED_LOCAL_OPERATION_CAPABILITY,
        BOUNDED_LOCAL_OPERATION_TASK_CLASS, Delegation, ExecutableIdentityRefusal,
        InstalledOperationHandler, OPERATION_RECEIPT_OBLIGATION, OperationalExecutionRegistry,
        OperationalRegistryRefusal, RESOURCE_MANIFEST_ACTION, RESOURCE_MANIFEST_OPERATION,
        RegisteredOperation, direct_grant_authorization_digest,
        validate_approved_executable_identity,
    };

    fn direct_grant() -> Delegation {
        Delegation {
            id: DelegationId::new(),
            issuer: PrincipalId::new(),
            subject: PrincipalId::new(),
            parent: None,
            actions: BTreeSet::from(["run-policy-control".to_owned()]),
            resources: BTreeSet::from(["policy-control:generation:activate".to_owned()]),
            effects: BTreeSet::<Effect>::new(),
            data_classes: BTreeSet::<DataClass>::new(),
            audience: BTreeSet::from(["institution:fixture".to_owned()]),
            expires_at: Timestamp::now() + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: None,
                cpu_ms: None,
                memory_bytes: None,
                io_bytes: None,
                network_bytes: None,
                external_cost_microunits: None,
            },
        }
    }

    fn informational_authority() -> BindingAuthority {
        let mut ladder = HardeningLadder::new();
        for state in [
            HardeningState::Observed,
            HardeningState::Proposed,
            HardeningState::Approved,
            HardeningState::Shadow,
        ] {
            ladder.advance(state).expect("fixture ladder advances");
        }
        BindingAuthority::new(ladder, Consequence::Informational)
            .expect("shadowed fixture binding is informational")
    }

    fn active_registry_with_descriptor(
        descriptor: ExecutionResourceDescriptor,
        executable: &Digest,
    ) -> Result<ActiveOperationalRegistry, OperationalRegistryRefusal> {
        let trust_domain = TrustDomainId::try_from("fixture.daemon".to_owned())
            .expect("fixture trust domain is valid");
        let resource = ExecutionResource {
            id: ExecutionResourceId::new(),
            descriptor,
            adapter: AdapterId::new(),
            trust_domain: trust_domain.clone(),
            control_domain: trust_domain.clone(),
            locality: politeia_core::ExecutionLocality::ClientLocal,
            allowed_data_classes: BTreeSet::from([DataClass::Public]),
            allowed_effects: BTreeSet::from([Effect::CreateArtifact]),
            max_context_tokens: 1,
            estimated_cost_microunits: 1,
            estimated_latency_ms: 1,
        };
        let observed_at = Timestamp::now();
        let verification = CapabilityVerificationRecord {
            id: CapabilityVerificationId::new(),
            profile: CapabilityProfileId::new(),
            resource: resource.id.clone(),
            resource_digest: resource.digest().expect("fixture resource digests"),
            task_classes: BTreeSet::from([BOUNDED_LOCAL_OPERATION_TASK_CLASS.to_owned()]),
            capabilities: BTreeSet::from([BOUNDED_LOCAL_OPERATION_CAPABILITY.to_owned()]),
            verifier: PrincipalId::new(),
            verifier_control_domain: trust_domain.clone(),
            evidence: BTreeSet::from([EvidenceId::new()]),
            observed_at,
            expires_at: observed_at + SignedDuration::from_hours(1),
        };
        let profile = CapabilityProfile {
            id: verification.profile.clone(),
            resource: resource.id.clone(),
            resource_digest: verification.resource_digest.clone(),
            task_classes: verification.task_classes.clone(),
            capabilities: verification.capabilities.clone(),
            verification: verification.id.clone(),
            verification_digest: verification.digest().expect("fixture verification digests"),
        };
        let requirement = ExecutionRequirement {
            task_class: BOUNDED_LOCAL_OPERATION_TASK_CLASS.to_owned(),
            required_capabilities: BTreeSet::from([BOUNDED_LOCAL_OPERATION_CAPABILITY.to_owned()]),
            required_effects: BTreeSet::from([Effect::CreateArtifact]),
            data_classes: BTreeSet::from([DataClass::Public]),
            allowed_localities: BTreeSet::from([politeia_core::ExecutionLocality::ClientLocal]),
            allowed_trust_domains: BTreeSet::from([trust_domain]),
            minimum_context_tokens: 1,
            maximum_cost_microunits: Some(1),
            maximum_latency_ms: Some(1),
            require_independent_result_verification: false,
            deterministic_only: true,
            preferences: vec![SoftPreference::MinimizeCost],
        };
        let operation = RegisteredOperation {
            spec: politeia_core::OperationSpec {
                id: OperationId::new(),
                name: RESOURCE_MANIFEST_OPERATION.to_owned(),
                actions: BTreeSet::from([RESOURCE_MANIFEST_ACTION.to_owned()]),
                effects: BTreeSet::from([Effect::CreateArtifact]),
                data_classes: BTreeSet::from([DataClass::Public]),
                evidence_obligations: vec![OPERATION_RECEIPT_OBLIGATION.to_owned()],
                execution_requirement: Some(
                    requirement.digest().expect("fixture requirement digests"),
                ),
                retryable: false,
                requires_idempotency: false,
            },
            requirement,
            handler: InstalledOperationHandler::ResourceManifest {
                maximum_resources: 1,
                maximum_resource_bytes: 128,
            },
        };
        let scope = operation_scope(&operation.spec);
        let execution = OperationalExecutionRegistry::new(
            vec![operation],
            vec![resource.clone()],
            vec![profile],
            vec![verification],
            BTreeSet::from([resource.id]),
        )?;
        let rule = PublicDetectorRule::ResourcePrefixForbidden {
            forbidden_prefix: "forbidden:".to_owned(),
            known_good_resources: BTreeSet::from(["public:known-good".to_owned()]),
            planted_violation_resources: BTreeSet::from(["forbidden:planted".to_owned()]),
        };
        let detector_id = "fixture-detector".to_owned();
        let policy = OperationalPolicyRegistry::new(
            PolicyBundleId::new(),
            vec![PolicyBinding {
                id: "fixture-binding".to_owned(),
                clause_id: "fixture-clause".to_owned(),
                detector_ids: vec![detector_id.clone()],
                scope,
                authority: informational_authority(),
            }],
            BTreeMap::from([(
                detector_id.clone(),
                OperationalDetector {
                    spec: DetectorSpec {
                        id: detector_id,
                        evidence_class: EvidenceClass::Substance,
                        control_version: "1".to_owned(),
                        configuration_digest: rule
                            .configuration_digest()
                            .expect("fixture detector digests"),
                        mediation_path: "fixture.dispatcher".to_owned(),
                        supported_scopes: BTreeSet::from([operation_scope(
                            &execution
                                .operation_named(RESOURCE_MANIFEST_OPERATION)
                                .expect("fixture operation remains registered")
                                .spec,
                        )]),
                        calibration_population: rule
                            .calibration_population_digest()
                            .expect("fixture calibration digests"),
                        known_blind_spots: Vec::new(),
                    },
                    rule,
                },
            )]),
        )
        .expect("fixture operational policy is coherent");
        ActiveOperationalRegistry::new(
            RuntimeGenerationId::derive(b"fixture"),
            policy,
            execution,
            executable,
        )
    }

    #[test]
    fn control_run_authorization_binds_the_exact_admitted_grant() {
        let first = direct_grant();
        let mut replacement = first.clone();
        replacement.id = DelegationId::new();
        assert_ne!(
            direct_grant_authorization_digest(&first).expect("fixture grant encodes"),
            direct_grant_authorization_digest(&replacement).expect("replacement grant encodes"),
            "a run cannot be replayed under another otherwise-equivalent direct grant"
        );
    }

    #[test]
    fn distinguishes_a_staged_executable_that_is_not_the_running_daemon() {
        let refusal = validate_approved_executable_identity(
            &Digest::blake3(b"staged approved executable"),
            &Digest::blake3(b"running daemon executable"),
        )
        .expect_err("a generation staged for different bytes must not activate here");
        assert_eq!(
            refusal,
            ExecutableIdentityRefusal::ApprovedExecutableMismatch
        );
    }

    #[test]
    fn active_registry_refuses_a_builtin_descriptor_for_another_executable() {
        let approved = Digest::blake3(b"running daemon executable");
        let refusal = active_registry_with_descriptor(
            ExecutionResourceDescriptor::DeterministicTool {
                artifact_digest: Digest::blake3(b"another deterministic tool"),
                version: "fixture".to_owned(),
            },
            &approved,
        )
        .expect_err("a target operational registry must reject a substituted builtin descriptor");
        assert!(matches!(
            refusal,
            OperationalRegistryRefusal::ExecutableIdentity(
                ExecutableIdentityRefusal::DescriptorExecutableMismatch
            )
        ));
    }

    #[test]
    fn active_registry_keeps_a_non_builtin_descriptor_unaffected() {
        active_registry_with_descriptor(
            ExecutionResourceDescriptor::Model {
                provider: "fixture-provider".to_owned(),
                model: "fixture-model".to_owned(),
                runtime: "fixture-runtime".to_owned(),
                harness: "fixture-harness".to_owned(),
            },
            &Digest::blake3(b"approved daemon executable"),
        )
        .expect("a non-builtin resource remains outside daemon executable binding");
    }
}
