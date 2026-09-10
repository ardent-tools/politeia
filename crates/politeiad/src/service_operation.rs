//! Generation-bound operational policy, routing, and deterministic execution.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use politeia_core::canonical::{CanonicalError, to_canonical_bytes};
use politeia_core::{
    Digest, ExecutionResourceId, OperationId, OperationSpec, RoutingDecisionId, RuntimeGenerationId,
};
use politeia_policy::operational::{OperationalPolicyRegistry, operation_scope};
use politeia_runtime::routing::{
    AvailabilitySnapshot, CapabilityProfile, CapabilityVerificationRecord, ExecutionRequirement,
    ExecutionResource, Router, RoutingDecision, RoutingError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{CoordinatorError, service::PoliteiadService};

/// Stable semantic name of the public deterministic operation in the first slice.
pub const RESOURCE_MANIFEST_OPERATION: &str = "derive_resource_manifest";
/// Stable semantic name of approved institutional-context compilation.
pub const COMPILE_CONTEXT_OPERATION: &str = "compile_institutional_context";
/// Stable semantic name of active-generation capability discovery.
pub const DISCOVER_CAPABILITIES_OPERATION: &str = "discover_institutional_capabilities";
/// Stable semantic name of descriptor-bounded source capture under an active generation.
pub const CAPTURE_SOURCE_OPERATION: &str = "capture_authorized_source";

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
    /// Independently admitted verification records used by routing.
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
        now: Timestamp,
    ) -> Result<RoutingDecision, OperationalRegistryRefusal> {
        let registered = self
            .exact_operation(operation)
            .ok_or(OperationalRegistryRefusal::UnknownOperation)?;
        if snapshot.available_resources != self.document.available_resources {
            return Err(OperationalRegistryRefusal::AvailabilityMismatch);
        }
        let mut decision = Router::route(
            &registered.requirement,
            self.document.resources.clone(),
            self.document.profiles.clone(),
            self.document.verifications.clone(),
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
        let artifact = self.verified_generation(&active).await?;
        let generation = artifact.generation();
        if generation.id().digest() != &active {
            return Err(operational_refusal(
                "active generation identity differs from its verified artifact",
            ));
        }
        let inputs = generation.inputs();
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
        ActiveOperationalRegistry::new(generation.id().clone(), policy, execution)
            .map_err(|error| operational_refusal(error.to_string()))
    }
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
        } = operation.handler
            && (maximum_resources == 0
                || maximum_resource_bytes == 0
                || !operation.requirement.deterministic_only)
        {
            return Err(OperationalRegistryRefusal::OperationContractMismatch);
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

fn operational_refusal(reason: impl Into<String>) -> CoordinatorError {
    CoordinatorError::Refused(format!(
        "active operational registry refused: {}",
        reason.into()
    ))
}

/// Why exact execution-registry admission or routing failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum OperationalRegistryRefusal {
    /// Artifact bytes do not have the generation-approved digest.
    ExecutionDigestMismatch,
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
            Self::Routing(error) => Some(error),
            _ => None,
        }
    }
}
