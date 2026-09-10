//! Immutable, verified runtime-generation artifact bundles.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use politeia_core::{
    AdapterId, DelegationId, Digest, EvidenceId,
    canonical::to_canonical_bytes,
    commissioning::CommissioningRecord,
    generation::{RuntimeGeneration, RuntimeGenerationInputs},
    institution::InstitutionWorkspace,
    trust::{AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire},
};
use serde::{Deserialize, Serialize};

const REQUIRED_COMPONENTS: &[&str] = &[
    "executable",
    "migrations",
    "execution_registry",
    "projections",
    "compatibility",
    "sbom",
    "provenance",
    "update_metadata",
];

/// Actual input bytes required to materialize a signed generation.
#[derive(Clone, Debug)]
pub struct ArtifactSources {
    /// Exact public source archive.
    pub public_source: PathBuf,
    /// Exact policy bundle bytes.
    pub policy: PathBuf,
    /// Exact specializer configuration bytes.
    pub specializer: PathBuf,
    /// Exact build-toolchain description bytes.
    pub toolchain: PathBuf,
    /// Schema bytes keyed by their approved names.
    pub schemas: BTreeMap<String, PathBuf>,
    /// Adapter bytes keyed by their approved identities.
    pub adapters: BTreeMap<AdapterId, PathBuf>,
    /// Pack bytes keyed by their approved names.
    pub packs: BTreeMap<String, PathBuf>,
    /// Remaining complete component bytes keyed by approved component names.
    pub components: BTreeMap<String, PathBuf>,
}

/// A complete artifact writer rooted in one client-owned directory.
#[derive(Clone, Debug)]
pub struct GenerationArtifactBuilder {
    artifact_dir: PathBuf,
}

/// A reread, integrity-checked immutable generation bundle.
#[derive(Clone, Debug)]
pub struct VerifiedGenerationArtifact {
    directory: PathBuf,
    generation: RuntimeGeneration,
    manifest_digest: Digest,
}

/// Artifact materialization or verification failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactError {
    /// Filesystem publication or reread failed.
    Io(io::Error),
    /// Installed trust anchors rejected generation inputs.
    Admission(politeia_core::trust::AdmissionError),
    /// Generation provenance did not rederive.
    Generation(politeia_core::generation::RuntimeGenerationError),
    /// A required named component was absent.
    MissingComponent(String),
    /// Supplied or reread bytes did not match their approved digest.
    Substitution(String),
    /// An existing generation directory did not verify.
    ExistingBundle,
    /// The bundle manifest could not encode or decode.
    Encoding(String),
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "artifact I/O failed: {e}"),
            Self::Admission(e) => write!(f, "generation admission failed: {e}"),
            Self::Generation(e) => write!(f, "generation provenance failed: {e}"),
            Self::MissingComponent(n) => write!(f, "required generation component is missing: {n}"),
            Self::Substitution(n) => write!(
                f,
                "generation component bytes do not match approved digest: {n}"
            ),
            Self::ExistingBundle => {
                f.write_str("generation bundle already exists with different bytes")
            }
            Self::Encoding(e) => write!(f, "artifact manifest encoding failed: {e}"),
        }
    }
}
impl std::error::Error for ArtifactError {}
impl From<io::Error> for ArtifactError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(target_os = "linux")]
fn read_source(path: &Path) -> Result<Vec<u8>, ArtifactError> {
    use std::io::Read;

    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};

    let descriptor = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    let mut file = fs::File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(ArtifactError::Substitution(path.display().to_string()));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn read_source(path: &Path) -> Result<Vec<u8>, ArtifactError> {
    let _ = path;
    Err(ArtifactError::Substitution(
        "generation artifact source reads require Linux descriptor resolution".to_owned(),
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BundleManifest {
    signed_inputs: SignedAdmissionWire<RuntimeGenerationInputs>,
    commissioning: CommissioningProvenance,
    generation_digest: Digest,
    generation_manifest_digest: Digest,
    components: BTreeMap<String, Digest>,
}

/// Inert selection material required to reconstruct commissioning provenance.
///
/// The signed runtime-generation inputs bind the resulting record identity and
/// digest. This material therefore has no authority by itself: every recovery
/// path must rebuild the record from currently re-admitted durable evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissioningProvenance {
    /// The commissioner delegation used when the record was assembled.
    pub delegation: DelegationId,
    /// Evidence identities for the admitted discovery observations.
    pub observations: std::collections::BTreeSet<EvidenceId>,
    /// Evidence identities for the owner approvals.
    pub approvals: std::collections::BTreeSet<EvidenceId>,
    /// Explicitly approved unresolved obligations.
    pub unresolved_obligations: std::collections::BTreeSet<String>,
}

fn expected_components(
    generation: &RuntimeGeneration,
) -> Result<BTreeMap<String, Digest>, ArtifactError> {
    let approved = &generation.inputs().approved;
    for required in REQUIRED_COMPONENTS {
        if !approved.component_digests.contains_key(*required) {
            return Err(ArtifactError::MissingComponent((*required).to_owned()));
        }
    }
    let mut expected = BTreeMap::from([
        ("public_source".to_owned(), approved.source_digest.clone()),
        (
            "policy".to_owned(),
            generation.inputs().policy_digest.clone(),
        ),
        (
            "specializer".to_owned(),
            approved.specializer_digest.clone(),
        ),
        ("toolchain".to_owned(), approved.toolchain_digest.clone()),
    ]);
    expected.extend(
        approved
            .schema_digests
            .iter()
            .map(|(name, digest)| (format!("schema:{name}"), digest.clone())),
    );
    expected.extend(
        approved
            .adapter_digests
            .iter()
            .map(|(name, digest)| (format!("adapter:{}", name.0), digest.clone())),
    );
    expected.extend(
        approved
            .pack_digests
            .iter()
            .map(|(name, digest)| (format!("pack:{name}"), digest.clone())),
    );
    expected.extend(
        approved
            .component_digests
            .iter()
            .map(|(name, digest)| (format!("component:{name}"), digest.clone())),
    );
    Ok(expected)
}

impl GenerationArtifactBuilder {
    /// Create a writer for an institution-owned artifact directory.
    pub fn new(artifact_dir: PathBuf) -> Self {
        Self { artifact_dir }
    }

    /// Admit, rederive, hash, fsync, and atomically publish a complete immutable bundle.
    pub fn publish(
        &self,
        anchors: &InstitutionTrustAnchors,
        signed_inputs: SignedAdmissionWire<RuntimeGenerationInputs>,
        workspace: &InstitutionWorkspace,
        commissioning: &CommissioningRecord,
        sources: &ArtifactSources,
    ) -> Result<VerifiedGenerationArtifact, ArtifactError> {
        self.publish_with_provenance(
            anchors,
            signed_inputs,
            workspace,
            commissioning,
            CommissioningProvenance {
                delegation: commissioning.commissioner_delegation().clone(),
                observations: std::collections::BTreeSet::new(),
                approvals: std::collections::BTreeSet::new(),
                unresolved_obligations: commissioning.unresolved_obligations().clone(),
            },
            sources,
        )
    }

    /// Publish a bundle while retaining the inert material needed for durable
    /// commissioning-record recovery.
    #[expect(
        clippy::too_many_arguments,
        reason = "publication binds independent trust, provenance, and byte-source boundaries"
    )]
    pub fn publish_with_provenance(
        &self,
        anchors: &InstitutionTrustAnchors,
        signed_inputs: SignedAdmissionWire<RuntimeGenerationInputs>,
        workspace: &InstitutionWorkspace,
        commissioning: &CommissioningRecord,
        provenance: CommissioningProvenance,
        sources: &ArtifactSources,
    ) -> Result<VerifiedGenerationArtifact, ArtifactError> {
        let admitted = anchors
            .admit_expected(AdmissionKind::Generation, signed_inputs.clone())
            .map_err(ArtifactError::Admission)?;
        let generation =
            RuntimeGeneration::derive(admitted.into_payload(), workspace, commissioning)
                .map_err(ArtifactError::Generation)?;
        let expected = expected_components(&generation)?;
        let approved = &generation.inputs().approved;
        if !sources.schemas.keys().eq(approved.schema_digests.keys())
            || !sources.adapters.keys().eq(approved.adapter_digests.keys())
            || !sources.packs.keys().eq(approved.pack_digests.keys())
            || !sources
                .components
                .keys()
                .eq(approved.component_digests.keys())
        {
            return Err(ArtifactError::MissingComponent(
                "approved component map".to_owned(),
            ));
        }
        let mut paths = BTreeMap::from([
            ("public_source".to_owned(), sources.public_source.clone()),
            ("policy".to_owned(), sources.policy.clone()),
            ("specializer".to_owned(), sources.specializer.clone()),
            ("toolchain".to_owned(), sources.toolchain.clone()),
        ]);
        for name in approved.schema_digests.keys() {
            paths.insert(
                format!("schema:{name}"),
                sources
                    .schemas
                    .get(name)
                    .ok_or_else(|| ArtifactError::MissingComponent(format!("schema:{name}")))?
                    .clone(),
            );
        }
        for name in approved.adapter_digests.keys() {
            paths.insert(
                format!("adapter:{}", name.0),
                sources
                    .adapters
                    .get(name)
                    .ok_or_else(|| ArtifactError::MissingComponent("adapter".to_owned()))?
                    .clone(),
            );
        }
        for name in approved.pack_digests.keys() {
            paths.insert(
                format!("pack:{name}"),
                sources
                    .packs
                    .get(name)
                    .ok_or_else(|| ArtifactError::MissingComponent(format!("pack:{name}")))?
                    .clone(),
            );
        }
        for name in approved.component_digests.keys() {
            paths.insert(
                format!("component:{name}"),
                sources
                    .components
                    .get(name)
                    .ok_or_else(|| ArtifactError::MissingComponent(format!("component:{name}")))?
                    .clone(),
            );
        }
        let mut bytes = BTreeMap::new();
        for (name, path) in paths {
            let value = read_source(&path).map_err(|error| match error {
                ArtifactError::Substitution(_) => ArtifactError::Substitution(name.clone()),
                other => other,
            })?;
            if Digest::blake3(&value) != expected[&name] {
                return Err(ArtifactError::Substitution(name));
            }
            bytes.insert(name, value);
        }
        let generation_digest = generation.id().digest().clone();
        let final_dir = self.artifact_dir.join(generation_digest.as_str());
        if final_dir.exists() {
            return self.verify(anchors, workspace, commissioning, &generation_digest);
        }
        fs::create_dir_all(&self.artifact_dir)?;
        let stage = self.artifact_dir.join(format!(
            ".stage-{}-{}",
            generation_digest.as_str(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&stage)?;
        let component_dir = stage.join("components");
        fs::create_dir(&component_dir)?;
        for value in bytes.values() {
            let name = Digest::blake3(value);
            let target = component_dir.join(name.as_str());
            if !target.exists() {
                let mut file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(target)?;
                file.write_all(value)?;
                file.sync_all()?;
            }
        }
        let manifest = BundleManifest {
            signed_inputs,
            commissioning: provenance,
            generation_digest: generation_digest.clone(),
            generation_manifest_digest: Digest::blake3(
                &generation
                    .canonical_bytes()
                    .map_err(|e| ArtifactError::Encoding(e.to_string()))?,
            ),
            components: expected,
        };
        let manifest_bytes =
            to_canonical_bytes(&manifest).map_err(|e| ArtifactError::Encoding(e.to_string()))?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(stage.join("manifest.json"))?;
        file.write_all(&manifest_bytes)?;
        file.sync_all()?;
        fs::File::open(&stage)?.sync_all()?;
        fs::rename(&stage, &final_dir)?;
        fs::File::open(&self.artifact_dir)?.sync_all()?;
        Ok(VerifiedGenerationArtifact {
            directory: final_dir,
            generation,
            manifest_digest: Digest::blake3(&manifest_bytes),
        })
    }
    /// Re-admit signed inputs, rederive provenance, and hash every immutable stored component.
    pub fn verify(
        &self,
        anchors: &InstitutionTrustAnchors,
        workspace: &InstitutionWorkspace,
        commissioning: &CommissioningRecord,
        generation_digest: &Digest,
    ) -> Result<VerifiedGenerationArtifact, ArtifactError> {
        let directory = self.artifact_dir.join(generation_digest.as_str());
        let bytes = fs::read(directory.join("manifest.json"))?;
        let manifest: BundleManifest =
            serde_json::from_slice(&bytes).map_err(|e| ArtifactError::Encoding(e.to_string()))?;
        if &manifest.generation_digest != generation_digest {
            return Err(ArtifactError::Substitution(
                "generation identity".to_owned(),
            ));
        }
        let admitted = anchors
            .admit_expected(AdmissionKind::Generation, manifest.signed_inputs)
            .map_err(ArtifactError::Admission)?;
        let generation =
            RuntimeGeneration::derive(admitted.into_payload(), workspace, commissioning)
                .map_err(ArtifactError::Generation)?;
        if generation.id().digest() != generation_digest {
            return Err(ArtifactError::Substitution("generation inputs".to_owned()));
        }
        let derived_manifest = Digest::blake3(
            &generation
                .canonical_bytes()
                .map_err(|e| ArtifactError::Encoding(e.to_string()))?,
        );
        if manifest.generation_manifest_digest != derived_manifest {
            return Err(ArtifactError::Substitution(
                "generation manifest".to_owned(),
            ));
        }
        if manifest.components != expected_components(&generation)? {
            return Err(ArtifactError::Substitution(
                "generation components".to_owned(),
            ));
        }
        for digest in manifest.components.values() {
            let value = fs::read(directory.join("components").join(digest.as_str()))?;
            if Digest::blake3(&value) != *digest {
                return Err(ArtifactError::Substitution(digest.as_str().to_owned()));
            }
        }
        Ok(VerifiedGenerationArtifact {
            directory,
            generation,
            manifest_digest: Digest::blake3(&bytes),
        })
    }

    /// Recover inert provenance selection material from an immutable bundle.
    ///
    /// Callers must re-admit the durable signed inputs and rebuild the
    /// commissioning record before using this selection.
    pub fn commissioning_provenance(
        &self,
        generation_digest: &Digest,
    ) -> Result<CommissioningProvenance, ArtifactError> {
        let bytes = fs::read(
            self.artifact_dir
                .join(generation_digest.as_str())
                .join("manifest.json"),
        )?;
        let manifest: BundleManifest = serde_json::from_slice(&bytes)
            .map_err(|error| ArtifactError::Encoding(error.to_string()))?;
        if &manifest.generation_digest != generation_digest {
            return Err(ArtifactError::Substitution(
                "generation identity".to_owned(),
            ));
        }
        Ok(manifest.commissioning)
    }
}
impl VerifiedGenerationArtifact {
    /// Return immutable bundle directory.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Return the rederived generation.
    pub fn generation(&self) -> &RuntimeGeneration {
        &self.generation
    }

    /// Reread one named artifact component and bind its bytes to this verified
    /// generation on every access.
    ///
    /// Verification at bundle-open time is not sufficient: filesystem bytes
    /// can still change afterwards. The role is resolved from the generation's
    /// approved component map, then the digest-addressed file is rehashed.
    pub fn component_bytes(&self, role: &str) -> Result<Vec<u8>, ArtifactError> {
        let expected = expected_components(&self.generation)?;
        let digest = expected
            .get(role)
            .ok_or_else(|| ArtifactError::MissingComponent(role.to_owned()))?;
        let bytes = fs::read(self.directory.join("components").join(digest.as_str()))?;
        if Digest::blake3(&bytes) != *digest {
            return Err(ArtifactError::Substitution(role.to_owned()));
        }
        Ok(bytes)
    }

    /// Reread the exact policy bundle bound into this verified generation.
    pub fn policy_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        self.component_bytes("policy")
    }

    /// Reread the exact execution registry bound into this verified generation.
    pub fn execution_registry_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        self.component_bytes("component:execution_registry")
    }

    /// Return the stored manifest digest.
    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "fixtures fail loudly when setup or assertions drift"
    )]
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::{Path, PathBuf},
    };

    use ed25519_dalek::SigningKey;
    use jiff::{SignedDuration, Timestamp};
    use politeia_core::{
        AdapterId, DataClass, Delegation, DelegationId, Digest, Effect, EvidenceId, InstitutionId,
        InstitutionWorkspaceId, PolicyBundleId, PrincipalId, ResourceBudget,
        commissioning::{
            ApprovedCommissioningSubject, CommissionerGrantRecord, CommissioningRecord,
            TrustedCommissionerGrantRegistry, commissioning_approval_subject_digest,
            commissioning_institution_audience, commissioning_observation_set_digest,
            commissioning_observation_subject_digest, commissioning_workspace_resource,
            unresolved_obligations_digest,
        },
        evidence::{EvidenceRecord, IndependenceClass, TrustedEvidenceRegistry},
        generation::{
            ApprovedGenerationInputs, CommissioningCapability, ReproducibilityContract,
            RuntimeGenerationInputs,
        },
        institution::{InstitutionWorkspace, TrustDomainId},
        lifecycle::{DeploymentTopology, LifecycleProfile},
        trust::{AdmissionKind, InstitutionTrustAnchors, SignedAdmissionWire, TrustedSigningKey},
    };

    use super::{ArtifactError, ArtifactSources, GenerationArtifactBuilder, REQUIRED_COMPONENTS};

    struct Fixture {
        inputs: RuntimeGenerationInputs,
        workspace: InstitutionWorkspace,
        commissioning: CommissioningRecord,
        key: SigningKey,
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("politeiad-artifact-tests-{}", uuid::Uuid::now_v7()));
            fs::create_dir(&path).expect("unique test directory creates");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn component_bytes(name: &str) -> Vec<u8> {
        format!("component bytes for {name}").into_bytes()
    }

    fn fixture(include_all_required_components: bool) -> Fixture {
        let institution = InstitutionId::new();
        let workspace_id = InstitutionWorkspaceId::new();
        let trust_domain: TrustDomainId = "client-a:production"
            .parse()
            .expect("fixture trust domain is canonical");
        let policy_bundle = PolicyBundleId::new();
        let policy_digest = Digest::blake3(b"policy");
        let mut component_digests: BTreeMap<_, _> = REQUIRED_COMPONENTS
            .iter()
            .map(|name| ((*name).to_owned(), Digest::blake3(&component_bytes(name))))
            .collect();
        if !include_all_required_components {
            component_digests.remove("sbom");
        }
        let approved_generation = ApprovedGenerationInputs {
            source_digest: Digest::blake3(b"source"),
            lifecycle: LifecycleProfile::Operational,
            topology: DeploymentTopology::ClientControlledSingleTenant,
            schema_digests: BTreeMap::from([("operation".to_string(), Digest::blake3(b"schema"))]),
            adapter_digests: BTreeMap::from([(AdapterId::new(), Digest::blake3(b"adapter"))]),
            pack_digests: BTreeMap::from([("institution".to_string(), Digest::blake3(b"pack"))]),
            component_digests,
            excluded_commissioning_capabilities: BTreeSet::from([
                CommissioningCapability::GenericReconnaissance,
                CommissioningCapability::InstitutionAuthoring,
                CommissioningCapability::AdapterDevelopment,
                CommissioningCapability::PolicyAuthoring,
                CommissioningCapability::GenerationDerivation,
            ]),
            specializer_digest: Digest::blake3(b"specializer"),
            toolchain_digest: Digest::blake3(b"toolchain"),
            reproducibility: ReproducibilityContract::Deterministic,
        };
        let workspace = InstitutionWorkspace {
            id: workspace_id.clone(),
            institution: institution.clone(),
            trust_domain: trust_domain.clone(),
            owner: PrincipalId::new(),
            owner_delegation: DelegationId::new(),
            approved_model_digest: Digest::blake3(b"model"),
            policy_bundle: policy_bundle.clone(),
            policy_digest: policy_digest.clone(),
            approved_generation: approved_generation.clone(),
            secret_references: BTreeSet::new(),
        };
        let workspace_digest = workspace.digest().expect("fixture workspace encodes");
        let as_of = Timestamp::now();
        let commissioner = PrincipalId::new();
        let commissioner_delegation = Delegation {
            id: DelegationId::new(),
            issuer: workspace.owner.clone(),
            subject: commissioner.clone(),
            parent: Some(workspace.owner_delegation.clone()),
            actions: BTreeSet::from(["commission".to_string()]),
            resources: BTreeSet::from([commissioning_workspace_resource(&workspace.id)]),
            effects: BTreeSet::from([Effect::ReadExternalSystem]),
            data_classes: BTreeSet::from([DataClass::Internal]),
            audience: BTreeSet::from([commissioning_institution_audience(&workspace.institution)]),
            expires_at: as_of + SignedDuration::from_hours(1),
            budget: ResourceBudget {
                wall_ms: Some(60_000),
                cpu_ms: Some(10_000),
                memory_bytes: Some(64 * 1024 * 1024),
                io_bytes: Some(1024 * 1024),
                network_bytes: Some(1024 * 1024),
                external_cost_microunits: Some(0),
            },
        };
        let grant = CommissionerGrantRecord {
            institution: workspace.institution.clone(),
            workspace: workspace.id.clone(),
            valid_from: as_of - SignedDuration::from_mins(1),
            revoked_at: None,
            delegation: commissioner_delegation.clone(),
        };
        let grant_digest = grant.digest().expect("fixture grant encodes");
        let observation = EvidenceRecord {
            id: EvidenceId::new(),
            subject: commissioning_observation_subject_digest(
                &workspace.institution,
                &workspace.id,
                &grant_digest,
                &Digest::blake3(b"observation payload"),
            )
            .expect("fixture observation subject encodes"),
            producer: commissioner,
            producer_delegation: commissioner_delegation.id.clone(),
            method: "bounded read-only discovery".to_string(),
            payload_digest: Digest::blake3(b"observation payload"),
            observed_at: as_of - SignedDuration::from_secs(30),
            independence: IndependenceClass::SelfReported,
        };
        let observation_set_digest =
            commissioning_observation_set_digest(std::slice::from_ref(&observation))
                .expect("fixture observation set encodes");
        let obligations = BTreeSet::new();
        let approved_subjects = [
            ApprovedCommissioningSubject::InstitutionalModel {
                digest: workspace.approved_model_digest.clone(),
            },
            ApprovedCommissioningSubject::PolicyBundle {
                id: workspace.policy_bundle.clone(),
                digest: workspace.policy_digest.clone(),
            },
            ApprovedCommissioningSubject::GenerationInputs {
                digest: approved_generation
                    .digest()
                    .expect("fixture generation plan encodes"),
            },
            ApprovedCommissioningSubject::UnresolvedObligations {
                digest: unresolved_obligations_digest(
                    &workspace.institution,
                    &workspace.id,
                    &obligations,
                )
                .expect("fixture obligations encode"),
            },
        ];
        let approvals: Vec<_> = approved_subjects
            .iter()
            .map(|subject| EvidenceRecord {
                id: EvidenceId::new(),
                subject: commissioning_approval_subject_digest(
                    &workspace.institution,
                    &workspace.id,
                    subject,
                    &observation_set_digest,
                )
                .expect("fixture approval subject encodes"),
                producer: workspace.owner.clone(),
                producer_delegation: workspace.owner_delegation.clone(),
                method: "institution-owner approval".to_string(),
                payload_digest: Digest::blake3(b"signed owner approval"),
                observed_at: as_of - SignedDuration::from_secs(10),
                independence: IndependenceClass::HumanAuthority,
            })
            .collect();
        let observation_ids = BTreeSet::from([observation.id.clone()]);
        let approval_ids = approvals.iter().map(|record| record.id.clone()).collect();
        let evidence = TrustedEvidenceRegistry::from_trusted_bootstrap(
            std::iter::once(observation).chain(approvals),
        )
        .expect("fixture evidence identities are unique");
        let grants = TrustedCommissionerGrantRegistry::from_trusted_bootstrap(as_of, [grant])
            .expect("fixture grant is unique and active");
        let commissioning = CommissioningRecord::new(
            &workspace,
            &grants,
            &evidence,
            &observation_ids,
            &approval_ids,
            obligations,
        )
        .expect("fixture commissioning record is complete");
        let inputs = RuntimeGenerationInputs {
            institution: institution.clone(),
            workspace: workspace_id,
            workspace_digest,
            trust_domain,
            policy_bundle,
            policy_digest,
            commissioning_record: commissioning.id().clone(),
            commissioning_record_digest: commissioning
                .digest()
                .expect("fixture commissioning record encodes"),
            approved: approved_generation,
        };
        Fixture {
            inputs,
            workspace,
            commissioning,
            key: SigningKey::from_bytes(&[7; 32]),
        }
    }

    fn anchors(fixture: &Fixture) -> InstitutionTrustAnchors {
        InstitutionTrustAnchors::from_trusted_bootstrap(
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            [TrustedSigningKey::new(
                fixture.workspace.owner.clone(),
                fixture.key.verifying_key().to_bytes(),
                BTreeSet::from([AdmissionKind::Generation]),
            )
            .expect("fixture signing key is valid")],
        )
        .expect("fixture trust anchor is unique")
    }

    fn signed_inputs(fixture: &Fixture) -> SignedAdmissionWire<RuntimeGenerationInputs> {
        SignedAdmissionWire::sign(
            AdmissionKind::Generation,
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            fixture.workspace.owner.clone(),
            fixture.inputs.clone(),
            &fixture.key,
        )
        .expect("fixture generation inputs sign")
    }

    fn write_sources(root: &Path, inputs: &RuntimeGenerationInputs) -> ArtifactSources {
        let source_dir = root.join("source-inputs");
        fs::create_dir(&source_dir).expect("source input directory creates");
        let write = |name: &str, bytes: &[u8]| {
            let path = source_dir.join(name);
            fs::write(&path, bytes).expect("fixture source bytes write");
            path
        };
        ArtifactSources {
            public_source: write("public-source", b"source"),
            policy: write("policy", b"policy"),
            specializer: write("specializer", b"specializer"),
            toolchain: write("toolchain", b"toolchain"),
            schemas: inputs
                .approved
                .schema_digests
                .keys()
                .map(|name| (name.clone(), write(&format!("schema-{name}"), b"schema")))
                .collect(),
            adapters: inputs
                .approved
                .adapter_digests
                .keys()
                .map(|name| {
                    (
                        name.clone(),
                        write(&format!("adapter-{}", name.0), b"adapter"),
                    )
                })
                .collect(),
            packs: inputs
                .approved
                .pack_digests
                .keys()
                .map(|name| (name.clone(), write(&format!("pack-{name}"), b"pack")))
                .collect(),
            components: inputs
                .approved
                .component_digests
                .keys()
                .map(|name| {
                    (
                        name.clone(),
                        write(&format!("component-{name}"), &component_bytes(name)),
                    )
                })
                .collect(),
        }
    }

    fn publish_fixture(
        fixture: &Fixture,
        root: &Path,
    ) -> (
        GenerationArtifactBuilder,
        ArtifactSources,
        super::VerifiedGenerationArtifact,
    ) {
        let sources = write_sources(root, &fixture.inputs);
        let builder = GenerationArtifactBuilder::new(root.join("artifacts"));
        let artifact = builder
            .publish(
                &anchors(fixture),
                signed_inputs(fixture),
                &fixture.workspace,
                &fixture.commissioning,
                &sources,
            )
            .expect("valid signed artifact publishes");
        (builder, sources, artifact)
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test asserts the complete trusted artifact path"
    )]
    fn publishes_and_rereads_an_immutable_complete_bundle() {
        let directory = TestDirectory::new();
        let fixture = fixture(true);
        let (builder, _, artifact) = publish_fixture(&fixture, directory.path());
        let reread = builder
            .verify(
                &anchors(&fixture),
                &fixture.workspace,
                &fixture.commissioning,
                artifact.generation().id().digest(),
            )
            .expect("published bytes reread and rederive");
        assert_eq!(artifact.directory(), reread.directory());
        assert_eq!(artifact.manifest_digest(), reread.manifest_digest());
        assert!(reread.directory().join("components").is_dir());
    }

    #[test]
    fn refuses_a_generation_without_every_required_component_role() {
        let directory = TestDirectory::new();
        let fixture = fixture(false);
        let builder = GenerationArtifactBuilder::new(directory.path().join("artifacts"));
        let sources = write_sources(directory.path(), &fixture.inputs);
        let result = builder.publish(
            &anchors(&fixture),
            signed_inputs(&fixture),
            &fixture.workspace,
            &fixture.commissioning,
            &sources,
        );
        assert!(matches!(result, Err(ArtifactError::MissingComponent(name)) if name == "sbom"));
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test constructs authentic and foreign signatures"
    )]
    fn refuses_wrong_signatures_and_foreign_workspaces_before_reading_sources() {
        let directory = TestDirectory::new();
        let fixture = fixture(true);
        let builder = GenerationArtifactBuilder::new(directory.path().join("artifacts"));
        let sources = write_sources(directory.path(), &fixture.inputs);
        let wrong_key = SigningKey::from_bytes(&[8; 32]);
        let wrong_signature = SignedAdmissionWire::sign(
            AdmissionKind::Generation,
            fixture.workspace.institution.clone(),
            fixture.workspace.id.clone(),
            fixture.workspace.owner.clone(),
            fixture.inputs.clone(),
            &wrong_key,
        )
        .expect("wrong test signature encodes");
        assert!(matches!(
            builder.publish(
                &anchors(&fixture),
                wrong_signature,
                &fixture.workspace,
                &fixture.commissioning,
                &sources,
            ),
            Err(ArtifactError::Admission(
                politeia_core::trust::AdmissionError::InvalidSignature
            ))
        ));
        let foreign = SignedAdmissionWire::sign(
            AdmissionKind::Generation,
            fixture.workspace.institution.clone(),
            InstitutionWorkspaceId::new(),
            fixture.workspace.owner.clone(),
            fixture.inputs.clone(),
            &fixture.key,
        )
        .expect("foreign test signature encodes");
        assert!(matches!(
            builder.publish(
                &anchors(&fixture),
                foreign,
                &fixture.workspace,
                &fixture.commissioning,
                &sources,
            ),
            Err(ArtifactError::Admission(
                politeia_core::trust::AdmissionError::ForeignWorkspace
            ))
        ));
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test mutates stored bytes after publication"
    )]
    fn detects_stored_component_and_manifest_tampering() {
        let directory = TestDirectory::new();
        let fixture = fixture(true);
        let (builder, _, artifact) = publish_fixture(&fixture, directory.path());
        let executable = Digest::blake3(&component_bytes("executable"));
        fs::write(
            artifact
                .directory()
                .join("components")
                .join(executable.as_str()),
            b"tampered component",
        )
        .expect("test can tamper stored component");
        assert!(matches!(
            builder.verify(
                &anchors(&fixture),
                &fixture.workspace,
                &fixture.commissioning,
                artifact.generation().id().digest(),
            ),
            Err(ArtifactError::Substitution(_))
        ));
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test changes stored provenance metadata after publication"
    )]
    fn detects_manifest_provenance_tampering() {
        let directory = TestDirectory::new();
        let fixture = fixture(true);
        let (builder, _, artifact) = publish_fixture(&fixture, directory.path());
        let manifest_path = artifact.directory().join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("test reads stored manifest"))
                .expect("stored manifest decodes for adversarial mutation");
        manifest["generation_manifest_digest"] = serde_json::Value::String(
            Digest::blake3(b"substituted generation manifest")
                .as_str()
                .to_owned(),
        );
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("tampered manifest encodes"),
        )
        .expect("test writes tampered manifest");
        assert!(matches!(
            builder.verify(
                &anchors(&fixture),
                &fixture.workspace,
                &fixture.commissioning,
                artifact.generation().id().digest(),
            ),
            Err(ArtifactError::Substitution(name)) if name == "generation manifest"
        ));
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test changes caller bytes after a valid immutable publish"
    )]
    fn changed_source_bytes_cannot_overwrite_an_existing_bundle() {
        let directory = TestDirectory::new();
        let fixture = fixture(true);
        let (builder, sources, artifact) = publish_fixture(&fixture, directory.path());
        fs::write(&sources.public_source, b"changed after approval")
            .expect("test changes source input bytes");
        assert!(matches!(
            builder.publish(
                &anchors(&fixture),
                signed_inputs(&fixture),
                &fixture.workspace,
                &fixture.commissioning,
                &sources,
            ),
            Err(ArtifactError::Substitution(name)) if name == "public_source"
        ));
        let reread = builder
            .verify(
                &anchors(&fixture),
                &fixture.workspace,
                &fixture.commissioning,
                artifact.generation().id().digest(),
            )
            .expect("failed replacement leaves original immutable bundle readable");
        assert_eq!(reread.directory(), artifact.directory());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test exercises descriptor-anchored source reads"
    )]
    fn rejects_final_and_parent_symlink_source_substitution() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let fixture = fixture(true);
        let sources = write_sources(directory.path(), &fixture.inputs);
        let builder = GenerationArtifactBuilder::new(directory.path().join("artifacts"));
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"source").expect("replacement source writes");
        fs::remove_file(&sources.public_source).expect("source file removes");
        symlink(&replacement, &sources.public_source).expect("final source symlink creates");
        assert!(
            builder
                .publish(
                    &anchors(&fixture),
                    signed_inputs(&fixture),
                    &fixture.workspace,
                    &fixture.commissioning,
                    &sources,
                )
                .is_err()
        );
        fs::remove_file(&sources.public_source).expect("final symlink removes");
        let parent = directory.path().join("symlinked-inputs");
        symlink(directory.path().join("source-inputs"), &parent).expect("parent symlink creates");
        let parent_sources = ArtifactSources {
            public_source: parent.join("public-source"),
            ..sources
        };
        assert!(
            builder
                .publish(
                    &anchors(&fixture),
                    signed_inputs(&fixture),
                    &fixture.workspace,
                    &fixture.commissioning,
                    &parent_sources,
                )
                .is_err()
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test mutates a component after the verified handle is created"
    )]
    fn verified_component_reads_rehash_bytes_after_initial_verification() {
        let directory = TestDirectory::new();
        let fixture = fixture(true);
        let (_, _, artifact) = publish_fixture(&fixture, directory.path());
        assert_eq!(
            artifact.policy_bytes().expect("policy bytes reread"),
            b"policy"
        );
        let policy = Digest::blake3(b"policy");
        fs::write(
            artifact
                .directory()
                .join("components")
                .join(policy.as_str()),
            b"changed after verification",
        )
        .expect("test mutates policy component");
        assert!(matches!(
            artifact.policy_bytes(),
            Err(ArtifactError::Substitution(role)) if role == "policy"
        ));
        assert!(matches!(
            artifact.execution_registry_bytes(),
            Ok(bytes) if bytes == component_bytes("execution_registry")
        ));
    }
}
