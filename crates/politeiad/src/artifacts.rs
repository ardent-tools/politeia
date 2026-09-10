//! Immutable, verified runtime-generation artifact bundles.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use politeia_core::{
    AdapterId, Digest,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BundleManifest {
    signed_inputs: SignedAdmissionWire<RuntimeGenerationInputs>,
    generation_digest: Digest,
    generation_manifest_digest: Digest,
    components: BTreeMap<String, Digest>,
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
        let admitted = anchors
            .admit_expected(AdmissionKind::Generation, signed_inputs.clone())
            .map_err(ArtifactError::Admission)?;
        let generation =
            RuntimeGeneration::derive(admitted.into_payload(), workspace, commissioning)
                .map_err(ArtifactError::Generation)?;
        let mut expected = BTreeMap::new();
        expected.insert(
            "public_source".to_owned(),
            generation.inputs().approved.source_digest.clone(),
        );
        expected.insert(
            "policy".to_owned(),
            generation.inputs().policy_digest.clone(),
        );
        expected.insert(
            "specializer".to_owned(),
            generation.inputs().approved.specializer_digest.clone(),
        );
        expected.insert(
            "toolchain".to_owned(),
            generation.inputs().approved.toolchain_digest.clone(),
        );
        for required in REQUIRED_COMPONENTS {
            if !generation
                .inputs()
                .approved
                .component_digests
                .contains_key(*required)
            {
                return Err(ArtifactError::MissingComponent((*required).to_owned()));
            }
        }
        if sources.schemas.len() != generation.inputs().approved.schema_digests.len()
            || sources.adapters.len() != generation.inputs().approved.adapter_digests.len()
            || sources.packs.len() != generation.inputs().approved.pack_digests.len()
            || sources.components.len() != generation.inputs().approved.component_digests.len()
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
        for (name, digest) in &generation.inputs().approved.schema_digests {
            expected.insert(format!("schema:{name}"), digest.clone());
            paths.insert(
                format!("schema:{name}"),
                sources
                    .schemas
                    .get(name)
                    .ok_or_else(|| ArtifactError::MissingComponent(format!("schema:{name}")))?
                    .clone(),
            );
        }
        for (name, digest) in &generation.inputs().approved.adapter_digests {
            expected.insert(format!("adapter:{}", name.0), digest.clone());
            paths.insert(
                format!("adapter:{}", name.0),
                sources
                    .adapters
                    .get(name)
                    .ok_or_else(|| ArtifactError::MissingComponent("adapter".to_owned()))?
                    .clone(),
            );
        }
        for (name, digest) in &generation.inputs().approved.pack_digests {
            expected.insert(format!("pack:{name}"), digest.clone());
            paths.insert(
                format!("pack:{name}"),
                sources
                    .packs
                    .get(name)
                    .ok_or_else(|| ArtifactError::MissingComponent(format!("pack:{name}")))?
                    .clone(),
            );
        }
        for (name, digest) in &generation.inputs().approved.component_digests {
            expected.insert(format!("component:{name}"), digest.clone());
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
            if fs::symlink_metadata(&path)?.file_type().is_symlink() || !path.is_file() {
                return Err(ArtifactError::Substitution(name));
            }
            let value = fs::read(path)?;
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
        let stage = self
            .artifact_dir
            .join(format!(".stage-{}", generation_digest.as_str()));
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
            generation_digest: generation_digest.clone(),
            generation_manifest_digest: Digest::blake3(
                &generation
                    .canonical_bytes()
                    .map_err(|e| ArtifactError::Encoding(e.to_string()))?,
            ),
            components: expected,
        };
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|e| ArtifactError::Encoding(e.to_string()))?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(stage.join("manifest.json"))?;
        file.write_all(&manifest_bytes)?;
        file.sync_all()?;
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

    /// Return the stored manifest digest.
    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }
}
