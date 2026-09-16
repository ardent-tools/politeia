//! Fresh generation materialization from retained, authenticated inputs.

use super::{
    ArtifactError, ArtifactSources, BundleManifest, CommissioningRecord, Digest,
    GenerationArtifactBuilder, InstitutionTrustAnchors, InstitutionWorkspace, PathBuf,
    expected_components, fs, read_source,
};

/// Exact result of materializing a generation again in a fresh directory.
///
/// Executables are approved generation inputs. This result establishes the
/// reproducibility of the generation bundle, not a compiler rebuild of those
/// executables from the public source archive.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct GenerationReproduction {
    /// Generation independently derived from the retained signed inputs.
    pub generation: Digest,
    /// Byte-identical canonical artifact manifest from the fresh publication.
    pub artifact_manifest: Digest,
    /// Number of declared component roles compared byte for byte.
    pub components_compared: usize,
}

impl GenerationArtifactBuilder {
    /// Re-materialize a complete generation without an original source tree,
    /// original signer, network endpoint, or pre-existing output directory.
    ///
    /// Retained input signatures and commissioning provenance are re-admitted
    /// first. The ordinary publisher then rederives the generation, reads each
    /// approved input, and writes a new bundle. Every output byte is compared
    /// with the verified original before the temporary output is removed.
    pub fn reproduce(
        &self,
        anchors: &InstitutionTrustAnchors,
        workspace: &InstitutionWorkspace,
        commissioning: &CommissioningRecord,
        generation: &Digest,
    ) -> Result<GenerationReproduction, ArtifactError> {
        let original = self.verify(anchors, workspace, commissioning, generation)?;
        let original_manifest = read_source(&original.directory.join("manifest.json"))?;
        if Digest::blake3(&original_manifest) != original.manifest_digest {
            return Err(ArtifactError::Substitution(
                "manifest changed during reproduction".into(),
            ));
        }
        let manifest: BundleManifest = serde_json::from_slice(&original_manifest)
            .map_err(|error| ArtifactError::Encoding(error.to_string()))?;
        let approved = &original.generation.inputs().approved;
        let component_path =
            |digest: &Digest| original.directory.join("components").join(digest.as_str());
        let sources = ArtifactSources {
            public_source: component_path(&approved.source_digest),
            policy: component_path(&original.generation.inputs().policy_digest),
            specializer: component_path(&approved.specializer_digest),
            toolchain: component_path(&approved.toolchain_digest),
            schemas: approved
                .schema_digests
                .iter()
                .map(|(key, digest)| (key.clone(), component_path(digest)))
                .collect(),
            adapters: approved
                .adapter_digests
                .iter()
                .map(|(key, digest)| (key.clone(), component_path(digest)))
                .collect(),
            packs: approved
                .pack_digests
                .iter()
                .map(|(key, digest)| (key.clone(), component_path(digest)))
                .collect(),
            components: approved
                .component_digests
                .iter()
                .map(|(key, digest)| (key.clone(), component_path(digest)))
                .collect(),
        };
        let scratch = ReproductionDirectory::create(&self.artifact_dir)?;
        let builder = Self::new(scratch.path.clone());
        let reproduced = builder.publish_with_provenance(
            anchors,
            manifest.signed_inputs,
            workspace,
            commissioning,
            manifest.commissioning,
            &sources,
        )?;
        let verified = builder.verify(anchors, workspace, commissioning, generation)?;
        if reproduced.directory == original.directory
            || reproduced.generation.id().digest() != generation
            || verified.manifest_digest != original.manifest_digest
            || read_source(&verified.directory.join("manifest.json"))? != original_manifest
        {
            return Err(ArtifactError::Substitution(
                "reproduced generation manifest".into(),
            ));
        }
        let roles = expected_components(&original.generation)?;
        for role in roles.keys() {
            if original.component_bytes(role)? != verified.component_bytes(role)? {
                return Err(ArtifactError::Substitution(format!("reproduced {role}")));
            }
        }
        let result = GenerationReproduction {
            generation: generation.clone(),
            artifact_manifest: verified.manifest_digest,
            components_compared: roles.len(),
        };
        scratch.remove()?;
        Ok(result)
    }
}

struct ReproductionDirectory {
    path: PathBuf,
    present: bool,
}

impl ReproductionDirectory {
    fn create(parent: &std::path::Path) -> Result<Self, ArtifactError> {
        let directory = parent.join(format!(".reproduce-{}", uuid::Uuid::now_v7()));
        // Only remove the directory that this call exclusively created.
        fs::create_dir(&directory)?;
        Ok(Self {
            path: directory,
            present: true,
        })
    }

    fn remove(mut self) -> Result<(), ArtifactError> {
        fs::remove_dir_all(&self.path)?;
        self.present = false;
        Ok(())
    }
}

impl Drop for ReproductionDirectory {
    fn drop(&mut self) {
        // Failed reproduction leaves the immutable published generation alone.
        if self.present {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
