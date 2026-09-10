//! Unsigned lifecycle calibration of one already-published generation bundle.
//!
//! The daemon reruns the immutable artifact verifier over the installed bundle
//! and a private copied bundle containing one exact component substitution.  A
//! caller may have separate control producers and verifiers sign the returned
//! values, but this module never signs or grants authority.

use politeia_core::{
    Digest, PolicyBundleId,
    canonical::{CanonicalError, to_canonical_bytes},
};
use politeia_evidence::assurance::{ControlResult, Coverage};
use serde::{Deserialize, Serialize};

use crate::artifacts::ArtifactCalibration;

/// Version of the installed immutable-bundle lifecycle verifier.
pub const LIFECYCLE_VERIFIER_VERSION: &str = "generation-artifact-verifier.v1";
/// Mediation path exercised by lifecycle verification and calibration.
pub const LIFECYCLE_VERIFIER_PATH: &str = "generation-artifact-bundle-verifier.v1";
/// Stable schema for unsigned generation validation output.
pub const GENERATION_VALIDATION_SCHEMA: &str = "politeia.generation-validation.v1";
/// Exact method identifier for a verifier-signed lifecycle calibration record.
pub const LIFECYCLE_CALIBRATION_METHOD: &str = "politeia.generation-calibration.v1";

/// Exact unsigned output of a real generation artifact validation.
///
/// Each field is intended to be copied into independently signed control-run
/// and activation-proof evidence.  Activation reruns this computation and
/// requires exact equality before it treats that evidence as a clean claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationValidationReport {
    /// Versioned identity of this report format.
    pub schema: String,
    /// Immutable generation whose bundle was exercised.
    pub generation: Digest,
    /// Exact reread bundle-manifest digest used as control configuration.
    pub artifact_manifest: Digest,
    /// Named lifecycle control whose evidence will bind this report.
    pub control: String,
    /// Installed verifier version that produced the vector outcomes.
    pub control_version: String,
    /// Actual installed mediation path exercised by both vectors.
    pub mediation_path: String,
    /// Policy bundle configured for this workspace.
    pub policy: PolicyBundleId,
    /// Exact configured policy bytes digest.
    pub policy_digest: Digest,
    /// Digest identifying the two exact calibration vectors.
    pub population: Digest,
    /// Digest identifying the accepted installed-bundle vector.
    pub known_good: Digest,
    /// The actual known-good outcome from the installed verifier.
    pub known_good_result: ControlResult,
    /// Digest identifying the copied-bundle substitution vector.
    pub planted_violation: Digest,
    /// The actual planted-substitution outcome from the installed verifier.
    pub planted_violation_result: ControlResult,
    /// Declared component role substituted only in the private copy.
    pub planted_component: String,
    /// Approved digest naming the substituted component bytes.
    pub planted_component_digest: Digest,
    /// Digest of the replacement bytes written into the copy.
    pub mutation_digest: Digest,
    /// Exact immutable component count checked by the verifier.
    pub coverage: Coverage,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CalibrationVector<'a> {
    schema: &'a str,
    generation: &'a Digest,
    artifact_manifest: &'a Digest,
    control: &'a str,
    control_version: &'a str,
    mediation_path: &'a str,
    policy: &'a PolicyBundleId,
    policy_digest: &'a Digest,
    component: &'a str,
    component_digest: &'a Digest,
    mutation_digest: Option<&'a Digest>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CalibrationPopulation<'a> {
    schema: &'a str,
    known_good: &'a Digest,
    planted_violation: &'a Digest,
}

impl GenerationValidationReport {
    /// Canonically digest this exact public validation report for retained
    /// lifecycle-calibration evidence.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if this report cannot be represented in its
    /// canonical lifecycle-calibration form.
    pub fn digest(&self) -> Result<Digest, CanonicalError> {
        to_canonical_bytes(self).map(|bytes| Digest::blake3(&bytes))
    }

    /// Bind one real verifier calibration into stable unsigned vector values.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the report cannot be canonically bound.
    pub(crate) fn from_calibration(
        generation: Digest,
        control: &str,
        policy: PolicyBundleId,
        policy_digest: Digest,
        calibration: ArtifactCalibration,
    ) -> Result<Self, CanonicalError> {
        let artifact_manifest = calibration.artifact.manifest_digest().clone();
        let known_good = Digest::blake3(&to_canonical_bytes(&CalibrationVector {
            schema: GENERATION_VALIDATION_SCHEMA,
            generation: &generation,
            artifact_manifest: &artifact_manifest,
            control,
            control_version: LIFECYCLE_VERIFIER_VERSION,
            mediation_path: LIFECYCLE_VERIFIER_PATH,
            policy: &policy,
            policy_digest: &policy_digest,
            component: "installed_bundle",
            component_digest: &artifact_manifest,
            mutation_digest: None,
        })?);
        let planted_violation = Digest::blake3(&to_canonical_bytes(&CalibrationVector {
            schema: GENERATION_VALIDATION_SCHEMA,
            generation: &generation,
            artifact_manifest: &artifact_manifest,
            control,
            control_version: LIFECYCLE_VERIFIER_VERSION,
            mediation_path: LIFECYCLE_VERIFIER_PATH,
            policy: &policy,
            policy_digest: &policy_digest,
            component: &calibration.planted_component,
            component_digest: &calibration.planted_component_digest,
            mutation_digest: Some(&calibration.mutation_digest),
        })?);
        let population = Digest::blake3(&to_canonical_bytes(&CalibrationPopulation {
            schema: GENERATION_VALIDATION_SCHEMA,
            known_good: &known_good,
            planted_violation: &planted_violation,
        })?);
        Ok(Self {
            schema: GENERATION_VALIDATION_SCHEMA.to_owned(),
            generation,
            artifact_manifest,
            control: control.to_owned(),
            control_version: LIFECYCLE_VERIFIER_VERSION.to_owned(),
            mediation_path: LIFECYCLE_VERIFIER_PATH.to_owned(),
            policy,
            policy_digest,
            population,
            known_good,
            known_good_result: ControlResult::Clean,
            planted_violation,
            planted_violation_result: ControlResult::Violation,
            planted_component: calibration.planted_component,
            planted_component_digest: calibration.planted_component_digest,
            mutation_digest: calibration.mutation_digest,
            coverage: Coverage {
                population: calibration.coverage,
                observed: calibration.coverage,
            },
        })
    }
}
