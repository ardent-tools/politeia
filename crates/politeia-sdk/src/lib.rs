//! politeia-sdk: extension-side types.
//!
//! Extension manifests declare capabilities they require; a manifest is a
//! request for capabilities, never a grant.

#![deny(missing_docs)]

use std::collections::BTreeSet;

use politeia_core::{DataClass, Digest, Effect, ResourceBudget};
use politeia_protocol::ProtocolRequirement;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The trust class of an extension, per docs/10-EXTENSIONS.md.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// Declarative domain pack: knowledge, probes, mappings, policy templates.
    Declarative,
    /// Small audited kernel-adjacent component running in process.
    TrustedInProcess,
    /// External-system bridge under OS/process isolation.
    IsolatedNative,
    /// Third-party executable code under the sandboxed component boundary.
    SandboxedComponent,
}

/// Capabilities and effect surfaces requested by an extension.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtensionRequirements {
    /// Named host capabilities the extension requests.
    pub capabilities: BTreeSet<String>,
    /// Semantic actions the extension requests.
    pub actions: BTreeSet<String>,
    /// Externally visible effects the extension requests.
    pub effects: BTreeSet<Effect>,
    /// Resource patterns the extension requests.
    pub resources: BTreeSet<String>,
    /// Data classes the extension handles.
    pub data_classes: BTreeSet<DataClass>,
    /// Network access the extension requests.
    pub network: BTreeSet<String>,
    /// Process execution the extension requests.
    pub process: BTreeSet<String>,
    /// Filesystem access the extension requests.
    pub filesystem: BTreeSet<String>,
    /// Schemas the extension consumes or produces.
    pub schemas: BTreeSet<String>,
    /// Resource budget requested from the host.
    pub budget: ResourceBudget,
}

/// Provenance and signature binding for an extension package.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtensionProvenance {
    /// Digest of the exact extension package.
    pub package_digest: Digest,
    /// Identity of the signer or attesting authority.
    pub signer: String,
    /// Signature over the package digest.
    pub signature: String,
}

/// A typed extension manifest: the capabilities an extension requests. Every
/// requirement is a request the host may deny, never an entitlement.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtensionManifest {
    /// Stable extension identity.
    pub id: String,
    /// Extension version.
    pub version: String,
    /// Typed compatibility requirement for the host semantic protocol.
    pub compatibility: ProtocolRequirement,
    /// The trust class requested.
    pub trust_class: TrustClass,
    /// Semantic operations the extension provides.
    pub provides: Vec<String>,
    /// Capabilities and bounded resources requested from the host.
    pub requires: ExtensionRequirements,
    /// Provenance and signature over the exact extension package.
    pub provenance: ExtensionProvenance,
}

impl ExtensionManifest {
    /// Whether this extension only reads.
    pub fn is_read_only(&self) -> bool {
        !self.requires.effects.iter().any(Effect::mutates)
    }

    /// Check that a probe stays inside what its manifest requested.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeRefusal::EffectsExceedManifest`] when the probe produces
    /// an effect the manifest does not request.
    ///
    /// Time: O(p log m) for p probe effects against m manifest effects.
    /// Space: O(p).
    pub fn admits_probe(&self, probe: &DiscoveryProbe) -> Result<(), ProbeRefusal> {
        let excess: BTreeSet<Effect> = probe
            .effects
            .difference(&self.requires.effects)
            .cloned()
            .collect();
        if excess.is_empty() {
            Ok(())
        } else {
            Err(ProbeRefusal::EffectsExceedManifest { excess })
        }
    }
}

/// A reconnaissance probe declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryProbe {
    /// Probe identity.
    pub id: String,
    /// What the probe observes.
    pub description: String,
    /// Externally visible effects the probe produces.
    ///
    /// WHY effects rather than a `read_only` flag: a flag is an assertion
    /// nothing can contradict. A probe declaring itself read-only beside an
    /// effect set containing `WriteExternalSystem` is self-inconsistent, and
    /// with two fields carrying one fact the reader has to guess which is
    /// true. Reading the property off the effects leaves one fact in one place.
    pub effects: BTreeSet<Effect>,
    /// The observation kinds the probe emits.
    pub outputs: Vec<String>,
}

impl DiscoveryProbe {
    /// Whether this probe only reads.
    ///
    /// Derived, not declared. `docs/03-ONTOLOGY.md` makes reconnaissance
    /// authority read-only, and `politeia_core::Effect::mutates` is the single
    /// classification that decides -- the same one
    /// `politeia_core::reconnaissance` applies to a commissioner's delegation.
    /// Two layers ask the question; one answer decides it.
    pub fn is_read_only(&self) -> bool {
        !self.effects.iter().any(Effect::mutates)
    }

    /// The effects that make this probe not read-only.
    pub fn mutating_effects(&self) -> BTreeSet<Effect> {
        self.effects
            .iter()
            .filter(|effect| effect.mutates())
            .cloned()
            .collect()
    }
}

/// Why a probe may not be carried by a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeRefusal {
    /// The probe produces effects its extension never requested.
    ///
    /// A manifest is a request the host may deny, so a probe reaching past it
    /// is asking the host to grant something it was never shown. This is the
    /// attenuation rule the rest of the kernel applies to delegations, at the
    /// extension boundary.
    EffectsExceedManifest {
        /// The effects requested by the probe and not by the manifest.
        excess: BTreeSet<Effect>,
    },
}

impl std::fmt::Display for ProbeRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeRefusal::EffectsExceedManifest { excess } => write!(
                formatter,
                "the probe produces {excess:?}, which its manifest does not request"
            ),
        }
    }
}

impl std::error::Error for ProbeRefusal {}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(effects: &[Effect]) -> DiscoveryProbe {
        DiscoveryProbe {
            id: "probe.contacts".to_string(),
            description: "lists contact records".to_string(),
            effects: effects.iter().cloned().collect(),
            outputs: vec!["contact".to_string()],
        }
    }

    #[test]
    fn a_probe_that_only_reads_is_read_only() {
        assert!(probe(&[Effect::ReadExternalSystem]).is_read_only());
        assert!(probe(&[]).is_read_only());
    }

    #[test]
    fn a_probe_cannot_declare_itself_read_only_past_its_effects() {
        // The case a declared flag cannot catch: a probe asserting it only
        // reads, beside an effect set that writes. With one fact in one place
        // the assertion has nowhere to disagree from.
        let writing = probe(&[Effect::ReadExternalSystem, Effect::WriteExternalSystem]);
        assert!(!writing.is_read_only());
        assert_eq!(
            writing.mutating_effects(),
            BTreeSet::from([Effect::WriteExternalSystem]),
            "the answer names what makes it so, not merely that it is so"
        );
    }

    #[test]
    fn read_only_is_the_same_judgement_the_kernel_makes_of_a_delegation() {
        // One classification, two layers. `politeia_core::reconnaissance`
        // refuses a commissioner delegation carrying a mutating effect; this
        // refuses a probe for the same reason, by the same function, so the
        // extension boundary and the authority boundary cannot drift apart on
        // what "read-only" means.
        for effect in [
            Effect::ReadFilesystem,
            Effect::ReadSecret,
            Effect::ReadExternalSystem,
            Effect::WriteFilesystem,
            Effect::SpawnProcess,
            Effect::NetworkEgress,
            Effect::WriteSecret,
            Effect::WriteExternalSystem,
            Effect::CreateArtifact,
            Effect::ChangeAuthorization,
        ] {
            assert_eq!(
                probe(&[effect.clone()]).is_read_only(),
                !effect.mutates(),
                "{effect:?} must be judged the same way in both layers"
            );
        }
    }

    #[test]
    fn a_probe_may_not_reach_past_what_its_manifest_requested() {
        // A manifest is a request the host may deny, so a probe exceeding it is
        // asking the host to grant something it was never shown. The same
        // attenuation rule the kernel applies to delegations, at the extension
        // boundary.
        let manifest = manifest();
        assert_eq!(
            manifest.admits_probe(&probe(&[Effect::ReadExternalSystem])),
            Ok(())
        );
        assert_eq!(
            manifest.admits_probe(&probe(&[Effect::WriteExternalSystem])),
            Err(ProbeRefusal::EffectsExceedManifest {
                excess: BTreeSet::from([Effect::WriteExternalSystem]),
            })
        );
    }

    #[test]
    fn a_manifest_requesting_only_reads_is_read_only() {
        let mut requesting = manifest();
        assert!(requesting.is_read_only());
        requesting.requires.effects.insert(Effect::CreateArtifact);
        assert!(!requesting.is_read_only());
    }

    fn manifest() -> ExtensionManifest {
        ExtensionManifest {
            id: "example.extension".to_string(),
            version: "0.1.0".to_string(),
            compatibility: ProtocolRequirement {
                major: 1,
                minimum_minor: 0,
            },
            trust_class: TrustClass::Declarative,
            provides: vec!["institution.observe".to_string()],
            requires: ExtensionRequirements {
                capabilities: BTreeSet::from(["observation.emit".to_string()]),
                actions: BTreeSet::from(["read".to_string()]),
                effects: BTreeSet::from([Effect::ReadExternalSystem]),
                resources: BTreeSet::from(["source:example".to_string()]),
                data_classes: BTreeSet::from([DataClass::Public]),
                network: BTreeSet::new(),
                process: BTreeSet::new(),
                filesystem: BTreeSet::new(),
                schemas: BTreeSet::from(["urn:example:observation:v1".to_string()]),
                budget: ResourceBudget {
                    wall_ms: Some(1_000),
                    cpu_ms: None,
                    memory_bytes: None,
                    io_bytes: None,
                    network_bytes: None,
                    external_cost_microunits: None,
                },
            },
            provenance: ExtensionProvenance {
                package_digest: Digest::blake3(b"example extension package"),
                signer: "example.test".to_string(),
                signature: "synthetic-signature".to_string(),
            },
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "valid manifest fixtures must serialize and deserialize"
    )]
    fn manifest_round_trips_with_snake_case_wire_vocabulary() {
        let encoded = serde_json::to_value(manifest()).expect("manifest serializes");
        assert_eq!(
            encoded
                .get("trust_class")
                .expect("manifest must include its trust class"),
            "declarative",
            "trust classes must use the public snake_case vocabulary"
        );
        let decoded: ExtensionManifest =
            serde_json::from_value(encoded).expect("manifest deserializes");
        assert_eq!(
            decoded.id, "example.extension",
            "the manifest identity must survive a wire round trip"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "unknown-field mutation requires a valid manifest object baseline"
    )]
    fn manifest_rejects_unknown_fields() {
        let mut encoded = serde_json::to_value(manifest()).expect("manifest serializes");
        encoded
            .as_object_mut()
            .expect("manifest is a JSON object")
            .insert(
                "ambient_authority".to_string(),
                serde_json::Value::Bool(true),
            );
        let result = serde_json::from_value::<ExtensionManifest>(encoded);
        assert!(
            result.is_err(),
            "unknown manifest fields must fail closed instead of being ignored"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "unknown-vocabulary mutation requires a valid requirements baseline"
    )]
    fn manifest_rejects_unknown_effect_vocabulary() {
        let mut encoded = serde_json::to_value(manifest()).expect("manifest serializes");
        let effects = encoded
            .get_mut("requires")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|requires| requires.get_mut("effects"))
            .expect("manifest requirements must include effects");
        *effects = serde_json::json!(["invented_effect"]);

        let result = serde_json::from_value::<ExtensionManifest>(encoded);
        assert!(
            result.is_err(),
            "unknown effect names must fail closed against the canonical vocabulary"
        );
    }
}
