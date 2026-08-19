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

/// A reconnaissance probe declaration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryProbe {
    /// Probe identity.
    pub id: String,
    /// What the probe observes.
    pub description: String,
    /// Whether the probe is read-only (reconnaissance grants are read-only).
    pub read_only: bool,
    /// The observation kinds the probe emits.
    pub outputs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
