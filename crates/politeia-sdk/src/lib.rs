//! politeia-sdk: extension-side types.
//!
//! Extension manifests declare capabilities they require; a manifest is a
//! request for capabilities, never a grant.

#![deny(missing_docs)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The trust class of an extension, per docs/10-EXTENSIONS.md.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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

/// A typed extension manifest: the capabilities an extension requests. Every
/// field is a request the host may deny, never an entitlement.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ExtensionManifest {
    /// Stable extension identity.
    pub id: String,
    /// Extension version.
    pub version: String,
    /// The trust class requested.
    pub trust_class: TrustClass,
    /// Semantic operations the extension provides.
    pub provides: Vec<String>,
    /// Semantic actions the extension requires.
    pub required_actions: Vec<String>,
    /// Effects the extension requires.
    pub required_effects: Vec<String>,
    /// Data classes the extension handles.
    pub handled_data_classes: Vec<String>,
    /// Compatibility range with the host.
    pub compatibility: String,
}

/// A reconnaissance probe declaration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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
