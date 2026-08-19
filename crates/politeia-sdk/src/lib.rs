use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum TrustClass {
    Declarative,
    TrustedInProcess,
    IsolatedNative,
    SandboxedComponent,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ExtensionManifest {
    pub id: String,
    pub version: String,
    pub trust_class: TrustClass,
    pub provides: Vec<String>,
    pub required_actions: Vec<String>,
    pub required_effects: Vec<String>,
    pub handled_data_classes: Vec<String>,
    pub compatibility: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DiscoveryProbe {
    pub id: String,
    pub description: String,
    pub read_only: bool,
    pub outputs: Vec<String>,
}
