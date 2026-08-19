use politeia_core::PrincipalId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const SEMANTIC_PROTOCOL_MAJOR: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SemanticRequest {
    pub version: ProtocolVersion,
    pub principal: PrincipalId,
    pub operation: String,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SemanticResponse {
    pub version: ProtocolVersion,
    pub result: serde_json::Value,
    pub evidence_refs: Vec<String>,
}

pub fn negotiate(peer: &ProtocolVersion) -> Option<ProtocolVersion> {
    (peer.major == SEMANTIC_PROTOCOL_MAJOR).then(|| ProtocolVersion {
        major: SEMANTIC_PROTOCOL_MAJOR,
        minor: peer.minor,
    })
}
