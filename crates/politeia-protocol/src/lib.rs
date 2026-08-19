//! politeia-protocol: the transport-independent semantic protocol envelope.
//!
//! MCP, A2A, HTTP/gRPC, CLI, and embedded use are transports over the same
//! operation model. No transport may reinterpret semantic operation meaning.

#![deny(missing_docs)]

use politeia_core::PrincipalId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The semantic protocol major version this crate speaks.
pub const SEMANTIC_PROTOCOL_MAJOR: u16 = 1;

/// A protocol version (major.minor). Compatibility is decided on major.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProtocolVersion {
    /// Major version; peers must match.
    pub major: u16,
    /// Minor version; informational within a major.
    pub minor: u16,
}

/// A semantic request envelope.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SemanticRequest {
    /// The protocol version the caller speaks.
    pub version: ProtocolVersion,
    /// The principal issuing the request.
    pub principal: PrincipalId,
    /// The semantic operation name (see docs/05-SEMANTIC_PROTOCOL.md).
    pub operation: String,
    /// The operation payload.
    pub payload: serde_json::Value,
}

/// A semantic response envelope.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SemanticResponse {
    /// The negotiated protocol version.
    pub version: ProtocolVersion,
    /// The operation result.
    pub result: serde_json::Value,
    /// References to evidence produced while serving the request.
    pub evidence_refs: Vec<String>,
}

/// Negotiate a protocol version with a peer. Returns `Some` with the peer's
/// minor when majors match, `None` otherwise (fail-closed on major mismatch).
pub fn negotiate(peer: &ProtocolVersion) -> Option<ProtocolVersion> {
    (peer.major == SEMANTIC_PROTOCOL_MAJOR).then_some(ProtocolVersion {
        major: SEMANTIC_PROTOCOL_MAJOR,
        minor: peer.minor,
    })
}
