//! Local authenticated Unix-socket transport for semantic operations.

use std::{
    io::{self, BufRead, BufReader, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
};

use politeia_protocol::{CURRENT_PROTOCOL_VERSION, ProtocolVersion, negotiate};
use serde::{Deserialize, Serialize};

use crate::{CommissioningCoordinator, OperationResult, SemanticOperation, execute};

const MAX_REQUEST_BYTES: usize = 1_048_576;

/// One newline-delimited local semantic request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRequest {
    /// Protocol version spoken by the caller.
    pub version: ProtocolVersion,
    /// Caller-chosen correlation identifier with no authority meaning.
    pub request_id: String,
    /// Transport-neutral semantic operation.
    pub operation: SemanticOperation,
}

/// One newline-delimited local semantic response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalResponse {
    /// Version successfully negotiated by the server.
    pub version: ProtocolVersion,
    /// Request correlation identifier copied from the request.
    pub request_id: String,
    /// Result or a typed failure.
    pub outcome: LocalOutcome,
}

/// A local operation outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalOutcome {
    /// The semantic operation completed.
    Ok {
        /// Evidence-bearing semantic result.
        result: OperationResult,
    },
    /// The request was rejected without a semantic state change.
    Error {
        /// Stable machine-readable failure class.
        code: String,
        /// Human-readable diagnostic without private payload echoing.
        message: String,
    },
}

/// Why the local transport could not serve a request.
#[derive(Debug)]
#[non_exhaustive]
pub enum TransportError {
    /// Socket creation, I/O, or peer credential inspection failed.
    Io(io::Error),
    /// A request exceeded the bounded local frame size.
    RequestTooLarge,
    /// The socket directory permits a different local user to reach the endpoint.
    InsecureSocketDirectory,
    /// The request was not valid JSON for the typed envelope.
    InvalidRequest(String),
    /// Caller and server do not speak the same semantic protocol major version.
    IncompatibleProtocol,
    /// Response serialization failed.
    Encoding(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "local socket I/O failed: {error}"),
            Self::RequestTooLarge => {
                formatter.write_str("local request exceeds the configured frame limit")
            }
            Self::InsecureSocketDirectory => {
                formatter.write_str("local socket parent must not grant group or other access")
            }
            Self::InvalidRequest(error) => write!(formatter, "local request is invalid: {error}"),
            Self::IncompatibleProtocol => {
                formatter.write_str("local request has an incompatible semantic protocol version")
            }
            Self::Encoding(error) => {
                write!(formatter, "local response could not be encoded: {error}")
            }
        }
    }
}

impl std::error::Error for TransportError {}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Bind a new private local socket without unlinking a prior endpoint.
pub fn bind(socket: &Path) -> Result<UnixListener, TransportError> {
    let parent = socket.parent().ok_or_else(|| {
        TransportError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local socket has no parent directory",
        ))
    })?;
    if parent.metadata()?.mode() & 0o077 != 0 {
        return Err(TransportError::InsecureSocketDirectory);
    }
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serve one connection through the shared semantic executor.
pub fn serve_once(
    listener: &UnixListener,
    coordinator: &dyn CommissioningCoordinator,
) -> Result<(), TransportError> {
    let (stream, _) = listener.accept()?;
    let response = read_request(&stream).and_then(|request| handle(coordinator, request));
    let mut writer = stream;
    let bytes = serde_json::to_vec(&response?)
        .map_err(|error| TransportError::Encoding(error.to_string()))?;
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Send one local semantic request and read its single response.
pub fn request(socket: &Path, request: &LocalRequest) -> Result<LocalResponse, TransportError> {
    let mut stream = UnixStream::connect(socket)?;
    let bytes =
        serde_json::to_vec(request).map_err(|error| TransportError::Encoding(error.to_string()))?;
    stream.write_all(&bytes)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    serde_json::from_str(&line).map_err(|error| TransportError::InvalidRequest(error.to_string()))
}

fn read_request(stream: &UnixStream) -> Result<LocalRequest, TransportError> {
    let mut line = String::new();
    let bytes = BufReader::new(stream).read_line(&mut line)?;
    if bytes > MAX_REQUEST_BYTES {
        return Err(TransportError::RequestTooLarge);
    }
    serde_json::from_str(&line).map_err(|error| TransportError::InvalidRequest(error.to_string()))
}

fn handle(
    coordinator: &dyn CommissioningCoordinator,
    request: LocalRequest,
) -> Result<LocalResponse, TransportError> {
    let version = negotiate(&request.version).ok_or(TransportError::IncompatibleProtocol)?;
    let outcome = match execute(coordinator, request.operation) {
        Ok(result) => LocalOutcome::Ok { result },
        Err(error) => LocalOutcome::Error {
            code: match error {
                crate::CoordinatorError::Unavailable => "coordinator_unavailable".to_string(),
                crate::CoordinatorError::Refused(_) => "semantic_refusal".to_string(),
            },
            message: error.to_string(),
        },
    };
    Ok(LocalResponse {
        version,
        request_id: request.request_id,
        outcome,
    })
}

/// Build a current-version request for CLI callers.
pub fn current_request(request_id: String, operation: SemanticOperation) -> LocalRequest {
    LocalRequest {
        version: CURRENT_PROTOCOL_VERSION,
        request_id,
        operation,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, thread};

    use super::*;
    use crate::{UnavailableCoordinator, source::SourceSnapshotRequest};

    #[test]
    fn local_socket_runs_the_same_source_operation_as_the_application() {
        let root = std::env::temp_dir().join(format!("politeiad-transport-{}", std::process::id()));
        fs::create_dir_all(&root).expect("fixture directory is creatable");
        fs::write(root.join("source.txt"), b"source").expect("fixture source is writable");
        let run = root.join("run");
        fs::create_dir(&run).expect("fixture run directory is creatable");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700))
            .expect("fixture run directory becomes private");
        let socket = run.join("politeiad.sock");
        let listener = bind(&socket).expect("fixture socket binds");
        let server = thread::spawn(move || {
            serve_once(&listener, &UnavailableCoordinator).expect("one valid request is served");
        });
        let response = request(
            &socket,
            &current_request(
                "request-1".to_string(),
                SemanticOperation::SnapshotSource {
                    request: SourceSnapshotRequest {
                        root: root.clone(),
                        members: BTreeSet::from(["source.txt".into()]),
                    },
                },
            ),
        )
        .expect("local semantic request succeeds");
        server.join().expect("server thread finishes");
        assert!(matches!(response.outcome, LocalOutcome::Ok { .. }));
        fs::remove_dir_all(root).expect("fixture is removable");
    }
}
