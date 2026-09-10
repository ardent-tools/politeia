//! Local authenticated Unix-socket transport for semantic operations.

use std::{
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use politeia_protocol::{CURRENT_PROTOCOL_VERSION, ProtocolVersion, negotiate};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

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
    /// The connecting Unix peer is not the daemon's local user.
    UntrustedPeer,
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
            Self::UntrustedPeer => {
                formatter.write_str("local socket peer does not match the daemon user")
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

/// A private Unix listener that unlinks its owned endpoint when dropped.
///
/// Abrupt termination may still leave a stale endpoint; [`bind`] proves it is
/// private and unreachable before removing it on the next start.
pub struct BoundSocket {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl std::ops::Deref for BoundSocket {
    type Target = UnixListener;

    fn deref(&self) -> &Self::Target {
        &self.listener
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.mode() & 0o077 == 0
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Bind a new private local socket, removing only a proved-stale owned endpoint.
pub async fn bind(socket: &Path) -> Result<BoundSocket, TransportError> {
    let parent = socket.parent().ok_or_else(|| {
        TransportError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local socket has no parent directory",
        ))
    })?;
    let parent_metadata = parent.metadata()?;
    if parent_metadata.mode() & 0o077 != 0 {
        return Err(TransportError::InsecureSocketDirectory);
    }
    if socket.exists() {
        let metadata = std::fs::symlink_metadata(socket)?;
        if !metadata.file_type().is_socket()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != parent_metadata.uid()
        {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::AddrInUse,
                "existing local socket path is not a private owned socket",
            )));
        }
        match UnixStream::connect(socket).await {
            Ok(_) => {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "an existing local daemon owns this socket",
                )));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                std::fs::remove_file(socket)?;
            }
            Err(error) => return Err(TransportError::Io(error)),
        }
    }
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    let metadata = std::fs::symlink_metadata(socket)?;
    Ok(BoundSocket {
        listener,
        path: socket.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

/// Serve one connection through the shared semantic executor.
pub async fn serve_once(
    listener: &UnixListener,
    coordinator: &dyn CommissioningCoordinator,
) -> Result<(), TransportError> {
    let (mut stream, _) = listener.accept().await?;
    let response = match peer_is_daemon_user(&stream) {
        Err(error) => error_response(String::new(), &error),
        Ok(()) => match read_request(&mut stream).await {
            Ok(request) => {
                let request_id = request.request_id.clone();
                match handle(coordinator, request).await {
                    Ok(response) => response,
                    Err(error) => error_response(request_id, &error),
                }
            }
            Err(error) => error_response(String::new(), &error),
        },
    };
    let bytes = serde_json::to_vec(&response)
        .map_err(|error| TransportError::Encoding(error.to_string()))?;
    stream.write_all(&bytes).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

/// Send one local semantic request and read its single response.
pub async fn request(
    socket: &Path,
    request: &LocalRequest,
) -> Result<LocalResponse, TransportError> {
    let mut stream = UnixStream::connect(socket).await?;
    let bytes =
        serde_json::to_vec(request).map_err(|error| TransportError::Encoding(error.to_string()))?;
    stream.write_all(&bytes).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).await?;
    serde_json::from_str(&line).map_err(|error| TransportError::InvalidRequest(error.to_string()))
}

/// Require that a local peer belongs to the daemon's Unix user before it may
/// supply a semantic frame. Signed request admission still establishes the
/// institutional principal; peer credentials only enforce the local host edge.
fn peer_is_daemon_user(stream: &UnixStream) -> Result<(), TransportError> {
    let daemon_uid = std::fs::metadata("/proc/self")?.uid();
    if stream.peer_cred()?.uid() != daemon_uid {
        return Err(TransportError::UntrustedPeer);
    }
    Ok(())
}

async fn read_request(stream: &mut UnixStream) -> Result<LocalRequest, TransportError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(TransportError::InvalidRequest(
                "local request ended before its newline-delimited frame".to_string(),
            ));
        }
        if bytes.len().saturating_add(count) > MAX_REQUEST_BYTES {
            return Err(TransportError::RequestTooLarge);
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.contains(&b'\n') {
            break;
        }
    }
    if bytes.last() != Some(&b'\n') || bytes[..bytes.len() - 1].contains(&b'\n') {
        return Err(TransportError::InvalidRequest(
            "local request must end with one newline-delimited frame".to_string(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| TransportError::InvalidRequest(error.to_string()))
}

async fn handle(
    coordinator: &dyn CommissioningCoordinator,
    request: LocalRequest,
) -> Result<LocalResponse, TransportError> {
    let version = negotiate(&request.version).ok_or(TransportError::IncompatibleProtocol)?;
    let outcome = match execute(coordinator, request.operation).await {
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

fn error_response(request_id: String, error: &TransportError) -> LocalResponse {
    let code = match error {
        TransportError::RequestTooLarge => "request_too_large",
        TransportError::InsecureSocketDirectory => "insecure_socket_directory",
        TransportError::UntrustedPeer => "untrusted_peer",
        TransportError::InvalidRequest(_) => "invalid_request",
        TransportError::IncompatibleProtocol => "incompatible_protocol",
        TransportError::Encoding(_) => "response_encoding_failed",
        TransportError::Io(_) => "transport_io_failure",
    };
    LocalResponse {
        version: CURRENT_PROTOCOL_VERSION,
        request_id,
        outcome: LocalOutcome::Error {
            code: code.to_string(),
            message: error.to_string(),
        },
    }
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
    #![expect(
        clippy::expect_used,
        reason = "fixtures fail loudly when setup or assertions drift"
    )]
    use std::{collections::BTreeSet, fs, future::Future, pin::Pin};

    use super::*;
    use crate::{
        CoordinatorError, SourceSnapshot,
        source::{SourceSnapshotRequest, snapshot},
    };

    struct SourceCoordinator {
        capture: SourceSnapshotRequest,
    }

    impl CommissioningCoordinator for SourceCoordinator {
        fn execute(
            &self,
            operation: SemanticOperation,
        ) -> Pin<Box<dyn Future<Output = Result<OperationResult, CoordinatorError>> + Send + '_>>
        {
            Box::pin(async move {
                match operation {
                    SemanticOperation::SnapshotSource { request }
                        if request == serde_json::json!({"signed": "capture-request"}) =>
                    {
                        snapshot(self.capture.clone())
                            .map(|snapshot: SourceSnapshot| OperationResult::SourceSnapshot {
                                snapshot,
                            })
                            .map_err(|error| CoordinatorError::Refused(error.to_string()))
                    }
                    _ => Err(CoordinatorError::Refused(
                        "test coordinator rejected unsigned capture request".to_string(),
                    )),
                }
            })
        }
    }

    #[tokio::test]
    async fn local_socket_routes_source_capture_through_the_coordinator() {
        let root = std::env::temp_dir().join(format!("politeiad-transport-{}", std::process::id()));
        fs::create_dir_all(&root).expect("fixture directory is creatable");
        fs::write(root.join("source.txt"), b"source").expect("fixture source is writable");
        let run = root.join("run");
        fs::create_dir(&run).expect("fixture run directory is creatable");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700))
            .expect("fixture run directory becomes private");
        let socket = run.join("politeiad.sock");
        let listener = bind(&socket).await.expect("fixture socket binds");
        let coordinator = SourceCoordinator {
            capture: SourceSnapshotRequest {
                root: root.clone(),
                members: BTreeSet::from(["source.txt".into()]),
            },
        };
        let server = tokio::spawn(async move {
            serve_once(&listener, &coordinator)
                .await
                .expect("one valid request is served");
        });
        let response = request(
            &socket,
            &current_request(
                "request-1".to_string(),
                SemanticOperation::SnapshotSource {
                    request: serde_json::json!({"signed": "capture-request"}),
                },
            ),
        )
        .await
        .expect("local semantic request succeeds");
        server.await.expect("server task finishes");
        assert!(matches!(response.outcome, LocalOutcome::Ok { .. }));
        fs::remove_dir_all(root).expect("fixture is removable");
    }

    #[tokio::test]
    async fn bound_socket_removes_only_its_own_endpoint_on_drop() {
        let root = std::env::temp_dir().join(format!(
            "politeiad-transport-cleanup-{}",
            uuid::Uuid::now_v7()
        ));
        let run = root.join("run");
        fs::create_dir_all(&run).expect("fixture run directory is creatable");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700))
            .expect("fixture run directory becomes private");
        let socket = run.join("politeiad.sock");
        let listener = bind(&socket).await.expect("fixture socket binds");
        assert!(socket.exists(), "bound socket exists");
        drop(listener);
        assert!(
            !socket.exists(),
            "normal daemon shutdown removes its endpoint"
        );
        fs::remove_dir_all(root).expect("fixture is removable");
    }

    #[tokio::test]
    async fn malformed_frame_is_refused_without_stopping_the_next_connection() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let root = std::env::temp_dir().join(format!(
            "politeiad-transport-error-{}",
            uuid::Uuid::now_v7()
        ));
        let run = root.join("run");
        fs::create_dir_all(&run).expect("fixture directory is creatable");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700))
            .expect("fixture run directory becomes private");
        let socket = run.join("politeiad.sock");
        let listener = bind(&socket).await.expect("fixture socket binds");
        let server = tokio::spawn(async move {
            let coordinator = crate::UnavailableCoordinator;
            serve_once(&listener, &coordinator)
                .await
                .expect("malformed connection receives a refusal");
            serve_once(&listener, &coordinator)
                .await
                .expect("next connection remains servable");
        });

        let mut stream = UnixStream::connect(&socket)
            .await
            .expect("fixture client connects");
        stream
            .write_all(b"{not-json}\n")
            .await
            .expect("fixture malformed frame writes");
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .await
            .expect("malformed frame receives response");
        let malformed: LocalResponse = serde_json::from_str(&line).expect("refusal is JSON");
        assert!(matches!(
            malformed.outcome,
            LocalOutcome::Error { ref code, .. } if code == "invalid_request"
        ));

        let valid = request(
            &socket,
            &current_request("after-error".to_string(), SemanticOperation::Status),
        )
        .await
        .expect("later request receives a response");
        assert!(matches!(
            valid.outcome,
            LocalOutcome::Error { ref code, .. } if code == "coordinator_unavailable"
        ));
        server.await.expect("server task finishes");
        fs::remove_dir_all(root).expect("fixture is removable");
    }
}
