//! The local Politeia daemon and CLI.

use std::{env, path::PathBuf};

use politeiad::{
    SemanticOperation, UnavailableCoordinator,
    config::InstallationLayout,
    source::SourceSnapshotRequest,
    transport::{bind, current_request, request, serve_once},
};

fn main() -> anyhow::Result<()> {
    let arguments: Vec<String> = env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("serve") => serve(&arguments),
        Some("snapshot") => send_snapshot(&arguments),
        Some("status") => send(&arguments, SemanticOperation::Status),
        Some("initialize") => send_request_path(&arguments, "initialize"),
        Some("commissioning") => send_request_path(&arguments, "commissioning"),
        Some("operate") => send_request_path(&arguments, "operate"),
        _ => Err(anyhow::anyhow!(usage())),
    }
}

fn serve(arguments: &[String]) -> anyhow::Result<()> {
    let prefix = required_path(arguments, 2, "serve requires an installation prefix")?;
    let layout = InstallationLayout::load(&prefix)?;
    let listener = bind(&layout.socket)?;
    let coordinator = UnavailableCoordinator;
    loop {
        serve_once(&listener, &coordinator)?;
    }
}

fn send_snapshot(arguments: &[String]) -> anyhow::Result<()> {
    let socket = required_path(arguments, 2, "snapshot requires a socket path")?;
    let root = required_path(arguments, 3, "snapshot requires a source root")?;
    let members = arguments
        .get(4..)
        .ok_or_else(|| anyhow::anyhow!("snapshot requires at least one explicit member"))?
        .iter()
        .map(PathBuf::from)
        .collect();
    send_to_socket(
        socket,
        SemanticOperation::SnapshotSource {
            request: SourceSnapshotRequest { root, members },
        },
    )
}

fn send_request_path(arguments: &[String], command: &str) -> anyhow::Result<()> {
    let socket = required_path(arguments, 2, &format!("{command} requires a socket path"))?;
    let request_path = required_path(arguments, 3, &format!("{command} requires a request path"))?
        .display()
        .to_string();
    let operation = match command {
        "initialize" => SemanticOperation::Initialize { request_path },
        "commissioning" => SemanticOperation::Commissioning { request_path },
        "operate" => SemanticOperation::Operate { request_path },
        _ => return Err(anyhow::anyhow!("unsupported command")),
    };
    send_to_socket(socket, operation)
}

fn send(arguments: &[String], operation: SemanticOperation) -> anyhow::Result<()> {
    let socket = required_path(arguments, 2, "status requires a socket path")?;
    send_to_socket(socket, operation)
}

fn send_to_socket(socket: PathBuf, operation: SemanticOperation) -> anyhow::Result<()> {
    let response = request(
        &socket,
        &current_request(uuid::Uuid::now_v7().to_string(), operation),
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn required_path(arguments: &[String], index: usize, message: &str) -> anyhow::Result<PathBuf> {
    arguments
        .get(index)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!(message.to_string()))
}

fn usage() -> &'static str {
    "usage: politeiad serve <prefix> | snapshot <socket> <root> <member>... | status <socket> | initialize <socket> <signed-request> | commissioning <socket> <signed-request> | operate <socket> <operation-request>"
}
