//! The local Politeia daemon and CLI.

use std::{env, fs, path::PathBuf};

use politeiad::{
    SemanticOperation, UnavailableCoordinator,
    config::InstallationLayout,
    transport::{bind, current_request, request, serve_once},
};

fn main() -> anyhow::Result<()> {
    let arguments: Vec<String> = env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("serve") => serve(&arguments),
        Some("snapshot") => send_request_document(&arguments, "snapshot"),
        Some("status") => send(&arguments, SemanticOperation::Status),
        Some("initialize") => send_request_document(&arguments, "initialize"),
        Some("commissioning") => send_request_document(&arguments, "commissioning"),
        Some("operate") => send_request_document(&arguments, "operate"),
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

fn send_request_document(arguments: &[String], command: &str) -> anyhow::Result<()> {
    let socket = required_path(arguments, 2, &format!("{command} requires a socket path"))?;
    let document_path = required_path(
        arguments,
        3,
        &format!("{command} requires a signed JSON document path"),
    )?;
    // This is a CLI-local read. The socket protocol contains the document
    // bytes, so the daemon never opens a client-selected filesystem path.
    let request = serde_json::from_slice(&fs::read(document_path)?)?;
    let operation = match command {
        "snapshot" => SemanticOperation::SnapshotSource { request },
        "initialize" => SemanticOperation::Initialize { request },
        "commissioning" => SemanticOperation::Commissioning { request },
        "operate" => SemanticOperation::Operate { request },
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
    "usage: politeiad serve <prefix> | status <socket> | snapshot <socket> <signed-request.json> | initialize <socket> <signed-request.json> | commissioning <socket> <signed-request.json> | operate <socket> <signed-request.json>"
}
