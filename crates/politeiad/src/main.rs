//! The local Politeia daemon and CLI.

use std::{env, fs, path::PathBuf};

use politeiad::{
    SemanticOperation,
    config::{HostTrustConfiguration, InstallationLayout},
    service::PoliteiadService,
    transport::{bind, current_request, request, serve_once},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments: Vec<String> = env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("initialize") => initialize_host(&arguments),
        Some("serve") => serve(&arguments).await,
        Some("snapshot") => send_request_document(&arguments, "snapshot").await,
        Some("status") => send(&arguments, SemanticOperation::Status).await,
        Some("commissioning") => send_request_document(&arguments, "commissioning").await,
        Some("operate") => send_request_document(&arguments, "operate").await,
        _ => Err(anyhow::anyhow!(usage())),
    }
}

async fn serve(arguments: &[String]) -> anyhow::Result<()> {
    let prefix = required_path(arguments, 2, "serve requires an installation prefix")?;
    let layout = InstallationLayout::load(&prefix)?;
    let listener = bind(&layout.socket).await?;
    let installed = HostTrustConfiguration::load(&layout)?;
    let database_url = env::var("POLITEIA_DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("POLITEIA_DATABASE_URL is required to run politeiad"))?;
    let anchors = installed.anchors()?;
    let coordinator =
        PoliteiadService::connect(layout, installed.workspace, anchors, &database_url)
            .await
            .map_err(anyhow::Error::msg)?;
    loop {
        serve_once(&listener, &coordinator).await?;
    }
}

fn initialize_host(arguments: &[String]) -> anyhow::Result<()> {
    let prefix = required_path(arguments, 2, "initialize requires an installation prefix")?;
    let configuration_path = required_path(
        arguments,
        3,
        "initialize requires a host trust configuration JSON path",
    )?;
    let configuration: HostTrustConfiguration =
        serde_json::from_slice(&fs::read(configuration_path)?)?;
    let layout = configuration.install(prefix)?;
    println!("{}", serde_json::to_string_pretty(&layout)?);
    Ok(())
}

async fn send_request_document(arguments: &[String], command: &str) -> anyhow::Result<()> {
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
        "commissioning" => SemanticOperation::Commissioning { request },
        "operate" => SemanticOperation::Operate { request },
        _ => return Err(anyhow::anyhow!("unsupported command")),
    };
    send_to_socket(socket, operation).await
}

async fn send(arguments: &[String], operation: SemanticOperation) -> anyhow::Result<()> {
    let socket = required_path(arguments, 2, "status requires a socket path")?;
    send_to_socket(socket, operation).await
}

async fn send_to_socket(socket: PathBuf, operation: SemanticOperation) -> anyhow::Result<()> {
    let response = request(
        &socket,
        &current_request(uuid::Uuid::now_v7().to_string(), operation),
    )
    .await?;
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
    "usage: politeiad initialize <prefix> <host-trust.json> | serve <prefix> | status <socket> | snapshot <socket> <signed-request.json> | commissioning <socket> <signed-request.json> | operate <socket> <signed-request.json>"
}
