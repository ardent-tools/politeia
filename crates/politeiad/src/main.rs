//! Administrative CLI for the local Politeia service.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    politeiad::cli::run().await
}
