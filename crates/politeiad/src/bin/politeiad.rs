//! Local Politeia daemon entrypoint, sharing the administrative coordinator.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    politeiad::cli::run().await
}
