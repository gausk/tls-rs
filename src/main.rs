use crate::client::tls_client;
use crate::server::tls_server;
use anyhow::Result;

mod client;
mod common;
mod server;

#[tokio::main]
async fn main() -> Result<()> {
    let server = tokio::spawn(tls_server());
    let client = tokio::spawn(tls_client());
    let (server_res, client_res) = tokio::try_join!(server, client)?;
    server_res?;
    client_res?;
    Ok(())
}
