#![allow(unused)]
use crate::client::tls_client;
use crate::server::tls_server;
use anyhow::Result;

mod client;
mod common;
mod handshake;
mod record;
mod server;

#[tokio::main]
async fn main() -> Result<()> {
    tokio::try_join!(tls_server(), tls_client())?;
    Ok(())
}
