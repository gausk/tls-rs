#![allow(unused, non_camel_case_types)]
use crate::client::tls_client;
use crate::server::tls_server;
use anyhow::Result;

mod certificate_request;
mod client;
mod common;
mod crypto;
mod encrypted_extension;
mod extension;
mod handshake;
mod record;
mod record_encrypted;
mod server;

#[tokio::main]
async fn main() -> Result<()> {
    tokio::try_join!(tls_server(), tls_client())?;
    Ok(())
}
