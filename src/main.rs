#![allow(unused, non_camel_case_types)]
use crate::client::tls_client;
use crate::server::tls_server;
use anyhow::Result;

mod cert_verify;
mod certificate_request;
mod client;
mod common;
mod crypto;
mod extension;
mod finished;
mod handshake;
mod new_session_ticket;
mod record;
mod record_encrypted;
mod server;
mod transcript_hash;

#[tokio::main]
async fn main() -> Result<()> {
    tokio::try_join!(tls_server(), tls_client())?;
    Ok(())
}
