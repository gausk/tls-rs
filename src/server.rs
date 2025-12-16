use crate::crypto::{calculate_shared_secret, derive_handshake_secret, derive_key_and_iv};
use crate::record::TlsPlainText;
use crate::transcript_hash::TranscriptHasher;
use anyhow::Result;
use p256::ecdh::EphemeralSecret;
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn tls_server() -> Result<()> {
    let tcp_server = TcpListener::bind("127.0.0.1:4433").await?;
    let (mut tcp_stream, _) = tcp_server.accept().await?;

    // Recv client hello
    let mut data = vec![0u8; 1600];
    let len = tcp_stream.read(&mut data).await?;
    let (client_hello, offset) = TlsPlainText::from_bytes(&data[0..len])?;
    assert_eq!(offset, len);
    println!("Server has received the client hello: {:?}", client_hello);

    // TODO: process client hello (currently we don't as we are the only client)

    // send server hello
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret.public_key();
    let pub_key_bytes = public_key.to_sec1_bytes().to_vec();

    let server_hello = TlsPlainText::server_hello(pub_key_bytes, client_hello.session_id());
    let server_hello_bytes = server_hello.into_bytes();
    tcp_stream.write_all(&server_hello_bytes).await?;
    tcp_stream.flush().await?;

    let shared_secret = calculate_shared_secret(&secret, client_hello.public_key()?)?;
    let mut hasher = TranscriptHasher::new();
    // client hello
    hasher.update(&data[5..offset]);
    hasher.update(&server_hello_bytes[5..]);
    let transcript_hash = hasher.finish();

    let (client_hs, server_hs) =
        derive_handshake_secret(shared_secret.raw_secret_bytes(), transcript_hash.as_ref());

    let (server_key, server_iv) = derive_key_and_iv(&server_hs);
    let (client_key, client_iv) = derive_key_and_iv(&client_hs);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::tls_client;

    #[tokio::test]
    async fn test_server_tls() {
        tokio::try_join!(tls_server(), tls_client()).unwrap_err();
    }
}
