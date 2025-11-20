use crate::record::TlsPlainText;
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
    let client_hello = TlsPlainText::from_bytes(&data[0..len])?;
    println!("{:?}", client_hello);

    // TODO: process client hello (currently we don't as we are the only client)

    // send server hello
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret.public_key();
    let pub_key_bytes = public_key.to_sec1_bytes().to_vec();

    let server_hello = TlsPlainText::server_hello(pub_key_bytes, client_hello.session_id());
    tcp_stream.write_all(&server_hello.into_bytes()).await?;
    tcp_stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::tls_client;

    #[tokio::test]
    async fn test_server_tls() {
        tokio::try_join!(tls_server(), tls_client()).unwrap();
    }
}
