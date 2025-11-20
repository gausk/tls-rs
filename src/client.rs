use crate::record::TlsPlainText;
use anyhow::Result;
use p256::ecdh::EphemeralSecret;
use rand::random;
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn tls_client() -> Result<()> {
    let mut tcp_stream = TcpStream::connect("127.0.0.1:4433").await?;

    // create and send ClientHello
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret.public_key();
    let pub_key_bytes = public_key.to_sec1_bytes().to_vec();

    let client_hello = TlsPlainText::client_hello(pub_key_bytes);
    tcp_stream.write_all(&client_hello.into_bytes()).await?;
    tcp_stream.flush().await?;

    // read ServerHello
    let mut data = vec![0u8; 1600];
    let len = tcp_stream.read(&mut data).await?;
    let server_hello = TlsPlainText::from_bytes(&data[0..len])?;
    println!("{:?}", server_hello);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    #[tokio::test]
    async fn test_tls_client() {
        struct ChildGuard(std::process::Child);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
            }
        }

        let mut server_p = Command::new("openssl")
            .args([
                "s_server",
                "-key",
                "certs/key.pem",
                "-cert",
                "certs/cert.pem",
                "-accept",
                "4433",
                "-quiet",
            ])
            .spawn()
            .expect("failed to start openssl");

        let _server = ChildGuard(server_p);

        tokio::time::sleep(Duration::from_secs(5)).await;
        let result = tls_client().await;
        eprintln!("{:?}", result);
    }
}
