use crate::crypto::{
    TlsDataKeyInfo, calculate_shared_secret, derive_handshake_secret, derive_key_and_iv,
};
use crate::record::TlsPlainText;
use crate::record_encrypted::TlsCipherText;
use crate::transcript_hash::TranscriptHasher;
use anyhow::Result;
use p256::ecdh::EphemeralSecret;
use rand::random;
use rand_core::OsRng;
use std::ptr::hash;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn tls_client() -> Result<()> {
    let mut tcp_stream = TcpStream::connect("127.0.0.1:4433").await?;

    // create and send ClientHello
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret.public_key();
    let pub_key_bytes = public_key.to_sec1_bytes().to_vec();

    let client_hello = TlsPlainText::client_hello(pub_key_bytes);
    println!("sending client_hello: {:?}", client_hello);
    let client_hello_bytes = client_hello.into_bytes();
    tcp_stream.write_all(&client_hello_bytes).await?;
    tcp_stream.flush().await?;

    // read ServerHello
    let mut data = vec![0u8; 3200];
    let len = tcp_stream.read(&mut data).await?;
    let (server_hello, mut offset) = TlsPlainText::from_bytes(&data[0..len])?;
    println!("Received server_hello: {:?}", server_hello);
    println!("Received remaining data: {:?}", &data[offset..len]);

    let shared_secret = calculate_shared_secret(&secret, server_hello.public_key()?)?;
    let mut hasher = TranscriptHasher::new();
    hasher.update(&client_hello_bytes);
    hasher.update(&data[0..offset]);
    let transcript_hash = hasher.finish();

    let (client_hs, server_hs) =
        derive_handshake_secret(shared_secret.raw_secret_bytes(), transcript_hash.as_ref());
    println!("client_hs: {}", hex::encode(&client_hs));
    println!("server_hs: {}", hex::encode(&server_hs));

    let (server_key, server_iv) = derive_key_and_iv(&server_hs);
    println!("server_key: {}", hex::encode(&server_key));
    let mut server_tls_data_key = TlsDataKeyInfo::new(server_key, server_iv);
    let (client_key, client_iv) = derive_key_and_iv(&client_hs);
    println!("client_key: {}", hex::encode(&client_key));

    let (tls_cipher_text, update_offset) = TlsCipherText::from_bytes(&data[offset..len])?;
    println!("Tls cipher text {:?}", tls_cipher_text);
    println!("offset for decryption: {:?}", &data[offset..offset + 5]);
    let decrypted_inner_info = server_tls_data_key
        .decrypt(&tls_cipher_text.encrypted_record, &data[offset..offset + 5])?;
    offset += update_offset;
    println!("decrypted inner_info: {:?}", decrypted_inner_info);
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
                "-tls1_3",
                "-no_middlebox",
                "-quiet",
                "-keylogfile",
                "/tmp/sslkeys.log",
            ])
            .spawn()
            .expect("failed to start openssl");

        let _server = ChildGuard(server_p);

        tokio::time::sleep(Duration::from_secs(5)).await;
        let result = tls_client().await;
        //eprintln!("{:?}", result);
    }
}
