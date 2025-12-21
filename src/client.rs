use crate::crypto::{
    TlsDataKeyInfo, calculate_shared_secret, derive_finished_key, derive_handshake_secret,
    derive_key_and_iv, derive_traffic_secret,
};
use crate::record::TlsPlainText;
use crate::record_encrypted::TlsCipherText;
use crate::transcript_hash::TranscriptHasher;
use anyhow::Result;
use p256::ecdh::EphemeralSecret;
use rand::random;
use rand_core::OsRng;
use std::ptr::hash;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

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

    let shared_secret = calculate_shared_secret(&secret, server_hello.public_key()?)?;
    let mut hasher = TranscriptHasher::new();
    let mut finished_hasher = TranscriptHasher::new();
    // First 5 bytes are record header
    hasher.update(&client_hello_bytes[5..]);
    hasher.update(&data[5..offset]);
    let transcript_hash = hasher.finish();

    finished_hasher.update(&client_hello_bytes[5..]);
    finished_hasher.update(&data[5..offset]);

    let (client_hs, server_hs, derived_secret) =
        derive_handshake_secret(shared_secret.raw_secret_bytes(), transcript_hash.as_ref());
    println!(
        "ECDHE shared secret: {}",
        hex::encode(shared_secret.raw_secret_bytes())
    );
    println!("client_hs: {}", hex::encode(&client_hs));
    println!("server_hs: {}", hex::encode(&server_hs));

    let (server_key, server_iv) = derive_key_and_iv(&server_hs);
    println!("server_key: {}", hex::encode(&server_key));
    let mut server_tls_data_key = TlsDataKeyInfo::new(server_key, server_iv)?;
    let (client_key, client_iv) = derive_key_and_iv(&client_hs);
    println!("client_key: {}", hex::encode(&client_key));
    let mut client_tls_data_key = TlsDataKeyInfo::new(client_key, client_iv)?;

    let (encrypted_extensions, update_offset) =
        TlsCipherText::from_bytes(&data[offset..len], &mut server_tls_data_key)?;
    println!(
        "Received server Encrypted Extensions message {:?}",
        encrypted_extensions
    );
    offset += update_offset;
    finished_hasher.update(&encrypted_extensions.handshake_bytes());

    let (certificate, update_offset) =
        TlsCipherText::from_bytes(&data[offset..len], &mut server_tls_data_key)?;
    println!("Received server certificate message {:?}", certificate);
    offset += update_offset;

    finished_hasher.update(&certificate.handshake_bytes());

    let (certificate_verify, update_offset) =
        TlsCipherText::from_bytes(&data[offset..len], &mut server_tls_data_key)?;
    println!(
        "Received server certificate_verify message {:?}",
        certificate_verify
    );
    offset += update_offset;
    // TODO: Verify signature
    finished_hasher.update(&certificate_verify.handshake_bytes());

    let (finished, update_offset) =
        TlsCipherText::from_bytes(&data[offset..len], &mut server_tls_data_key)?;
    println!("Received server finished message {:?}", finished);
    offset += update_offset;
    // TODO: Verify server finished message
    finished_hasher.update(&finished.handshake_bytes());

    let client_finished_key = derive_finished_key(&client_hs);
    let finished_hash = finished_hasher.finish();
    let client_finished =
        TlsCipherText::client_finished(client_finished_key, finished_hash.as_ref())?;
    println!("Client finished message: {:?}", client_finished);
    let client_finished_bytes = client_finished.into_bytes(&mut client_tls_data_key)?;

    tcp_stream.write_all(&client_finished_bytes).await?;
    tcp_stream.flush().await?;

    let (client_application_traffic_secret_0, server_application_traffic_secret_0) =
        derive_traffic_secret(&derived_secret, finished_hash.as_ref());
    println!(
        "client_application_traffic_secret_0: {}",
        hex::encode(&client_application_traffic_secret_0)
    );
    println!(
        "server_application_traffic_secret_0: {}",
        hex::encode(&server_application_traffic_secret_0)
    );
    let (client_key, client_iv) = derive_key_and_iv(&client_application_traffic_secret_0);
    let mut client_app_key = TlsDataKeyInfo::new(client_key, client_iv)?;
    let (server_key, server_iv) = derive_key_and_iv(&server_application_traffic_secret_0);
    let mut server_app_key = TlsDataKeyInfo::new(server_key, server_iv)?;

    time::sleep(Duration::from_secs(1)).await;
    let mut data = vec![0u8; 3200];
    let len = tcp_stream.read(&mut data).await?;
    let (new_session_ticket, mut offset) =
        TlsCipherText::from_bytes(&data[..len], &mut server_app_key)?;
    println!(
        "Received 1st server new_session_ticket message {:?}",
        new_session_ticket
    );

    let (new_session_ticket, update_offset) =
        TlsCipherText::from_bytes(&data[offset..len], &mut server_app_key)?;
    println!(
        "Received 2nd server new_session_ticket message {:?}",
        new_session_ticket
    );
    offset += update_offset;
    if offset < len {
        let (server_data, update_offset) =
            TlsCipherText::from_bytes(&data[offset..len], &mut server_app_key)?;
        println!("Received server data {:?}", server_data);
        offset += update_offset;
    }
    assert!(offset == len);

    let data_ciphertext = TlsCipherText::from_application_data(b"Hello TLS 1.3 server".to_vec());
    let data_ciphertext_bytes = data_ciphertext.into_bytes(&mut client_app_key)?;
    println!("Client data ciphertext bytes: {:?}", data_ciphertext_bytes);
    tcp_stream.write_all(&data_ciphertext_bytes).await?;
    tcp_stream.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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
                "-msgfile",
                "/tmp/msg.log",
                //"-msg",
                //"-debug",
            ])
            .stdin(Stdio::piped())
            .spawn()
            .expect("failed to start openssl");

        tokio::time::sleep(Duration::from_secs(5)).await;
        if let Some(stdin) = server_p.stdin.as_mut() {
            stdin.write_all(b"Hello TLS 1.3 client").unwrap();
        }
        let _server = ChildGuard(server_p);
        let result = tls_client().await.unwrap();
    }
}
