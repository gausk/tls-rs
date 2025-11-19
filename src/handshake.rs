use crate::common::{TlsClientHello, TlsServerHello};
use anyhow::{Result, bail};
use num_enum::TryFromPrimitive;

#[derive(Debug, Clone, TryFromPrimitive, PartialEq)]
#[repr(u8)]
pub enum HandShakeType {
    client_hello = 1,
    server_hello = 2,
}

/// struct {
///     HandshakeType msg_type;    /* handshake type */
///     uint24 length;             /* remaining bytes in message */
///     select (Handshake.msg_type) {
///     case client_hello:          ClientHello;
///     case server_hello:          ServerHello;
///     case end_of_early_data:     EndOfEarlyData;
///     case encrypted_extensions:  EncryptedExtensions;
///     case certificate_request:   CertificateRequest;
///     case certificate:           Certificate;
///     case certificate_verify:    CertificateVerify;
///     case finished:              Finished;
///     case new_session_ticket:    NewSessionTicket;
///     case key_update:            KeyUpdate;
///     };
/// } Handshake;
#[derive(Debug)]
pub enum HandShake {
    ClientHello(TlsClientHello),
    ServerHello(TlsServerHello),
}

impl HandShake {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            HandShake::ClientHello(hello) => {
                out.push(HandShakeType::client_hello as u8);
                let data = hello.into_bytes();
                let len = (data.len() as u32).to_be_bytes();
                assert!(len[0] == 0);
                out.extend([len[1], len[2], len[3]]);
                out.extend(data);
            }
            HandShake::ServerHello(hello) => {
                out.push(HandShakeType::server_hello as u8);
                let data = hello.into_bytes();
                let len = (data.len() as u32).to_be_bytes();
                assert!(len[0] == 0);
                out.extend([len[1], len[2], len[3]]);
                out.extend(data);
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<HandShake> {
        let mut offset = 0;
        let len = bytes.len();
        if len < 3 {
            bail!("invalid handshake data");
        }
        let handshake_type = HandShakeType::try_from(bytes[0])?;
        offset += 1;
        let handshake_len: u32 = (bytes[offset] as u32) << 16
            | (bytes[offset + 1] as u32) << 8
            | (bytes[offset + 2] as u32);
        offset += 3;
        if offset + handshake_len as usize != len {
            bail!(
                "invalid handshake length expected {}, got {}",
                offset + handshake_len as usize,
                len
            );
        }
        Ok(match handshake_type {
            HandShakeType::client_hello => {
                let client = TlsClientHello::from_bytes(&bytes[offset..])?;
                HandShake::ClientHello(client)
            }
            HandShakeType::server_hello => {
                let server = TlsServerHello::from_bytes(&bytes[offset..])?;
                HandShake::ServerHello(server)
            }
        })
    }

    pub fn client_hello(share_pub_key: Vec<u8>) -> Self {
        HandShake::ClientHello(TlsClientHello::new(share_pub_key))
    }
}
