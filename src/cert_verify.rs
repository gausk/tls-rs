use crate::extension::SignatureScheme;
use anyhow::{Result, bail};

/// This message is used to provide explicit proof that an endpoint
/// possesses the private key corresponding to its certificate.  The
/// CertificateVerify message also provides integrity for the handshake
/// up to this point.
/// struct {
///     SignatureScheme algorithm;
///     opaque signature<0..2^16-1>;
/// }
/// Transcript-Hash(Handshake Context, Certificate)
///
/// The digital signature is then computed over the concatenation of:
///
/// -  A string that consists of octet 32 (0x20) repeated 64 times
///
/// -  The context string
///
/// -  A single 0 byte which serves as the separator
///
/// -  The content to be signed
///
/// The context string for a server signature is
/// "TLS 1.3, server CertificateVerify".  The context string for a
/// client signature is "TLS 1.3, client CertificateVerify"
#[derive(Debug)]
pub struct CertificateVerify {
    algorithm: SignatureScheme,
    signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let algorithm = SignatureScheme::try_from(u16::from_be_bytes([data[0], data[1]]))?;
        let sign_len = u16::from_be_bytes([data[2], data[3]]);
        if sign_len as usize + 4 != data.len() {
            bail!("Signature length mismatch");
        }
        Ok(CertificateVerify {
            algorithm,
            signature: data[4..].to_vec(),
        })
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend((self.algorithm as u16).to_be_bytes());
        out.extend((self.signature.len() as u16).to_be_bytes());
        out.extend(self.signature);
        out
    }
}
