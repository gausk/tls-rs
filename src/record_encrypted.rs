use crate::common::TlsProtocolVersion;
use crate::handshake::HandShake;
use crate::record::TlsContentType;
use anyhow::{Result, bail};
use num_enum::TryFromPrimitive;
use p256::PublicKey;
use p256::ecdh::{EphemeralSecret, SharedSecret};

/// struct {
///    ContentType opaque_type = application_data; /* 23 */
///    ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
///    uint16 length;
///    opaque encrypted_record[TLSCiphertext.length];
/// } TLSCiphertext;

#[derive(Debug)]
pub struct TlsCipherText {
    /// The outer opaque_type field of a TLSCiphertext record
    /// is always set to the value 23 (application_data) for outward
    /// compatibility with middleboxes accustomed to parsing previous
    /// versions of TLS.  The actual content type of the record is found
    /// in TLSInnerPlaintext.type after decryption
    content_type: TlsContentType,
    /// The legacy_record_version field is always 0x0303. TLS 1.3 TLSCiphertexts
    /// are not generated until after TLS 1.3 has been negotiated, so there are no
    /// historical compatibility concerns where other values might be received.
    legacy_record_version: TlsProtocolVersion,
    /// The length (in bytes) of the following TLSCiphertext.encrypted_record,
    /// which is the sum of the lengths of the content and the padding, plus one
    /// for the inner content type, plus any expansion added by the AEAD algorithm.
    length: u16,
    /// The AEAD-encrypted form of the serialized TLSInnerPlaintext structure.
    pub encrypted_record: Vec<u8>,
}

/// struct {
///   opaque content[TLSPlaintext.length];
///   ContentType type;
///   uint8 zeros[length_of_padding];
/// } TLSInnerPlaintext;
#[derive(Debug)]
struct TLSInnerPlaintext {
    /// The TLSPlaintext.fragment value, containing the byte encoding of a handshake
    /// or an alert message, or the raw bytes of the application's data to send.
    content: Vec<u8>,
    /// The TLSPlaintext.type value containing the content type of the record.
    content_type: TlsContentType,
    /// An arbitrary-length run of zero-valued bytes may appear in the cleartext after the type field.
    /// This provides an opportunity for senders to pad any TLS record by a chosen amount as long as
    /// the total stays within record size limits.
    zeros: Vec<u8>,
}

impl TlsCipherText {
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        let mut offset = 0;
        let len = bytes.len();
        if offset + 1 >= len {
            bail!("unexpected data length, not able to read content type");
        }
        let content_type = TlsContentType::try_from(bytes[offset])?;
        offset += 1;
        if offset + 2 >= len {
            bail!("unexpected data length, not able to read legacy record version");
        }
        let record_version = u16::from_be_bytes(bytes[offset..(offset + 2)].try_into()?);
        let legacy_record_version = TlsProtocolVersion::try_from_primitive(record_version)?;
        offset += 2;
        if offset + 2 >= len {
            bail!("unexpected data length, not able to read legacy record version");
        }
        let length = u16::from_be_bytes(bytes[offset..(offset + 2)].try_into()?);
        offset += 2;
        if offset + length as usize > len {
            bail!("unexpected data length, not able to read fragment");
        }

        Ok((
            Self {
                content_type,
                legacy_record_version,
                length,
                encrypted_record: (bytes[offset..offset + length as usize]).to_vec(),
            },
            offset + length as usize,
        ))
    }
}
