use crate::common::TlsProtocolVersion;
use crate::crypto::TlsDataKeyInfo;
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
    /// When data is sent or received, the data get encrypted/decrypted.
    /// pub encrypted_record: Vec<u8>,
    pub encrypted_record: TLSInnerPlaintext,
}

/// struct {
///   opaque content[TLSPlaintext.length];
///   ContentType type;
///   uint8 zeros[length_of_padding];
/// } TLSInnerPlaintext;
#[derive(Debug)]
pub struct TLSInnerPlaintext {
    /// The TLSPlaintext.fragment value, containing the byte encoding of a handshake
    /// or an alert message, or the raw bytes of the application's data to send.
    /// content: Vec<u8>,
    content: TlsContent,
    /// The TLSPlaintext.type value containing the content type of the record.
    content_type: TlsContentType,
    /// An arbitrary-length run of zero-valued bytes may appear in the cleartext after the type field.
    /// This provides an opportunity for senders to pad any TLS record by a chosen amount as long as
    /// the total stays within record size limits.
    zeros: Vec<u8>,
}

impl TLSInnerPlaintext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            bail!("empty TLSInnerPlaintext");
        }

        // Find last non-zero byte (strip padding)
        let end = match bytes.iter().rposition(|&b| b != 0) {
            Some(i) => i + 1,
            None => bail!("TLSInnerPlaintext contains only padding"),
        };

        // Last non-zero byte is content type
        let content_type = TlsContentType::try_from_primitive(bytes[end - 1])?;

        // Everything before content_type is content
        let content_bytes = &bytes[..end - 1];
        let content = TlsContent::from_bytes(content_bytes, &content_type)?;
        let zeros = bytes[end..].to_vec();

        Ok(Self {
            content,
            content_type,
            zeros,
        })
    }
}

#[derive(Debug)]
enum TlsContent {
    Handshake(HandShake),
    ApplicationData(Vec<u8>),
    Alert(Vec<u8>),
    Invalid,
}

impl TlsContent {
    pub fn from_bytes(data: &[u8], content_type: &TlsContentType) -> Result<TlsContent> {
        match content_type {
            TlsContentType::handshake => Ok(Self::Handshake(HandShake::from_bytes(data)?)),
            TlsContentType::application_data => Ok(Self::ApplicationData(data.to_vec())),
            TlsContentType::alert => Ok(Self::Alert(data.to_vec())),
            TlsContentType::invalid => Ok(Self::Invalid),
        }
    }
}

impl TlsCipherText {
    pub fn from_bytes(bytes: &[u8], key_info: &mut TlsDataKeyInfo) -> Result<(Self, usize)> {
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
        let decrypted_bytes =
            key_info.decrypt(&bytes[offset..offset + length as usize], &bytes[..5])?;
        Ok((
            Self {
                content_type,
                legacy_record_version,
                length,
                encrypted_record: TLSInnerPlaintext::from_bytes(&decrypted_bytes)?,
            },
            offset + length as usize,
        ))
    }
}
