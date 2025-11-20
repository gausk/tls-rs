use crate::common::TlsProtocolVersion;
use crate::record::TlsContentType;
use anyhow::Result;
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
    encrypted_record: Vec<u8>,
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

// AEAD algorithms take as input a single key, a nonce, a plaintext, and
// "additional data" to be included in the authentication check, as
// described in Section 2.1 of [RFC5116].  The key is either the
// client_write_key or the server_write_key, the nonce is derived from
// the sequence number and the client_write_iv or server_write_iv (see
// Section 5.3), and the additional data input is the record header.
// I.e.,
// additional_data = TLSCiphertext.opaque_type ||
// TLSCiphertext.legacy_record_version || TLSCiphertext.length
// AEADEncrypted = AEAD-Encrypt(write_key, nonce, additional_data, plaintext)

/// Based on pvt key from client and public key for server or vice-versa
pub fn calculate_handshake_traffic_secret(
    pvt_key: &EphemeralSecret,
    pub_key: &[u8],
) -> Result<SharedSecret> {
    let pub_key = PublicKey::from_sec1_bytes(pub_key)?;
    Ok(pvt_key.diffie_hellman(&pub_key))
}
