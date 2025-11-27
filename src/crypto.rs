use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::ecdh::SharedSecret;
use ring::digest::SHA384;
use ring::hkdf::{HKDF_SHA384, Prk, Salt};

const PREFIX_LABEL: &[u8] = b"tls13 ";

/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
struct HkdfLabel<'a> {
    length: u16,
    label: &'a str,
    context: &'a [u8],
}

impl<'a> HkdfLabel<'a> {
    fn new(length: u16, label: &'a str, context: &'a [u8]) -> Self {
        Self {
            length,
            label,
            context,
        }
    }

    fn expand(&self, prk: &Prk, output: &mut [u8]) {
        let mut info = Vec::new();
        info.extend(self.length.to_be_bytes());
        let full_label = [PREFIX_LABEL, self.label.as_bytes()].concat();
        info.push(full_label.len() as u8);
        assert!(full_label.len() < 256);
        info.extend(full_label);
        info.push(self.context.len() as u8);
        info.extend_from_slice(self.context);

        prk.expand(&[info.as_slice()], HKDF_SHA384)
            .expect("expand")
            .fill(output)
            .expect("fill");
    }
}

pub fn derive_handshake_secret(shared_secret: &[u8], transcript_hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // early_secret = HKDF-Extract(0, 0)
    let zero_salt = Salt::new(HKDF_SHA384, &[0u8; 48]);
    let early_secret = zero_salt.extract(&[]);

    // derived_secret = HKDF-Expand-Label(early_secret, "derived", "")
    // Derive-Secret(., "derived", "")
    let mut derived = vec![0u8; 48];
    HkdfLabel::new(48, "derived", &[]).expand(&early_secret, derived.as_mut_slice());

    // handshake_secret = HKDF-Extract(derived_secret, shared_secret)
    let derived_salt = Salt::new(HKDF_SHA384, derived.as_slice());
    let handshake_secret = derived_salt.extract(shared_secret);

    // client_handshake_traffic_secret = Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
    let mut client_hs = vec![0u8; 48];
    HkdfLabel::new(48, "c hs traffic", transcript_hash)
        .expand(&handshake_secret, client_hs.as_mut_slice());

    // server_handshake_traffic_secret = Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
    let mut server_hs = vec![0u8; 48];
    HkdfLabel::new(48, "s hs traffic", transcript_hash)
        .expand(&handshake_secret, server_hs.as_mut_slice());

    (client_hs, server_hs)
}

pub fn derive_key_and_iv(traffic_secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let prk = Prk::new_less_safe(HKDF_SHA384, traffic_secret);

    // AES-256-GCM key length 32
    let mut key = vec![0u8; 48];
    HkdfLabel::new(32, "key", &[]).expand(&prk, key.as_mut_slice());

    // IV length always 12 in TLS 1.3
    let mut iv = vec![0u8; 48];
    HkdfLabel::new(12, "iv", &[]).expand(&prk, iv.as_mut_slice());

    (key[..32].to_vec(), iv[0..12].to_vec())
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

/// Based on pvt key from client and public key for server or vice versa
pub fn calculate_shared_secret(
    pvt_key: &EphemeralSecret,
    pub_key: &[u8],
) -> anyhow::Result<p256::ecdh::SharedSecret> {
    let pub_key = PublicKey::from_sec1_bytes(pub_key)?;
    Ok(pvt_key.diffie_hellman(&pub_key))
}
