use crate::common::TlsProtocolVersion;
use num_enum::TryFromPrimitive;

#[derive(Debug, Clone, TryFromPrimitive, PartialEq)]
#[repr(u16)]
pub enum SignatureScheme {
    // ECDSA on P-256
    ecdsa_secp256r1_sha256 = 0x0403,

    // ECDSA on P-384
    ecdsa_secp384r1_sha384 = 0x0503,

    // TLS 1.3 RSA (Required for RSA certs)
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
}

#[derive(Debug, Clone, TryFromPrimitive, PartialEq)]
#[repr(u16)]
pub enum ExtensionType {
    server_name = 0,
    supported_groups = 10,
    application_layer_protocol_negotiation = 16,
    status_request = 5,
    signature_algorithms = 13,
    signed_certificate_timestamp = 18,
    key_share = 51,
    psk_key_exchange_modes = 45,
    supported_versions = 43,
}

#[derive(Debug)]
pub enum Extension {
    Signature(Vec<SignatureScheme>),
    SupportedVersionsClient(Vec<TlsProtocolVersion>),
    SupportedVersionsServer(TlsProtocolVersion),
    SupportedGroups(Vec<NamedGroup>),
    KeyShareClient(Vec<KeyShareEntry>),
    KeyShareServer(KeyShareEntry),
}

impl Extension {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        let ext_type = self.extension_type();
        out.extend((ext_type as u16).to_be_bytes());
        // subtract 2 byte for type and total_len, removed from individual size
        let total_len = self.len() - 2 - 2;
        out.extend((total_len as u16).to_be_bytes());
        match self {
            Extension::Signature(schemes) => {
                out.extend(((schemes.len() * 2) as u16).to_be_bytes());
                for scheme in schemes {
                    out.extend((scheme as u16).to_be_bytes());
                }
            }
            Extension::SupportedVersionsClient(versions) => {
                out.push(2 * versions.len() as u8);
                for version in versions {
                    out.extend((version as u16).to_be_bytes());
                }
            }
            Extension::SupportedGroups(groups) => {
                out.extend(((groups.len() * 2) as u16).to_be_bytes());
                for group in groups {
                    out.extend((group as u16).to_be_bytes());
                }
            }
            Extension::KeyShareClient(key_shares) => {
                assert!(!key_shares.is_empty());
                out.extend(((total_len - 2) as u16).to_be_bytes());
                for share in key_shares {
                    out.extend((share.group as u16).to_be_bytes());
                    out.extend((share.pub_key.len() as u16).to_be_bytes());
                    out.extend(share.pub_key);
                }
            }
            Extension::SupportedVersionsServer(version) => {
                out.extend((version as u16).to_be_bytes());
            }
            Extension::KeyShareServer(share) => {
                out.extend((share.group as u16).to_be_bytes());
                out.extend((share.pub_key.len() as u16).to_be_bytes());
                out.extend(share.pub_key);
            }
        }
        out
    }

    pub fn extension_type(&self) -> ExtensionType {
        match self {
            Extension::Signature(_) => ExtensionType::signature_algorithms,
            Extension::SupportedVersionsClient(_) | Extension::SupportedVersionsServer(_) => {
                ExtensionType::supported_versions
            }
            Extension::SupportedGroups(_) => ExtensionType::supported_groups,
            Extension::KeyShareClient(_) | Extension::KeyShareServer(_) => ExtensionType::key_share,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            // each scheme 2 byte + schemes len total byte 2 + particular extension total len 2 byte + 2 byte of type
            Extension::Signature(schemes) => schemes.len() * 2 + 2 + 2 + 2,
            // each version 2 byte + all versions len total byte 1 (max 254) + particular extension total len 2 byte + 2 byte of type
            Extension::SupportedVersionsClient(versions) => versions.len() * 2 + 2 + 1 + 2,
            // each groups 2 byte + groups len total byte 2 + particular extension total len 2 byte + 2 byte of type
            Extension::SupportedGroups(groups) => groups.len() * 2 + 2 + 2 + 2,
            Extension::KeyShareClient(key_shares) => {
                // 2 byte for type
                // 2 byte for total len
                // 2 byte for key share length
                // for each key 2 byte for type + 2byte for len and len of pub key
                assert!(!key_shares.is_empty());
                let mut len = 2 + 2 + 2;
                for share in key_shares {
                    len += share.pub_key.len() + 2 + 2;
                }
                len
            }
            Extension::SupportedVersionsServer(_) => {
                // 2 byte for type
                // 2 byte for total len
                // 2 byt for version
                2 + 2 + 2
            }
            Extension::KeyShareServer(key) => {
                // 2 byte for type
                // 2 byte for total len
                // 2 byte for type + 2byte for len and len of pub key
                2 + 2 + key.pub_key.len() + 2 + 2
            }
        }
    }
}

#[derive(Debug, Clone, TryFromPrimitive, PartialEq)]
#[repr(u16)]
pub enum NamedGroup {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    x25519 = 0x001d,
}

#[derive(Debug)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub pub_key: Vec<u8>,
}
