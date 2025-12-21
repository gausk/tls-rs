use crate::extension::Extension;
use anyhow::{Result, bail};
use num_enum::TryFromPrimitive;

#[derive(Debug)]
pub struct CertificateRequest {
    pub certificate_request_context: Vec<u8>,
    pub extensions: Vec<Extension>,
}

/// enum {
///     X509(0),
///     RawPublicKey(2),
///     (255)
/// } CertificateType;
#[derive(Debug, TryFromPrimitive, PartialEq)]
#[repr(u8)]
pub enum CertificateType {
    X509 = 0,
    RawPublicKey = 2,
}

#[derive(Debug)]
pub enum CertificateTypeData {
    X509(Vec<u8>),
    RawPublicKey(Vec<u8>),
}
/// struct {
///     select (certificate_type) {
///     case RawPublicKey:
///     /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
///     opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
///
///     case X509:
///     opaque cert_data<1..2^24-1>;
///     };
///     Extension extensions<0..2^16-1>;
/// } CertificateEntry;
#[derive(Debug)]
pub struct CertificateEntry {
    cert_data: CertificateTypeData,
    /// A set of extension values for the CertificateEntry. Valid extensions
    /// for server certificates at present include the OCSP Status
    /// extension [RFC6066] and the SignedCertificateTimestamp extension
    /// [RFC6962]; future extensions may be defined for this message as
    /// well.
    extensions: Vec<Extension>,
}

impl CertificateEntry {
    pub fn list_from_bytes(
        bytes: &[u8],
        cert_type: CertificateType,
    ) -> Result<Vec<CertificateEntry>> {
        let mut entries: Vec<CertificateEntry> = Vec::new();
        let total_len = bytes.len();
        let mut offset = 0;
        while offset < total_len {
            if bytes.len() < offset + 3 {
                bail!("certificate_list too short");
            }
            let cert_len =
                u32::from_be_bytes([0, bytes[offset], bytes[offset + 1], bytes[offset + 2]])
                    as usize;
            offset += 3;
            if offset + cert_len > total_len {
                bail!("certificate_list too short to read cert_data");
            }
            let cert_data = match cert_type {
                CertificateType::X509 => {
                    CertificateTypeData::X509(bytes[offset..offset + cert_len].to_vec())
                }
                CertificateType::RawPublicKey => {
                    CertificateTypeData::RawPublicKey(bytes[offset..offset + cert_len].to_vec())
                }
            };
            offset += cert_len;
            let (extensions, ext_len) = Extension::list_from_bytes(&bytes[offset..], false)?;
            offset += ext_len;
            entries.push({
                CertificateEntry {
                    cert_data,
                    extensions: vec![],
                }
            })
        }
        Ok(entries)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        let data = match self.cert_data {
            CertificateTypeData::X509(data) => data,
            CertificateTypeData::RawPublicKey(data) => data,
        };
        let len = (data.len() as u32).to_be_bytes();
        assert!(len[0] == 0);
        out.extend([len[1], len[2], len[3]]);
        out.extend(data);
        assert!(self.extensions.len() == 0);
        out.extend(0u16.to_be_bytes());
        out
    }
}

/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
#[derive(Debug)]
pub struct Certificate {
    /// certificate_request_context:  If this message is in response to a
    /// CertificateRequest, the value of certificate_request_context in
    /// that message.  Otherwise (in the case of server authentication),
    /// this field SHALL be zero length
    certificate_request_context: Vec<u8>,
    ///  A sequence (chain) of CertificateEntry structures, each
    /// containing a single certificate and set of extensions.
    certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    pub fn from_bytes(data: &[u8], cert_type: CertificateType) -> Result<Certificate> {
        if data.is_empty() {
            bail!("Empty certificate");
        }
        let mut offset = 0;
        let crc_len = data[0] as usize;
        offset += 1;
        if data.len() < crc_len + offset + 3 {
            bail!("Certificate data too short for CRC");
        }
        let certificate_request_context = data[offset..offset + crc_len].to_vec();
        offset += crc_len;
        if offset + 3 > data.len() {
            bail!("Certificate data too short for cert");
        }
        // 3 bytes cert_list bytes len
        let certs_len = u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]);
        offset += 3;
        let certificate_list = CertificateEntry::list_from_bytes(
            &data[offset..offset + certs_len as usize],
            cert_type,
        )?;

        Ok(Certificate {
            certificate_request_context,
            certificate_list,
        })
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.certificate_request_context.len() as u8);
        out.extend(self.certificate_request_context);
        let mut data = Vec::new();
        for certificate in self.certificate_list {
            data.extend(certificate.into_bytes());
        }
        let data_len = (data.len() as u32).to_be_bytes();
        assert!(data_len[0] == 0);
        out.extend([data_len[1], data_len[2], data_len[3]]);
        out.extend(data);
        out
    }
}
