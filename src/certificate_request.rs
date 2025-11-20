use crate::extension::Extension;

#[derive(Debug)]
pub struct CertificateRequest {
    pub certificate_request_context: Vec<u8>,
    pub extensions: Vec<Extension>,
}
