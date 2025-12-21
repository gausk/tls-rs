use anyhow::{Result, bail};
use ring::digest::SHA384;
use ring::hkdf::KeyType;
use ring::hmac;
use ring::hmac::HMAC_SHA384;

#[derive(Debug)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn from_bytes(data: &[u8]) -> Result<Finished> {
        if data.len() != HMAC_SHA384.len() {
            bail!("Wrong length for finished message");
        }
        Ok(Self {
            verify_data: data.to_vec(),
        })
    }

    /// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    ///
    /// Structure of this message:
    ///
    /// struct {
    ///     opaque verify_data[Hash.length];
    /// } Finished;
    ///
    /// The verify_data value is computed as follows:
    ///
    /// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
    pub fn derive(finished_key: Vec<u8>, hash: &[u8]) -> Result<Finished> {
        let key = hmac::Key::new(hmac::HMAC_SHA384, finished_key.as_slice());
        let tag = hmac::sign(&key, hash);
        Ok(Self {
            verify_data: tag.as_ref().to_vec(),
        })
    }
}
