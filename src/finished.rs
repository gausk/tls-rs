use anyhow::{Result, bail};

#[derive(Debug)]
pub struct Finished {
    verify_data: Vec<u8>,
}

impl Finished {
    pub fn from_bytes(data: &[u8]) -> Result<Finished> {
        Ok(Self {
            verify_data: data.to_vec(),
        })
    }
}
