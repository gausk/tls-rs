use ring::digest::{Context, Digest, SHA384};

pub struct TranscriptHasher {
    context: Context,
}

impl TranscriptHasher {
    pub fn new() -> TranscriptHasher {
        TranscriptHasher {
            context: Context::new(&SHA384),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    pub fn finish(self) -> Digest {
        self.context.finish()
    }
}
