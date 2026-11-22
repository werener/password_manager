pub mod aead;
pub mod hash;
pub mod jwt;
pub mod kdf;

pub mod base64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    use crate::error::CryptoError;

    pub fn encode(value: &[u8]) -> String {
        BASE64.encode(value)
    }

    pub fn decode(value: &str) -> Result<Vec<u8>, CryptoError> {
        BASE64
            .decode(value)
            .map_err(|_| CryptoError::InvalidData("invalid base64".to_string()))
    }
}
pub mod rand {
    use rand::{RngCore, rngs::OsRng};

    pub fn bytes<const N: usize>() -> [u8; N] {
        let mut out = [0u8; N];
        OsRng.fill_bytes(&mut out);
        out
    }
}
