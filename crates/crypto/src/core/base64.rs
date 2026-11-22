use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

pub fn encode(value: &[u8]) -> String {
    BASE64.encode(value)
}

pub fn decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64.decode(value)
}
