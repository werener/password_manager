use crate::core;

pub fn normalize_email(email: &str) -> String {
    core::email::normalize(email)
}

pub fn encode_base64(value: &[u8]) -> String {
    core::base64::encode(value)
}

pub fn decode_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    core::base64::decode(value)
}
