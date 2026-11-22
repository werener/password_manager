use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::CryptoError;

#[derive(Debug, Clone, Copy)]
pub struct Argon2idParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_len: usize,
}

pub fn argon2id_derive<const N: usize>(
    secret: &[u8],
    salt: &[u8],
    params: Argon2idParams,
) -> Result<Zeroizing<[u8; N]>, CryptoError> {
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|_| CryptoError::InvalidInput("invalid argon2 params".into()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; N]);
    argon2
        .hash_password_into(secret, salt, &mut *out)
        .map_err(|_| CryptoError::Internal)?;
    Ok(out)
}

pub fn hkdf_sha256<const N: usize>(ikm: &[u8], info: &[u8]) -> Result<[u8; N], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; N];
    hk.expand(info, &mut out)
        .map_err(|_| CryptoError::Internal)?;
    Ok(out)
}
