//! AES-256-CBC + URL-safe base64 (no pad) — same wire format as implants and `routes::check_in`.

use base64::{
    alphabet,
    engine::{self},
    Engine as _,
};
use openssl::symm::{Cipher, Crypter, Mode};

pub const CUSTOM_B64: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD);

/// Encrypt plaintext and return URL-safe base64 body for `POST /js`, `/index`, etc.
pub fn encrypt_aes_cbc_urlsafe_b64(aes_key: &[u8], plaintext: &[u8]) -> String {
    let cipher = Cipher::aes_256_cbc();
    let iv = vec![0u8; cipher.iv_len().expect("AES-CBC IV length")];
    let mut crypter =
        Crypter::new(cipher, Mode::Encrypt, aes_key, Some(&iv)).expect("Crypter::new encrypt");
    let mut encrypted = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = crypter
        .update(plaintext, &mut encrypted)
        .expect("encrypt update");
    count += crypter
        .finalize(&mut encrypted[count..])
        .expect("encrypt finalize");
    encrypted.truncate(count);
    CUSTOM_B64.encode(encrypted)
}

/// Decrypt a URL-safe base64 implant payload (mirrors server-side decrypt in `check_in`).
pub fn decrypt_aes_cbc_urlsafe_b64(aes_key: &[u8], b64_body: &str) -> Vec<u8> {
    let decoded = CUSTOM_B64
        .decode(b64_body.trim())
        .expect("base64 decode");
    let cipher = Cipher::aes_256_cbc();
    let iv = vec![0u8; cipher.iv_len().expect("AES-CBC IV length")];
    let mut crypter =
        Crypter::new(cipher, Mode::Decrypt, aes_key, Some(&iv)).expect("Crypter::new decrypt");
    let mut decrypted = vec![0u8; decoded.len() + cipher.block_size()];
    let mut count = crypter
        .update(&decoded, &mut decrypted)
        .expect("decrypt update");
    count += crypter
        .finalize(&mut decrypted[count..])
        .expect("decrypt finalize");
    decrypted.truncate(count);
    decrypted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_matches_server_iv_zero() {
        let key = [0xABu8; 32];
        let plain = br#"{"sleep":"2"}"#;
        let b64 = encrypt_aes_cbc_urlsafe_b64(&key, plain);
        let out = decrypt_aes_cbc_urlsafe_b64(&key, &b64);
        assert_eq!(out, plain);
    }
}
