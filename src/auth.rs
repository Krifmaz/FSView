//! argon2id password hashing (PHC strings) and random tokens.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use subtle::ConstantTimeEq;

/// RFC 9106 second recommended option with a 64 MiB memory cost.
pub const MEMORY_KIB: u32 = 64 * 1024;
pub const TIME: u32 = 3;
pub const THREADS: u32 = 2;
pub const KEY_LEN: usize = 32;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("system random source");
    b
}

fn derive(pw: &str, salt: &[u8], m: u32, t: u32, p: u32, len: usize) -> Result<Vec<u8>, String> {
    let params = Params::new(m, t, p, Some(len)).map_err(|e| e.to_string())?;
    let mut out = vec![0u8; len];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pw.as_bytes(), salt, &mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// PHC-format argon2id hash.
pub fn hash_password(pw: &str) -> Result<String, String> {
    hash_with(pw, MEMORY_KIB, TIME, THREADS)
}

pub(crate) fn hash_with(pw: &str, m: u32, t: u32, p: u32) -> Result<String, String> {
    let salt = random_bytes::<16>();
    let key = derive(pw, &salt, m, t, p, KEY_LEN)?;
    Ok(format!(
        "$argon2id$v=19$m={m},t={t},p={p}${}${}",
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(key)
    ))
}

/// Constant-time verification against a PHC argon2id hash.
pub fn verify_password(pw: &str, encoded: &str) -> Result<bool, String> {
    let parts: Vec<&str> = encoded.split('$').collect();
    if parts.len() != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
        return Err("invalid password hash".into());
    }
    let mut m = 0;
    let mut t = 0;
    let mut p = 0;
    for kv in parts[3].split(',') {
        let (k, v) = kv.split_once('=').ok_or("invalid password hash")?;
        let v: u32 = v.parse().map_err(|_| "invalid password hash")?;
        match k {
            "m" => m = v,
            "t" => t = v,
            "p" => p = v,
            _ => return Err("invalid password hash".into()),
        }
    }
    let salt = STANDARD_NO_PAD
        .decode(parts[4])
        .map_err(|_| "invalid password hash")?;
    let want = STANDARD_NO_PAD
        .decode(parts[5])
        .map_err(|_| "invalid password hash")?;
    if want.is_empty() {
        return Err("invalid password hash".into());
    }
    let got = derive(pw, &salt, m, t, p, want.len())?;
    Ok(got.ct_eq(&want).into())
}

/// Random password from an unambiguous alphabet.
pub fn generate_password(n: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut out = String::with_capacity(n);
    while out.len() < n {
        for b in random_bytes::<64>() {
            // Rejection sampling avoids modulo bias.
            let limit = 256 - (256 % ALPHABET.len());
            if (b as usize) < limit && out.len() < n {
                out.push(ALPHABET[b as usize % ALPHABET.len()] as char);
            }
        }
    }
    out
}

/// URL-safe token with 256 bits of entropy.
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verify() {
        let h = hash_with("correct horse", 1024, 1, 1).unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=1024,t=1,p=1$"), "{h}");
        assert!(verify_password("correct horse", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
        assert!(verify_password("x", "$2y$10$bcrypt").is_err());
        let p = generate_password(20);
        assert_eq!(p.len(), 20);
        assert_ne!(random_token(), random_token());
    }
}
