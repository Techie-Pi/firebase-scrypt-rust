//! Implementation of [Firebase Scrypt](https://github.com/firebase/scrypt) in pure Rust.
//!
//! If you are only using the [`verify_password`] function instead of the higher-level struct [`FirebaseScrypt`],
//! it's recommended to disable default features in your ``Cargo.toml``
//!
//! ```toml
//! [dependencies]
//! firebase-scrypt = { version = "0.1", default-features = false }
//! ```
//!
//! # Usage (with ``simple`` feature)
//! ```
//! use firebase_scrypt::FirebaseScrypt;
//!
//! const SALT_SEPARATOR: &str = "Bw==";
//! const SIGNER_KEY: &str = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
//! const ROUNDS: u32 = 8;
//! const MEM_COST: u32 = 14;
//!
//! let firebase_scrypt = FirebaseScrypt::new(SALT_SEPARATOR, SIGNER_KEY, ROUNDS, MEM_COST);
//!
//! let password = "user1password";
//! let salt = "42xEC+ixf3L2lw==";
//! let password_hash ="lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";
//!
//! assert!(firebase_scrypt.verify_password(password, salt, password_hash).unwrap())
//! ```

#![feature(int_log)]

use aes::{Aes256};
use aes::cipher::{KeyIvInit, StreamCipher};
use constant_time_eq::constant_time_eq;
use ctr::{Ctr128BE};
use scrypt::Params;
use crate::errors::{DerivedKeyError, EncryptError, VerifyPasswordError};

pub mod errors;
#[cfg(feature = "simple")]
mod simple;

#[cfg(feature = "simple")]
pub use simple::FirebaseScrypt;

const IV: [u8; 16] = *b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

fn generate_derived_key<'a>(
    password: &'a str,
    salt: &'a str,
    salt_separator: &'a str,
    rounds: u32,
    mem_cost: u32,
) -> Result<[u8; 64], DerivedKeyError> {
    let log2_n = 2_u32.pow(mem_cost).log(2);
    let p: u32 = 1;

    debug_assert!(log2_n < 64, "log2 of n must not be larger than 64");

    let mut salt = base64::decode(salt)?;
    salt.append(&mut base64::decode(salt_separator)?);
    let password = password.as_bytes();

    let params = Params::new(log2_n as u8, rounds, p)?;

    let mut result = [0u8; 64];
    scrypt::scrypt(
        password,
        salt.as_slice(),
        &params,
        &mut result
    )?;

    Ok(result)
}

fn encrypt(signer_key: &[u8], key: [u8; 32]) -> Result<Vec<u8>, EncryptError> {
    let mut cipher = Ctr128BE::<Aes256>::new(&key.into(), &IV.into());

    let mut buffer = vec![0u8; signer_key.len()];
    cipher
        .apply_keystream_b2b(signer_key, &mut buffer)?;

    Ok(buffer)
}

/// Verifies the password with a given known hash.
///
/// In case the salt separator, signer key, number of rounds and cost of memory don't change in
/// runtime, you may want to use the [`FirebaseScrypt`] struct to manage them.
///
/// # Example
/// ```
/// use firebase_scrypt::verify_password;
///
/// const SALT_SEPARATOR: &str = "Bw==";
/// const SIGNER_KEY: &str = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
/// const ROUNDS: u32 = 8;
/// const MEM_COST: u32 = 14;
///
/// let password = "user1password";
/// let salt = "42xEC+ixf3L2lw==";
/// let password_hash ="lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";
///
/// let is_valid = verify_password(
///     password,
///     password_hash,
///     salt,
///     SALT_SEPARATOR,
///     SIGNER_KEY,
///     ROUNDS,
///     MEM_COST,
/// ).unwrap();
///
/// assert!(is_valid)
/// ```
pub fn verify_password(
    password: &str,
    known_hash: &str,
    salt: &str,
    salt_separator: &str,
    signer_key: &str,
    rounds: u32,
    mem_cost: u32,
) -> Result<bool, VerifyPasswordError> {
    let derived_key = generate_derived_key(password, salt, salt_separator, rounds, mem_cost)?;
    let signer_key = base64::decode(signer_key)?;

    let result = encrypt(signer_key.as_slice(), derived_key[..32].try_into().unwrap())?;
    let password_hash = base64::decode(base64::encode(result))?;

    Ok(constant_time_eq(password_hash.as_slice(), base64::decode(known_hash)?.as_slice()))
}

#[cfg(test)]
mod tests {
    const SALT_SEPARATOR: &str = "Bw==";
    const SIGNER_KEY: &str = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
    const ROUNDS: u32 = 8;
    const MEM_COST: u32 = 14;

    const PASSWORD: &str = "user1password";
    const SALT: &str = "42xEC+ixf3L2lw==";
    const PASSWORD_HASH: &str ="lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

    use super::*;
    #[test]
    fn verify_password_works() {
        assert!(verify_password(
            PASSWORD,
            PASSWORD_HASH,
            SALT,
            SALT_SEPARATOR,
            SIGNER_KEY,
            ROUNDS,
            MEM_COST
        ).unwrap())
    }

    #[test]
    fn encrypt_works() {
        let param_1 = b"randomrandomrandomrandomrandomrandomrandom";
        let param_2 = b"12345678901234567890123456789012";

        assert_eq!(hex::encode(encrypt(param_1, *param_2).unwrap()), "09f509fa3d09cde568f80709416681e4ed5d9677ca8b4807a932869ba3fd057be3606c2940877850ed96");
    }

    #[test]
    fn generate_derived_key_works() {
        assert_eq!(hex::encode(generate_derived_key(PASSWORD, SALT, SALT_SEPARATOR, ROUNDS, MEM_COST).unwrap()), "e87fa22d9b4e3be6bbd41214f2f98f8c78b694bd17e12c2b73501054a2099ce11fe896483c68a443c6cf9ff8a8dfe1dfe2adaa4be6c8ca1b7686687a26f48831");
    }
}
