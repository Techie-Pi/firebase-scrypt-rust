use crate::{verify_password, VerifyPasswordError};

/// Struct to simplify the usage of the [`verify_password`] function.
///
/// Holds the salt separator, signer key, round and memory cost to make the usage of the [`verify_password`]
/// function easier.
///
/// # Example
/// ```
/// use firebase_scrypt::FirebaseScrypt;
///
/// const SALT_SEPARATOR: &str = "Bw==";
/// const SIGNER_KEY: &str = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
/// const ROUNDS: u32 = 8;
/// const MEM_COST: u32 = 14;
///
/// let firebase_scrypt = FirebaseScrypt::new(SALT_SEPARATOR, SIGNER_KEY, ROUNDS, MEM_COST);
///
/// let password = "user1password";
/// let salt = "42xEC+ixf3L2lw==";
/// let password_hash ="lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";
///
/// assert!(firebase_scrypt.verify_password(password, salt, password_hash).unwrap())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirebaseScrypt {
    salt_separator: String,
    signer_key: String,
    rounds: u32,
    mem_cost: u32,
}

impl FirebaseScrypt {
    pub fn new(salt_separator: &str, signer_key: &str, rounds: u32, mem_cost: u32) -> Self {
        Self {
            salt_separator: salt_separator.to_string(),
            signer_key: signer_key.to_string(),
            rounds,
            mem_cost,
        }
    }

    /// Calls [`verify_password`] with the data from the [`FirebaseScrypt`]
    pub fn verify_password(&self, password: &str, salt: &str, known_hash: &str) -> Result<bool, VerifyPasswordError> {
        Ok(verify_password(
            password,
            known_hash,
            salt,
            self.salt_separator.as_str(),
            self.signer_key.as_str(),
            self.rounds,
            self.mem_cost,
        )?)
    }
}
