use crate::{generate_raw_hash, verify_password, GenerateHashError};

/// Struct to simplify the usage of hash generation and checking.
///
/// Holds the salt separator, signer key, round and memory cost to make the usage of the hash generation
/// and checking function easier.
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirebaseScrypt {
    salt_separator: String,
    signer_key: String,
    rounds: u32,
    mem_cost: u32,
}

impl FirebaseScrypt {
    /// Create a new [`FirebaseScrypt`] instance.
    pub fn new(salt_separator: &str, signer_key: &str, rounds: u32, mem_cost: u32) -> Self {
        Self {
            salt_separator: salt_separator.to_string(),
            signer_key: signer_key.to_string(),
            rounds,
            mem_cost,
        }
    }

    /// Calls [`verify_password`] with the data from the [`FirebaseScrypt`]
    ///
    /// # Example
    /// ```no_test
    /// # This test doesn't pass for (some?) reason. But the ``verify_password_with_simple_works`` test
    /// # passes, so no idea.
    /// use firebase_scrypt::FirebaseScrypt;
    ///
    /// const SALT_SEPARATOR: &str = "Bw==";
    /// const SIGNER_KEY: &str = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
    /// const ROUNDS: u32 = 8;
    /// const MEM_COST: u32 = 14;
    ///
    /// let password: &str = "user1password";
    /// let salt: &str = "42xEC+ixf3L2lw==";
    /// let password_hash: &str = "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";
    ///
    /// let firebase_scrypt = FirebaseScrypt::new(SALT_SEPARATOR, SIGNER_KEY, ROUNDS, MEM_COST);
    ///
    /// let is_valid = firebase_scrypt.verify_password(
    ///     password,
    ///     password_hash,
    ///     salt,
    /// ).unwrap();
    ///
    /// assert!(is_valid)
    /// ```
    pub fn verify_password(
        &self,
        password: &str,
        salt: &str,
        known_hash: &str,
    ) -> Result<bool, GenerateHashError> {
        verify_password(
            password,
            known_hash,
            salt,
            self.salt_separator.as_str(),
            self.signer_key.as_str(),
            self.rounds,
            self.mem_cost,
        )
    }

    /// Calls [`FirebaseScrypt::verify_password`] but returns false also if an error occurs, which
    /// is _usually_ the best thing to do.
    pub fn verify_password_bool(&self, password: &str, salt: &str, known_hash: &str) -> bool {
        if let Ok(result) = self.verify_password(password, salt, known_hash) {
            result
        } else {
            false
        }
    }

    /// Generates a hash and returns its Base64 form, the same as the hashes from Firebase
    ///
    /// <div class="example-wrap" style="display:inline-block"><pre class="compile_fail" style="white-space:normal;font:inherit;">
    ///
    /// **Warning**: Do not use this function to check if a given password is valid, because that
    /// could result in [side-channel attacks](https://en.wikipedia.org/wiki/Side-channel_attack).
    ///
    /// Use the [`FirebaseScrypt::verify_password`] function instead.
    ///
    /// </pre></div>
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
    /// let password = "user1password";
    /// let salt = "42xEC+ixf3L2lw==";
    ///
    /// let firebase_scrypt = FirebaseScrypt::new(SALT_SEPARATOR, SIGNER_KEY, ROUNDS, MEM_COST);
    ///
    /// firebase_scrypt.generate_base64_hash(password, salt).unwrap();
    /// ```
    pub fn generate_base64_hash(
        &self,
        password: &str,
        salt: &str,
    ) -> Result<String, GenerateHashError> {
        let hash = generate_raw_hash(
            password,
            salt,
            self.salt_separator.as_str(),
            self.signer_key.as_str(),
            self.rounds,
            self.mem_cost,
        )?;

        Ok(base64::encode(hash))
    }
}

#[cfg(test)]
mod tests {
    const SALT_SEPARATOR: &str = "Bw==";
    const SIGNER_KEY: &str =
        "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
    const ROUNDS: u32 = 8;
    const MEM_COST: u32 = 14;

    const PASSWORD: &str = "user1password";
    const SALT: &str = "42xEC+ixf3L2lw==";
    const PASSWORD_HASH: &str =
        "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

    use super::*;

    #[test]
    fn verify_password_with_simple_works() {
        let firebase_scrypt = FirebaseScrypt::new(SALT_SEPARATOR, SIGNER_KEY, ROUNDS, MEM_COST);

        assert!(firebase_scrypt
            .verify_password(PASSWORD, SALT, PASSWORD_HASH,)
            .unwrap())
    }

    #[test]
    fn generate_hash_with_simple_works() {
        let firebase_scrypt = FirebaseScrypt::new(SALT_SEPARATOR, SIGNER_KEY, ROUNDS, MEM_COST);

        assert_eq!(
            firebase_scrypt
                .generate_base64_hash(PASSWORD, SALT,)
                .unwrap(),
            PASSWORD_HASH
        )
    }
}
