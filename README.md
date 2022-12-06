# Firebase Scrypt (for Rust)

Pure Rust implementation of [Firebase's scrypt](https://github.com/firebase/scrypt) password hashing algorithm.

[![Crates.io](https://img.shields.io/crates/v/firebase-scrypt.svg)](https://crates.io/crates/firebase-scrypt)
[![Documentation](https://docs.rs/firebase-scrypt/badge.svg)](https://docs.rs/firebase-scrypt)

## Installation
Add this to your ``Cargo.toml``

```toml
[dependencies]
firebase-scrypt = "0.2"
```

## Usage
With the ``simple`` feature:
```rust
use firebase_scrypt::FirebaseScrypt;

const SALT_SEPARATOR: &str = "Bw==";
const SIGNER_KEY: &str = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
const ROUNDS: u32 = 8;
const MEM_COST: u32 = 14;

let firebase_scrypt = FirebaseScrypt::new(SALT_SEPARATOR, SIGNER_KEY, ROUNDS, MEM_COST);

let password = "user1password";
let salt = "42xEC+ixf3L2lw==";
let password_hash ="lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

assert!(firebase_scrypt.verify_password(password, salt, password_hash).unwrap())
```

Use the ``verify_password`` function without ``FirebaseScrypt``
```rust
use firebase_scrypt::verify_password;

const SALT_SEPARATOR: &str = "Bw==";
const SIGNER_KEY: &str = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
const ROUNDS: u32 = 8;
const MEM_COST: u32 = 14;

let password = "user1password";
let salt = "42xEC+ixf3L2lw==";
let password_hash ="lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

let is_valid = verify_password(
     password,
     password_hash,
     salt,
     SALT_SEPARATOR,
     SIGNER_KEY,
     ROUNDS,
     MEM_COST,
).unwrap();
```

## MSRV
The minimum supported Rust version is: ``1.59``
