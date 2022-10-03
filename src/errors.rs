use base64::DecodeError;
use ctr::cipher::StreamCipherError;
use scrypt::errors::{InvalidOutputLen, InvalidParams};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DerivedKeyError {
    Base64Decode(DecodeError),
    InvalidScryptParams(InvalidParams),
    InvalidOutputLen(InvalidOutputLen),
}

impl From<DecodeError> for DerivedKeyError {
    fn from(e: DecodeError) -> Self {
        Self::Base64Decode(e)
    }
}

impl From<InvalidParams> for DerivedKeyError {
    fn from(e: InvalidParams) -> Self {
        Self::InvalidScryptParams(e)
    }
}

impl From<InvalidOutputLen> for DerivedKeyError {
    fn from(e: InvalidOutputLen) -> Self {
        Self::InvalidOutputLen(e)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum EncryptError {
    StreamCipher(StreamCipherError)
}

impl From<StreamCipherError> for EncryptError {
    fn from(e: StreamCipherError) -> Self {
        Self::StreamCipher(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GenerateHashError {
    GenerateDerivedKeyFailed,
    DecodingFailed,
    EncryptionFailed,
}

impl From<DecodeError> for GenerateHashError {
    fn from(_: DecodeError) -> Self {
        Self::DecodingFailed
    }
}

impl From<EncryptError> for GenerateHashError {
    fn from(_: EncryptError) -> Self {
        Self::EncryptionFailed
    }
}

impl From<DerivedKeyError> for GenerateHashError {
    fn from(_: DerivedKeyError) -> Self {
        Self::GenerateDerivedKeyFailed
    }
}
