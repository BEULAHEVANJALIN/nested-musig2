use thiserror::Error;

#[derive(Debug, Error)]
pub enum MusigError {
    #[error("invalid input")]
    InvalidInput,

    #[error("invalid pubkey encoding")]
    InvalidPubkey,

    #[error("invalid nonce (zero or point at infinity)")]
    InvalidNonce,

    #[error("signing failed")]
    SigningFailed,

    #[error("verification failed")]
    VerificationFailed,
}
