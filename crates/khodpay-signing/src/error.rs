//! Error types for the signing crate.

use thiserror::Error;

/// Errors that can occur during transaction signing operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid chain ID provided.
    #[error("Invalid chain ID: {0}")]
    InvalidChainId(u64),

    /// Invalid EVM address.
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid gas parameters.
    #[error("Invalid gas: {0}")]
    InvalidGas(String),

    /// Invalid transaction value.
    #[error("Invalid value: {0}")]
    InvalidValue(String),

    /// Invalid nonce.
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Transaction validation failed.
    #[error("Transaction validation failed: {0}")]
    ValidationError(String),

    /// ECDSA signing error.
    #[error("Signing error: {0}")]
    SigningError(String),

    /// RLP encoding error.
    #[error("RLP encoding error: {0}")]
    RlpEncodingError(String),

    /// Error from BIP-32 operations.
    #[error("BIP-32 error: {0}")]
    Bip32Error(#[from] khodpay_bip32::Error),

    /// Error from BIP-44 operations.
    #[error("BIP-44 error: {0}")]
    Bip44Error(#[from] khodpay_bip44::Error),

    /// Hex decoding error.
    #[error("Hex decode error: {0}")]
    HexError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_chain_id_error() {
        let error = Error::InvalidChainId(999);
        assert_eq!(error.to_string(), "Invalid chain ID: 999");
    }

    #[test]
    fn test_invalid_address_error() {
        let error = Error::InvalidAddress("0xinvalid".to_string());
        assert_eq!(error.to_string(), "Invalid address: 0xinvalid");
    }

    #[test]
    fn test_invalid_gas_error() {
        let error = Error::InvalidGas("gas limit too low".to_string());
        assert_eq!(error.to_string(), "Invalid gas: gas limit too low");
    }

    #[test]
    fn test_invalid_value_error() {
        let error = Error::InvalidValue("negative value".to_string());
        assert_eq!(error.to_string(), "Invalid value: negative value");
    }

    #[test]
    fn test_invalid_nonce_error() {
        let error = Error::InvalidNonce("nonce overflow".to_string());
        assert_eq!(error.to_string(), "Invalid nonce: nonce overflow");
    }

    #[test]
    fn test_validation_error() {
        let error = Error::ValidationError("max_fee < max_priority_fee".to_string());
        assert_eq!(
            error.to_string(),
            "Transaction validation failed: max_fee < max_priority_fee"
        );
    }

    #[test]
    fn test_signing_error() {
        let error = Error::SigningError("invalid private key".to_string());
        assert_eq!(error.to_string(), "Signing error: invalid private key");
    }

    #[test]
    fn test_rlp_encoding_error() {
        let error = Error::RlpEncodingError("encoding failed".to_string());
        assert_eq!(error.to_string(), "RLP encoding error: encoding failed");
    }

    #[test]
    fn test_hex_error() {
        let error = Error::HexError("invalid hex character".to_string());
        assert_eq!(error.to_string(), "Hex decode error: invalid hex character");
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }
}
