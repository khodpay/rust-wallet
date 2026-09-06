//! Error types for the `khodpay-mpc-tss` crate.
//!
//! All public operations in this crate return [`Result<T>`], which is an alias
//! for `std::result::Result<T, MpcError>`.
//!
//! # Error categories
//!
//! | Variant | When it arises |
//! |---|---|
//! | [`MpcError::DkgFailed`] | The distributed key-generation ceremony could not complete |
//! | [`MpcError::SigningFailed`] | The threshold signing round failed |
//! | [`MpcError::ResharingFailed`] | The device-share resharing ceremony failed |
//! | [`MpcError::InvalidShare`] | A `DeviceShare` byte blob failed to deserialise or is otherwise malformed |
//! | [`MpcError::ProtocolViolation`] | A protocol invariant was breached (e.g. unexpected message from the server) |
//! | [`MpcError::NetworkRoundFailed`] | A specific protocol round payload was malformed or the session ID was unknown |
//! | [`MpcError::ShareDeserializationError`] | Deserialising a share from raw bytes failed |

use thiserror::Error;

/// All errors that can be returned by `khodpay-mpc-tss` operations.
///
/// Implements [`std::error::Error`], [`std::fmt::Display`], [`Send`], and
/// [`Sync`] so it is safe to propagate across thread boundaries and wrap with
/// `anyhow` or similar.
#[derive(Debug, Error)]
pub enum MpcError {
    /// The distributed key-generation ceremony failed.
    ///
    /// # Example
    /// ```
    /// use khodpay_mpc_tss::MpcError;
    /// let e = MpcError::DkgFailed { reason: "round 1 timeout".into() };
    /// assert!(e.to_string().contains("DKG failed"));
    /// ```
    #[error("DKG failed: {reason}")]
    DkgFailed {
        /// Human-readable description of why the ceremony failed.
        reason: String,
    },

    /// The threshold signing round failed.
    #[error("signing failed: {reason}")]
    SigningFailed {
        /// Human-readable description of why signing failed.
        reason: String,
    },

    /// The device-share resharing ceremony failed.
    #[error("resharing failed: {reason}")]
    ResharingFailed {
        /// Human-readable description of why resharing failed.
        reason: String,
    },

    /// A `DeviceShare` byte blob is malformed or otherwise invalid.
    ///
    /// Callers can treat this as a permanent error — retrying with the same
    /// bytes will not succeed.
    #[error("invalid share: {reason}")]
    InvalidShare {
        /// Human-readable description of the validation failure.
        reason: String,
    },

    /// A protocol invariant was breached.
    ///
    /// This indicates a logic error (e.g. an out-of-order message from the
    /// server, a mismatched session ID, or an unexpected state transition).
    /// It is distinct from [`MpcError::NetworkRoundFailed`], which represents
    /// a recoverable transport-level failure.
    #[error("protocol violation: {reason}")]
    ProtocolViolation {
        /// Human-readable description of the violation.
        reason: String,
    },

    /// A specific protocol round payload was malformed or the session ID was
    /// unknown on the server side.
    ///
    /// Callers use this variant to distinguish a **retry-safe** protocol
    /// failure (e.g. a dropped packet) from a data-corruption problem
    /// ([`MpcError::InvalidShare`]) or a logic error
    /// ([`MpcError::ProtocolViolation`]).
    ///
    /// # Fields
    /// * `round` — the zero-indexed protocol round number where the failure
    ///   occurred.
    #[error("network round {round} failed: {reason}")]
    NetworkRoundFailed {
        /// Zero-indexed protocol round number where the failure occurred.
        round: u8,
        /// Human-readable description of the network/transport failure.
        reason: String,
    },

    /// Deserialising a raw byte slice into a share type failed.
    ///
    /// Returned by [`DeviceShare::from_bytes`](crate::DeviceShare::from_bytes)
    /// when the input is not valid serialised share data.
    #[error("share deserialisation error: {reason}")]
    ShareDeserializationError {
        /// Human-readable description of the deserialisation failure.
        reason: String,
    },
}

impl PartialEq for MpcError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MpcError::DkgFailed { reason: a }, MpcError::DkgFailed { reason: b }) => a == b,
            (MpcError::SigningFailed { reason: a }, MpcError::SigningFailed { reason: b }) => {
                a == b
            }
            (MpcError::ResharingFailed { reason: a }, MpcError::ResharingFailed { reason: b }) => {
                a == b
            }
            (MpcError::InvalidShare { reason: a }, MpcError::InvalidShare { reason: b }) => {
                a == b
            }
            (
                MpcError::ProtocolViolation { reason: a },
                MpcError::ProtocolViolation { reason: b },
            ) => a == b,
            (
                MpcError::NetworkRoundFailed {
                    round: ra,
                    reason: a,
                },
                MpcError::NetworkRoundFailed {
                    round: rb,
                    reason: b,
                },
            ) => ra == rb && a == b,
            (
                MpcError::ShareDeserializationError { reason: a },
                MpcError::ShareDeserializationError { reason: b },
            ) => a == b,
            _ => false,
        }
    }
}

impl Eq for MpcError {}

/// Convenience alias — all fallible operations in this crate return this type.
pub type Result<T> = std::result::Result<T, MpcError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ── Display / to_string ─────────────────────────────────────────────────

    #[test]
    fn test_dkg_failed_display() {
        let e = MpcError::DkgFailed {
            reason: "round 1 timeout".into(),
        };
        assert_eq!(e.to_string(), "DKG failed: round 1 timeout");
    }

    #[test]
    fn test_signing_failed_display() {
        let e = MpcError::SigningFailed {
            reason: "bad nonce".into(),
        };
        assert_eq!(e.to_string(), "signing failed: bad nonce");
    }

    #[test]
    fn test_resharing_failed_display() {
        let e = MpcError::ResharingFailed {
            reason: "server rejected".into(),
        };
        assert_eq!(e.to_string(), "resharing failed: server rejected");
    }

    #[test]
    fn test_invalid_share_display() {
        let e = MpcError::InvalidShare {
            reason: "empty bytes".into(),
        };
        assert_eq!(e.to_string(), "invalid share: empty bytes");
    }

    #[test]
    fn test_protocol_violation_display() {
        let e = MpcError::ProtocolViolation {
            reason: "unexpected round 3".into(),
        };
        assert_eq!(e.to_string(), "protocol violation: unexpected round 3");
    }

    #[test]
    fn test_network_round_failed_display() {
        let e = MpcError::NetworkRoundFailed {
            round: 2,
            reason: "connection reset".into(),
        };
        assert_eq!(e.to_string(), "network round 2 failed: connection reset");
    }

    #[test]
    fn test_share_deserialization_error_display() {
        let e = MpcError::ShareDeserializationError {
            reason: "invalid cbor".into(),
        };
        assert_eq!(
            e.to_string(),
            "share deserialisation error: invalid cbor"
        );
    }

    // ── PartialEq / Eq ──────────────────────────────────────────────────────

    #[test]
    fn test_eq_same_variant_same_data() {
        let a = MpcError::DkgFailed {
            reason: "x".into(),
        };
        let b = MpcError::DkgFailed {
            reason: "x".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_eq_same_variant_different_data() {
        let a = MpcError::DkgFailed {
            reason: "x".into(),
        };
        let b = MpcError::DkgFailed {
            reason: "y".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_eq_different_variants() {
        let a = MpcError::DkgFailed {
            reason: "x".into(),
        };
        let b = MpcError::SigningFailed {
            reason: "x".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_eq_network_round_failed_round_differs() {
        let a = MpcError::NetworkRoundFailed {
            round: 1,
            reason: "oops".into(),
        };
        let b = MpcError::NetworkRoundFailed {
            round: 2,
            reason: "oops".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_eq_network_round_failed_reason_differs() {
        let a = MpcError::NetworkRoundFailed {
            round: 1,
            reason: "oops".into(),
        };
        let b = MpcError::NetworkRoundFailed {
            round: 1,
            reason: "different".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_eq_network_round_failed_equal() {
        let a = MpcError::NetworkRoundFailed {
            round: 0,
            reason: "timeout".into(),
        };
        let b = MpcError::NetworkRoundFailed {
            round: 0,
            reason: "timeout".into(),
        };
        assert_eq!(a, b);
    }

    // ── Send + Sync ─────────────────────────────────────────────────────────

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MpcError>();
    }

    // ── All variants covered ─────────────────────────────────────────────────

    #[test]
    fn test_all_variants_eq_reflexive() {
        let variants: Vec<MpcError> = vec![
            MpcError::DkgFailed {
                reason: "r".into(),
            },
            MpcError::SigningFailed {
                reason: "r".into(),
            },
            MpcError::ResharingFailed {
                reason: "r".into(),
            },
            MpcError::InvalidShare {
                reason: "r".into(),
            },
            MpcError::ProtocolViolation {
                reason: "r".into(),
            },
            MpcError::NetworkRoundFailed {
                round: 0,
                reason: "r".into(),
            },
            MpcError::ShareDeserializationError {
                reason: "r".into(),
            },
        ];
        // Each variant equals a freshly constructed copy of itself
        for v in &variants {
            let clone = match v {
                MpcError::DkgFailed { reason } => MpcError::DkgFailed {
                    reason: reason.clone(),
                },
                MpcError::SigningFailed { reason } => MpcError::SigningFailed {
                    reason: reason.clone(),
                },
                MpcError::ResharingFailed { reason } => MpcError::ResharingFailed {
                    reason: reason.clone(),
                },
                MpcError::InvalidShare { reason } => MpcError::InvalidShare {
                    reason: reason.clone(),
                },
                MpcError::ProtocolViolation { reason } => MpcError::ProtocolViolation {
                    reason: reason.clone(),
                },
                MpcError::NetworkRoundFailed { round, reason } => MpcError::NetworkRoundFailed {
                    round: *round,
                    reason: reason.clone(),
                },
                MpcError::ShareDeserializationError { reason } => {
                    MpcError::ShareDeserializationError {
                        reason: reason.clone(),
                    }
                }
            };
            assert_eq!(v, &clone);
        }
    }
}
