//! [`DeviceShare`] — the device-side key share produced by DKG.
//!
//! A `DeviceShare` is an opaque byte blob that the Flutter app stores in
//! `SecureStorageService` under the key `mpc_device_share_v1`. Its internal
//! encoding is deliberately hidden from callers; the only stable contract is
//! the `to_bytes` / `from_bytes` round-trip.
//!
//! # Security
//!
//! `DeviceShare` implements [`Zeroize`] and [`ZeroizeOnDrop`], so the secret
//! material is wiped from memory as soon as the value is dropped. The
//! `Debug` impl prints `DeviceShare([REDACTED])` — the actual bytes are
//! never logged.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{MpcError, Result};

/// The device-side key share produced by the 2-of-2 DKG ceremony.
///
/// This is an opaque, serialised representation of the secret material held
/// by the user's device. Together with the server's cooperating share it is
/// sufficient to produce a valid ECDSA signature; neither share alone is
/// sufficient.
///
/// Store the raw bytes (obtained via [`to_bytes`](DeviceShare::to_bytes))
/// in `SecureStorageService` under the key `mpc_device_share_v1`.
///
/// # Security
///
/// The bytes are zeroed on drop. Never log or transmit this value.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DeviceShare(Vec<u8>);

impl DeviceShare {
    /// Returns a reference to the raw bytes of the share.
    ///
    /// The returned slice is suitable for writing to secure storage. It must
    /// **never** be written to a log.
    ///
    /// # Example
    ///
    /// ```
    /// use khodpay_mpc_tss::DeviceShare;
    ///
    /// let share = DeviceShare::from_bytes(&[1u8, 2, 3]).unwrap();
    /// assert_eq!(share.to_bytes(), &[1u8, 2, 3]);
    /// ```
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Reconstructs a `DeviceShare` from a raw byte slice.
    ///
    /// This performs basic validity checks — empty slices are rejected.
    /// The bytes must have been produced by a prior call to
    /// [`to_bytes`](DeviceShare::to_bytes) (or equivalently, read from
    /// `SecureStorageService`).
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::ShareDeserializationError`] if the byte slice is
    /// empty or otherwise cannot be interpreted as a valid share.
    ///
    /// # Example
    ///
    /// ```
    /// use khodpay_mpc_tss::{DeviceShare, MpcError};
    ///
    /// // Empty bytes are rejected.
    /// let err = DeviceShare::from_bytes(&[]).unwrap_err();
    /// assert!(matches!(err, MpcError::ShareDeserializationError { .. }));
    ///
    /// // Non-empty bytes round-trip successfully.
    /// let original = &[0xde, 0xad, 0xbe, 0xef];
    /// let share = DeviceShare::from_bytes(original).unwrap();
    /// assert_eq!(share.to_bytes(), original);
    /// ```
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.is_empty() {
            return Err(MpcError::ShareDeserializationError {
                reason: "share bytes must not be empty".into(),
            });
        }
        Ok(Self(b.to_vec()))
    }

    /// Returns the length of the share in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the share contains no bytes.
    ///
    /// In practice this should never be `true` for a valid share — it would
    /// have been rejected by [`from_bytes`](DeviceShare::from_bytes).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Prints `DeviceShare([REDACTED])` — the actual bytes are never exposed via
/// `Debug` to prevent accidental logging of secret material.
impl std::fmt::Debug for DeviceShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DeviceShare").field(&"[REDACTED]").finish()
    }
}

/// Two `DeviceShare` values are equal if and only if their underlying bytes
/// are identical.
impl PartialEq for DeviceShare {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for DeviceShare {}

#[cfg(test)]
mod tests {
    use super::*;

    // ── from_bytes / to_bytes round-trip ────────────────────────────────────

    #[test]
    fn test_round_trip_non_empty_bytes() {
        let raw = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02];
        let share = DeviceShare::from_bytes(&raw).expect("should succeed for non-empty bytes");
        assert_eq!(share.to_bytes(), raw.as_slice());
    }

    #[test]
    fn test_single_byte_round_trip() {
        let share = DeviceShare::from_bytes(&[0xff]).expect("single byte should succeed");
        assert_eq!(share.to_bytes(), &[0xff]);
    }

    #[test]
    fn test_from_bytes_empty_returns_error() {
        let err = DeviceShare::from_bytes(&[]).expect_err("empty bytes should fail");
        assert!(
            matches!(err, MpcError::ShareDeserializationError { ref reason } if !reason.is_empty())
        );
    }

    #[test]
    fn test_from_bytes_empty_error_message() {
        let err = DeviceShare::from_bytes(&[]).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "error message should mention 'empty', got: {}",
            err
        );
    }

    // ── len / is_empty ──────────────────────────────────────────────────────

    #[test]
    fn test_len_reflects_byte_count() {
        let data = vec![1u8, 2, 3, 4, 5];
        let share = DeviceShare::from_bytes(&data).unwrap();
        assert_eq!(share.len(), 5);
    }

    #[test]
    fn test_is_empty_false_for_valid_share() {
        let share = DeviceShare::from_bytes(&[42]).unwrap();
        assert!(!share.is_empty());
    }

    // ── Debug ───────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_redacted() {
        let share = DeviceShare::from_bytes(&[0x01, 0x02, 0x03]).unwrap();
        let debug_str = format!("{:?}", share);
        assert!(
            debug_str.contains("REDACTED"),
            "Debug output must be redacted, got: {}",
            debug_str
        );
        assert!(
            !debug_str.contains("1") && !debug_str.contains("2") && !debug_str.contains("3"),
            "Debug output must not leak byte values, got: {}",
            debug_str
        );
    }

    // ── PartialEq / Eq ──────────────────────────────────────────────────────

    #[test]
    fn test_eq_same_bytes() {
        let a = DeviceShare::from_bytes(&[1, 2, 3]).unwrap();
        let b = DeviceShare::from_bytes(&[1, 2, 3]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_eq_different_bytes() {
        let a = DeviceShare::from_bytes(&[1, 2, 3]).unwrap();
        let b = DeviceShare::from_bytes(&[1, 2, 4]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_eq_different_lengths() {
        let a = DeviceShare::from_bytes(&[1, 2, 3]).unwrap();
        let b = DeviceShare::from_bytes(&[1, 2]).unwrap();
        assert_ne!(a, b);
    }

    // ── Clone ───────────────────────────────────────────────────────────────

    #[test]
    fn test_clone_produces_equal_share() {
        let original = DeviceShare::from_bytes(&[0xAA, 0xBB, 0xCC]).unwrap();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_clone_is_independent() {
        // Modifying the original's internal data via a round-trip does not
        // affect the clone (the underlying Vec is heap-allocated).
        let original = DeviceShare::from_bytes(&[0x01]).unwrap();
        let cloned = original.clone();
        // original is dropped here; clone must still be intact
        drop(original);
        assert_eq!(cloned.to_bytes(), &[0x01]);
    }

    // ── Serde round-trip ────────────────────────────────────────────────────

    #[test]
    fn test_serde_json_round_trip() {
        let share = DeviceShare::from_bytes(&[10, 20, 30, 40]).unwrap();
        let json = serde_json::to_string(&share).expect("serialisation must not fail");
        let restored: DeviceShare =
            serde_json::from_str(&json).expect("deserialisation must not fail");
        assert_eq!(share, restored);
    }

    #[test]
    fn test_serde_json_large_payload() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let share = DeviceShare::from_bytes(&data).unwrap();
        let json = serde_json::to_string(&share).unwrap();
        let restored: DeviceShare = serde_json::from_str(&json).unwrap();
        assert_eq!(share, restored);
    }

    // ── Zeroize / ZeroizeOnDrop (smoke test) ────────────────────────────────

    #[test]
    fn test_zeroize_clears_bytes() {
        use zeroize::Zeroize;
        let mut share = DeviceShare::from_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        share.zeroize();
        // After zeroize(), the internal bytes should all be zero.
        assert!(
            share.0.iter().all(|&b| b == 0),
            "zeroize() must clear all bytes to zero"
        );
    }

    // ── Send + Sync ─────────────────────────────────────────────────────────

    #[test]
    fn test_device_share_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DeviceShare>();
    }
}
