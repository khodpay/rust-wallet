//! 2-party key resharing (device-loss recovery) for secp256k1 / EVM.
//!
//! # What resharing does
//!
//! Resharing re-randomises the secret shares of both parties while keeping the
//! same joint public key (and therefore the same EVM wallet address).  After a
//! successful ceremony:
//!
//! * The device holds a **new** [`DeviceShare`] that, together with the
//!   server's updated cooperating share, can produce valid signatures.
//! * The **old** device share is cryptographically invalidated on the server
//!   side: the server discards its old share and replaces it with the new one,
//!   so any future signing attempt that presents the old device share will be
//!   rejected by the server.
//!
//! # Protocol
//!
//! Key refresh is performed using [`cggmp21::key_refresh`] (non-threshold
//! variant, 2-of-2).  Both parties supply their current [`cggmp21::KeyShare`]
//! and receive a fresh `KeyShare` whose `core.shared_public_key` is identical
//! to the pre-refresh value.
//!
//! The refresh protocol requires Paillier-modulus generation
//! ([`PregeneratedPrimes`]).  In tests this is generated with
//! `PregeneratedPrimes::generate`, which is slow (~seconds) but correct.
//! Production code would pre-generate the primes out-of-band and cache them.
//!
//! # Security
//!
//! * No complete private key is ever assembled on either party.
//! * All in-progress state lives only for the duration of `run_local`; when
//!   the function returns (or the `ReshareSession` is dropped), any
//!   intermediate secret material held by the `cggmp21` runtime is freed.
//! * Neither the old nor the new share is ever written to a log.

use crate::session::MpcSession;

// ─── Public result type ───────────────────────────────────────────────────────

/// The output of a completed resharing ceremony on the device side.
///
/// Returned by [`ReshareSession::run_local`].  Store
/// [`ReshareOutput::new_device_share`] in `SecureStorageService` under the key
/// `mpc_device_share_v1`, overwriting the previous entry.  The old share is
/// now useless — the server will reject any signing request that uses it.
pub struct ReshareOutput {
    /// The freshly-issued device-side key share.
    ///
    /// Store this in `SecureStorageService` under `mpc_device_share_v1`.
    /// **Never log or transmit this value.**
    pub new_device_share: crate::share::DeviceShare,
}

// Custom Debug that never leaks the share bytes.
impl std::fmt::Debug for ReshareOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReshareOutput")
            .field("new_device_share", &"[REDACTED]")
            .finish()
    }
}

// ─── ReshareSession ───────────────────────────────────────────────────────────

/// High-level 2-party resharing session for the device side.
///
/// Wraps an [`MpcSession`] for lifecycle management.  After construction the
/// session is in [`crate::SessionState::Pending`].
///
/// Call [`ReshareSession::run_local`] (in tests / bridge integration) to drive
/// the full ceremony in-process.  The production round-trip transport to the
/// KhodPay signer server is added in Task 06.
pub struct ReshareSession {
    inner: MpcSession,
}

impl ReshareSession {
    /// Creates a new `ReshareSession` in [`crate::SessionState::Pending`].
    ///
    /// A fresh UUID v4 session ID is generated automatically.
    pub fn new() -> Self {
        Self {
            inner: MpcSession::new(),
        }
    }

    /// Returns the session ID (UUID v4 string).
    pub fn session_id(&self) -> &str {
        self.inner.session_id()
    }

    /// Returns a reference to the underlying [`MpcSession`].
    pub fn session(&self) -> &MpcSession {
        &self.inner
    }

    /// Runs a full 2-of-2 key-refresh ceremony locally (both parties in-process).
    ///
    /// This method is intended for unit and integration tests in this crate and
    /// for the `crates/flutter_bridge` integration test (Task 06).  In production
    /// the Flutter UI is responsible for the round-trip transport.
    ///
    /// # Parameters
    ///
    /// * `key_shares` — a slice of exactly 2 complete [`cggmp21::KeyShare`]s
    ///   (device share at index 0, server share at index 1), as produced by
    ///   [`crate::signing::run_two_party_trusted_dealer`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::MpcError::ResharingFailed`] if the protocol fails or
    /// if the resulting share cannot be serialised.
    #[cfg(test)]
    pub(crate) fn run_local(
        &mut self,
        key_shares: &[cggmp21::KeyShare<cggmp21::supported_curves::Secp256k1>],
    ) -> crate::error::Result<ReshareOutput> {
        use crate::error::MpcError;
        use crate::share::DeviceShare;

        self.inner.advance_round(1)?;

        match run_two_party_key_refresh(key_shares) {
            Ok(refreshed_shares) => {
                // Party 0 is always the device share.
                let new_device_ks = &refreshed_shares[0];

                // Serialise the refreshed IncompleteKeyShare (core) so it can
                // be stored as a DeviceShare byte blob, mirroring the DKG path.
                let share_bytes =
                    serde_json::to_vec(&new_device_ks.core).map_err(|e| {
                        let err = MpcError::ResharingFailed {
                            reason: format!("failed to serialise refreshed device share: {e}"),
                        };
                        let _ = self.inner.fail(err.clone());
                        err
                    })?;

                let new_device_share = DeviceShare::from_bytes(&share_bytes).map_err(|e| {
                    let _ = self.inner.fail(e.clone());
                    e
                })?;

                self.inner.complete()?;

                Ok(ReshareOutput { new_device_share })
            }
            Err(e) => {
                let err = MpcError::ResharingFailed {
                    reason: format!("CGGMP21 key refresh failed: {e}"),
                };
                let _ = self.inner.fail(err.clone());
                Err(err)
            }
        }
    }
}

impl Default for ReshareSession {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReshareSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReshareSession")
            .field("session_id", &self.inner.session_id())
            .field("state", self.inner.state())
            .finish()
    }
}

// ─── Internal: two-party key-refresh simulation (test-only) ──────────────────

/// Runs a 2-of-2 CGGMP21 non-threshold key refresh using `round_based::sim`.
///
/// Both parties supply their current [`cggmp21::KeyShare`] and receive a fresh
/// one with the same joint public key.
///
/// Available in tests only — production transport is the Flutter bridge's job.
#[cfg(test)]
pub(crate) fn run_two_party_key_refresh(
    key_shares: &[cggmp21::KeyShare<cggmp21::supported_curves::Secp256k1>],
) -> std::result::Result<
    Vec<cggmp21::KeyShare<cggmp21::supported_curves::Secp256k1>>,
    cggmp21::KeyRefreshError,
> {
    use cggmp21::{
        key_refresh::PregeneratedPrimes, security_level::SecurityLevel128,
        supported_curves::Secp256k1, ExecutionId,
    };
    use rand::rngs::OsRng;
    use sha3::{Digest, Sha3_256};

    assert_eq!(key_shares.len(), 2, "need exactly 2 key shares for 2-of-2 refresh");

    // Derive a unique execution ID from the current shares' public key bytes
    // so each refresh ceremony has a distinct EID.
    let pk_bytes = {
        use cggmp21::generic_ec::coords::HasAffineXY;
        let pk = key_shares[0].core.shared_public_key;
        let coords = pk.coords().expect("shared_public_key is non-zero");
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(coords.x.as_be_bytes());
        raw[32..].copy_from_slice(coords.y.as_be_bytes());
        raw
    };
    let eid_bytes: [u8; 32] = Sha3_256::digest(pk_bytes).into();

    type Msg = cggmp21::key_refresh::msg::non_threshold::Msg<
        Secp256k1,
        sha2::Sha256,
        SecurityLevel128,
    >;

    // Pre-generate Paillier primes for each party.
    // This is slow in real usage; in tests it's acceptable.
    let primes_0: PregeneratedPrimes<SecurityLevel128> =
        PregeneratedPrimes::generate(&mut OsRng);
    let primes_1: PregeneratedPrimes<SecurityLevel128> =
        PregeneratedPrimes::generate(&mut OsRng);
    let primes = vec![primes_0, primes_1];

    let shares_clone = key_shares.to_vec();

    let results = round_based::sim::run::<Msg, _>(2, |i, party| {
        let share = shares_clone[usize::from(i)].clone();
        let p = primes[usize::from(i)].clone();
        let eid = ExecutionId::new(&eid_bytes);
        let mut rng = OsRng;
        async move {
            cggmp21::key_refresh(eid, &share, p)
                .start(&mut rng, party)
                .await
        }
    })
    .unwrap_or_else(|e| panic!("round_based sim infrastructure failed: {e}"));

    let mut outputs: Vec<_> = results.into_vec();
    assert_eq!(outputs.len(), 2);

    // Collect in order: party 0 (device) first, party 1 (server) second.
    let server = outputs.pop().unwrap()?;
    let device = outputs.pop().unwrap()?;

    Ok(vec![device, server])
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        signing::{run_two_party_signing, run_two_party_trusted_dealer, verify_signature_recovers_address, encode_signature_evm},
        MpcError, SessionState,
    };

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /// Known 32-byte hash used as a fixed test vector.
    const TEST_HASH: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];

    // ─── ReshareSession lifecycle ─────────────────────────────────────────────

    #[test]
    fn test_new_session_is_pending() {
        let session = ReshareSession::new();
        assert!(matches!(session.session().state(), SessionState::Pending));
    }

    #[test]
    fn test_session_id_is_uuid_v4() {
        let session = ReshareSession::new();
        assert_eq!(session.session_id().len(), 36);
    }

    #[test]
    fn test_after_reshare_session_is_complete() {
        let (shares, _) = run_two_party_trusted_dealer();
        let mut session = ReshareSession::new();
        session.run_local(&shares).expect("reshare must succeed");
        assert!(session.session().is_complete());
        assert!(matches!(session.session().state(), SessionState::Complete));
    }

    #[test]
    fn test_reshare_twice_returns_protocol_violation() {
        let (shares, _) = run_two_party_trusted_dealer();
        let mut session = ReshareSession::new();
        session.run_local(&shares).unwrap();
        let err = session
            .run_local(&shares)
            .expect_err("second reshare on complete session must fail");
        assert!(
            matches!(err, MpcError::ProtocolViolation { .. }),
            "expected ProtocolViolation, got: {:?}",
            err
        );
    }

    // ─── ReshareOutput: new share is non-empty ────────────────────────────────

    #[test]
    fn test_new_device_share_is_non_empty() {
        let (shares, _) = run_two_party_trusted_dealer();
        let mut session = ReshareSession::new();
        let output = session.run_local(&shares).unwrap();
        assert!(!output.new_device_share.is_empty());
    }

    #[test]
    fn test_new_device_share_round_trips_through_bytes() {
        let (shares, _) = run_two_party_trusted_dealer();
        let mut session = ReshareSession::new();
        let output = session.run_local(&shares).unwrap();
        let bytes = output.new_device_share.to_bytes().to_vec();
        let restored = crate::share::DeviceShare::from_bytes(&bytes)
            .expect("round-trip must succeed");
        assert_eq!(output.new_device_share, restored);
    }

    // ─── Acceptance criterion 1: new share produces valid signatures ──────────
    //
    // After resharing the refreshed KeyShares (device + server) must still be
    // able to produce a valid signature over the same wallet address.

    #[test]
    fn test_sign_with_new_share_verifies_against_same_address() {
        let (old_shares, wallet_address) = run_two_party_trusted_dealer();

        // Run resharing to get new KeyShares.
        let new_shares =
            run_two_party_key_refresh(&old_shares).expect("key refresh must succeed");

        // Sign with the new shares.
        let raw_sig =
            run_two_party_signing(&new_shares, TEST_HASH).expect("signing with new shares must succeed");
        let sig_bytes =
            encode_signature_evm(&raw_sig, &wallet_address, TEST_HASH)
                .expect("signature encoding must succeed");

        assert!(
            verify_signature_recovers_address(&sig_bytes, TEST_HASH, &wallet_address),
            "signature produced with new shares must recover to the original address"
        );
    }

    // ─── Acceptance criterion 2: wallet address is unchanged after resharing ──

    #[test]
    fn test_wallet_address_unchanged_after_reshare() {
        let (old_shares, wallet_address) = run_two_party_trusted_dealer();

        let new_shares =
            run_two_party_key_refresh(&old_shares).expect("key refresh must succeed");

        // Derive the address from the new device share's public key.
        let new_pk = new_shares[0].core.shared_public_key;
        let new_address = crate::address::evm_address_from_public_key(&new_pk)
            .expect("new public key must yield a valid address");

        assert_eq!(
            wallet_address, new_address,
            "wallet address must be unchanged after resharing"
        );
    }

    // ─── Acceptance criterion 2 (cont.): both parties agree on the public key ─

    #[test]
    fn test_both_parties_agree_on_public_key_after_reshare() {
        let (old_shares, _) = run_two_party_trusted_dealer();
        let new_shares =
            run_two_party_key_refresh(&old_shares).expect("key refresh must succeed");

        assert_eq!(
            new_shares[0].core.shared_public_key,
            new_shares[1].core.shared_public_key,
            "both parties must agree on the joint public key after resharing"
        );
    }

    // ─── Acceptance criterion 3: old share is unusable post-reshare ──────────
    //
    // Server-side invalidation is enforced on the server: after resharing the
    // server replaces its old share with the new one and refuses any signing
    // session that presents the old device share.
    //
    // We simulate this by mixing old-device-share with new-server-share and
    // verifying the resulting signature does NOT recover to the wallet address.

    #[test]
    fn test_old_share_cannot_sign_after_reshare() {
        let (old_shares, wallet_address) = run_two_party_trusted_dealer();
        let new_shares =
            run_two_party_key_refresh(&old_shares).expect("key refresh must succeed");

        // Mix: old device share (index 0) + new server share (index 1).
        // These are from different refresh epochs and must not produce a valid
        // signature verifiable against the wallet address.
        let mixed_shares = vec![old_shares[0].clone(), new_shares[1].clone()];

        // The CGGMP21 signing protocol may still complete (it doesn't know the
        // shares are mismatched), but the resulting signature will not recover
        // to the correct address.
        let result = run_two_party_signing(&mixed_shares, TEST_HASH);

        match result {
            Ok(raw_sig) => {
                // Protocol completed but signature must NOT verify.
                // encode_signature_evm itself will fail (can't find matching
                // recovery ID), or the signature will recover to a wrong address.
                let sig_result =
                    encode_signature_evm(&raw_sig, &wallet_address, TEST_HASH);
                match sig_result {
                    Ok(sig_bytes) => {
                        assert!(
                            !verify_signature_recovers_address(
                                &sig_bytes,
                                TEST_HASH,
                                &wallet_address
                            ),
                            "mixed old/new shares must NOT produce a valid signature for the wallet address"
                        );
                    }
                    Err(_) => {
                        // encode_signature_evm returning an error is the
                        // expected outcome — the stale share produced a
                        // signature that does not recover to the wallet address.
                    }
                }
            }
            Err(_) => {
                // Signing protocol failure is also acceptable — mismatched
                // shares may cause a ZK-proof verification error inside CGGMP21.
            }
        }
    }

    // ─── New share differs from old share ────────────────────────────────────

    #[test]
    fn test_new_device_share_bytes_differ_from_old() {
        let (old_shares, _) = run_two_party_trusted_dealer();

        let old_device_bytes =
            serde_json::to_vec(&old_shares[0].core).expect("serialisation must succeed");

        let new_shares =
            run_two_party_key_refresh(&old_shares).expect("key refresh must succeed");

        let new_device_bytes =
            serde_json::to_vec(&new_shares[0].core).expect("serialisation must succeed");

        assert_ne!(
            old_device_bytes, new_device_bytes,
            "refreshed device share bytes must differ from the original share bytes"
        );
    }

    // ─── Debug / Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_debug_contains_session_id() {
        let session = ReshareSession::new();
        let id = session.session_id().to_string();
        assert!(format!("{session:?}").contains(&id));
    }

    #[test]
    fn test_reshare_session_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ReshareSession>();
    }

    #[test]
    fn test_reshare_output_debug_is_redacted() {
        let (shares, _) = run_two_party_trusted_dealer();
        let mut session = ReshareSession::new();
        let output = session.run_local(&shares).unwrap();
        let debug = format!("{output:?}");
        assert!(debug.contains("REDACTED"), "ReshareOutput debug must be redacted");
    }
}
