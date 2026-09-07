//! 2-party distributed key generation (DKG) for secp256k1 / EVM.
//!
//! # Architecture
//!
//! [`DkgSession`] is the high-level type consumed by the Flutter bridge (Task 06).
//! It stores the completed device-side key share ([`DeviceShare`]) and the joint
//! EVM wallet address that were produced after a successful DKG ceremony.
//!
//! The cryptographic heavy lifting is done by the `cggmp21` library via
//! `round_based` networking.  During tests, the two-party ceremony is driven
//! entirely in-process using `round_based::sim`.  In production the Flutter
//! bridge is responsible for the gRPC transport.
//!
//! # Security
//!
//! * The device's secret share (`x_i` in CGGMP21 notation) is serialised into
//!   `DeviceShare`, which implements [`zeroize::ZeroizeOnDrop`] — it is wiped
//!   from heap memory as soon as the value is dropped.
//! * The joint public key (and therefore the wallet address) is derived from
//!   the *combined* key material of both parties.  Neither party's share alone
//!   is sufficient to reconstruct the private key.
//! * No mnemonic, BIP39 seed, or BIP32 derivation path is involved.

use crate::{session::MpcSession, share::DeviceShare};

#[cfg(any(test, feature = "test-utils"))]
use crate::{
    address::evm_address_from_public_key,
    error::{MpcError, Result},
};
#[cfg(any(test, feature = "test-utils"))]
use cggmp21::{supported_curves::Secp256k1, ExecutionId, IncompleteKeyShare};
#[cfg(any(test, feature = "test-utils"))]
use rand::rngs::OsRng;

// ─── Result types ────────────────────────────────────────────────────────────

/// The result of a completed DKG ceremony on the device side.
///
/// Returned by [`DkgSession::run_local`] (used in tests and the bridge
/// integration test).  Production code serialises [`DkgOutput::device_share`]
/// to secure storage and surfaces [`DkgOutput::wallet_address`] to the UI.
#[derive(Debug)]
pub struct DkgOutput {
    /// The device-side key share.  Store this in `SecureStorageService` under
    /// the key `mpc_device_share_v1`.  **Never log or transmit this value.**
    pub device_share: DeviceShare,
    /// EVM wallet address derived from the joint public key (EIP-55 checksummed).
    pub wallet_address: String,
}

// ─── DkgSession ──────────────────────────────────────────────────────────────

/// High-level 2-party DKG session for the device side.
///
/// Each instance wraps an [`MpcSession`] that tracks the ceremony lifecycle.
/// After construction the session is in [`crate::SessionState::Pending`].
/// Call [`DkgSession::run_local`] (in tests / bridge integration) or drive it
/// round-by-round via the Flutter bridge (Task 06) to produce a [`DkgOutput`].
pub struct DkgSession {
    inner: MpcSession,
}

impl DkgSession {
    /// Creates a new `DkgSession` in the [`crate::SessionState::Pending`] state.
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

    /// Runs a full 2-of-2 DKG ceremony locally (both parties in-process).
    ///
    /// This method is intended for unit and integration tests in this crate and
    /// for the `crates/flutter_bridge` integration test (Task 06).  In production
    /// the Flutter UI is responsible for the round-trip transport to the KhodPay
    /// signer server; that production API is added in Task 06.
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::DkgFailed`] if the protocol fails or if the resulting
    /// share cannot be serialised.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn run_local(&mut self) -> Result<DkgOutput> {
        // Transition: Pending → InProgress { round: 1 }
        self.inner.advance_round(1)?;

        let session_id = self.inner.session_id().to_owned();

        match run_two_party_dkg(&session_id) {
            Ok((device_incomplete_share, _server_incomplete_share)) => {
                let joint_pk = device_incomplete_share.shared_public_key();
                let wallet_address = evm_address_from_public_key(&joint_pk).map_err(|e| {
                    let _ = self.inner.fail(e.clone());
                    e
                })?;

                let share_bytes = serde_json::to_vec(&device_incomplete_share).map_err(|e| {
                    let err = MpcError::ShareDeserializationError {
                        reason: format!("failed to serialise device share: {e}"),
                    };
                    let _ = self.inner.fail(err.clone());
                    err
                })?;

                let device_share = DeviceShare::from_bytes(&share_bytes)?;
                self.inner.complete()?;

                Ok(DkgOutput {
                    device_share,
                    wallet_address,
                })
            }
            Err(e) => {
                let err = MpcError::DkgFailed {
                    reason: format!("CGGMP21 keygen failed: {e}"),
                };
                let _ = self.inner.fail(err.clone());
                Err(err)
            }
        }
    }
}

impl Default for DkgSession {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DkgSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkgSession")
            .field("session_id", &self.inner.session_id())
            .field("state", self.inner.state())
            .finish()
    }
}

// ─── Internal: two-party DKG simulation (test-only) ─────────────────────────

/// Runs a 2-party CGGMP21 non-threshold DKG (2-of-2) using `round_based::sim`.
///
/// Returns `(party_0_share, party_1_share)` on success.
///
/// Available in tests and when the `test-utils` feature is enabled.
#[cfg(any(test, feature = "test-utils"))]
pub fn run_two_party_dkg(
    execution_id_str: &str,
) -> std::result::Result<
    (IncompleteKeyShare<Secp256k1>, IncompleteKeyShare<Secp256k1>),
    cggmp21::KeygenError,
> {
    use sha3::{Digest, Sha3_256};

    // CGGMP21 ExecutionId needs fixed-size bytes; we SHA3-256 the string.
    let eid_bytes: [u8; 32] = Sha3_256::digest(execution_id_str.as_bytes()).into();

    type Msg = cggmp21::keygen::msg::non_threshold::Msg<
        Secp256k1,
        cggmp21::security_level::SecurityLevel128,
        sha2::Sha256,
    >;

    let results = round_based::sim::run::<Msg, _>(2, |i, party| {
        let eid = ExecutionId::new(&eid_bytes);
        let mut rng = OsRng;
        async move {
            cggmp21::keygen::<Secp256k1>(eid, i, 2)
                .start(&mut rng, party)
                .await
        }
    })
    .unwrap_or_else(|e| panic!("round_based sim infrastructure failed: {e}"));

    let mut outputs: Vec<_> = results.into_vec();
    assert_eq!(outputs.len(), 2);

    let server_share = outputs.pop().unwrap()?;
    let device_share = outputs.pop().unwrap()?;

    Ok((device_share, server_share))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MpcError, SessionState};

    // ─── Helper ─────────────────────────────────────────────────────────────

    fn successful_dkg() -> (DkgSession, DkgOutput) {
        let mut session = DkgSession::new();
        let output = session.run_local().expect("local DKG must succeed");
        (session, output)
    }

    // ─── Session lifecycle ───────────────────────────────────────────────────

    #[test]
    fn test_new_session_is_pending() {
        let session = DkgSession::new();
        assert!(matches!(session.session().state(), SessionState::Pending));
    }

    #[test]
    fn test_session_id_is_non_empty() {
        let session = DkgSession::new();
        assert!(!session.session_id().is_empty());
        assert_eq!(session.session_id().len(), 36); // UUID v4
    }

    #[test]
    fn test_after_run_local_session_is_complete() {
        let (session, _) = successful_dkg();
        assert!(session.session().is_complete());
        assert!(matches!(session.session().state(), SessionState::Complete));
    }

    #[test]
    fn test_run_local_twice_returns_protocol_violation() {
        let mut session = DkgSession::new();
        session.run_local().expect("first run must succeed");
        let err = session
            .run_local()
            .expect_err("second run on complete session must fail");
        assert!(
            matches!(err, MpcError::ProtocolViolation { .. }),
            "expected ProtocolViolation, got: {:?}",
            err
        );
    }

    // ─── DkgOutput: device share ─────────────────────────────────────────────

    #[test]
    fn test_device_share_is_non_empty() {
        let (_, output) = successful_dkg();
        assert!(!output.device_share.is_empty());
    }

    #[test]
    fn test_device_share_round_trips_through_bytes() {
        let (_, output) = successful_dkg();
        let bytes = output.device_share.to_bytes().to_vec();
        let restored =
            DeviceShare::from_bytes(&bytes).expect("round-trip from to_bytes must succeed");
        assert_eq!(output.device_share, restored);
    }

    #[test]
    fn test_device_share_deserialises_to_incomplete_key_share() {
        let (_, output) = successful_dkg();
        let bytes = output.device_share.to_bytes();
        let share: IncompleteKeyShare<Secp256k1> = serde_json::from_slice(bytes)
            .expect("device share bytes must deserialise to IncompleteKeyShare");
        assert_eq!(share.i, 0); // device is party 0
        assert_eq!(share.n(), 2); // 2-of-2
    }

    // ─── DkgOutput: wallet address ───────────────────────────────────────────

    #[test]
    fn test_wallet_address_format() {
        let (_, output) = successful_dkg();
        assert!(
            output.wallet_address.starts_with("0x"),
            "address must start with 0x: {}",
            output.wallet_address
        );
        assert_eq!(
            output.wallet_address.len(),
            42,
            "address must be 42 chars: {}",
            output.wallet_address
        );
        assert!(
            output.wallet_address[2..]
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "non-hex chars: {}",
            output.wallet_address
        );
    }

    #[test]
    fn test_wallet_address_is_deterministic_for_same_share() {
        let (_, output) = successful_dkg();
        let share: IncompleteKeyShare<Secp256k1> =
            serde_json::from_slice(output.device_share.to_bytes()).unwrap();
        let pk = share.shared_public_key();
        let re_derived = evm_address_from_public_key(&pk).unwrap();
        assert_eq!(output.wallet_address, re_derived);
    }

    #[test]
    fn test_two_dkg_runs_produce_different_addresses() {
        let (_, out1) = successful_dkg();
        let (_, out2) = successful_dkg();
        assert_ne!(
            out1.wallet_address, out2.wallet_address,
            "independent DKG runs must produce different wallet addresses"
        );
    }

    // ─── Security: share independence ────────────────────────────────────────

    #[test]
    fn test_incomplete_share_n_and_min_signers() {
        let (_, output) = successful_dkg();
        let share: IncompleteKeyShare<Secp256k1> =
            serde_json::from_slice(output.device_share.to_bytes()).unwrap();
        assert_eq!(share.n(), 2);
        assert_eq!(share.min_signers(), 2); // non-threshold: min_signers == n
    }

    #[test]
    fn test_both_shares_have_same_public_key() {
        let (dev, srv) = run_two_party_dkg("test-both-shares-same-pk").expect("DKG must succeed");
        assert_eq!(
            dev.shared_public_key(),
            srv.shared_public_key(),
            "both parties must agree on the joint public key"
        );
    }

    #[test]
    fn test_device_and_server_have_different_party_indices() {
        let (dev, srv) = run_two_party_dkg("test-different-indices").expect("DKG must succeed");
        assert_eq!(dev.i, 0);
        assert_eq!(srv.i, 1);
        assert_ne!(dev.i, srv.i);
    }

    #[test]
    fn test_device_share_public_commitment_differs_from_server() {
        let (dev, srv) =
            run_two_party_dkg("test-public-commitments-differ").expect("DKG must succeed");
        // Each party's commitment to their own secret share must be distinct
        assert_ne!(
            dev.public_shares[0], srv.public_shares[1],
            "party public commitments must be distinct"
        );
    }

    // ─── Interrupted session ─────────────────────────────────────────────────

    #[test]
    fn test_interrupted_session_leaves_state_pending() {
        let session = DkgSession::new();
        assert!(matches!(session.session().state(), SessionState::Pending));
        drop(session); // ZeroizeOnDrop fires; no share produced
    }

    // ─── Debug ───────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_contains_session_id() {
        let session = DkgSession::new();
        let id = session.session_id().to_string();
        let debug = format!("{session:?}");
        assert!(debug.contains(&id));
    }
}
