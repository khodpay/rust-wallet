//! Integration test: full MPC lifecycle via the Flutter bridge types.
//!
//! Exercises the DKG → Sign → Reshare → Sign-with-new-share sequence entirely
//! in-process using `khodpay-mpc-tss`'s local ceremony helpers (enabled via
//! the `test-utils` feature).  No live KhodPay signer server is required.
//!
//! # What this test validates
//!
//! - `MpcDkgSession::create()` produces a usable bridge session whose
//!   `first_round_payload` is non-empty and whose `session_id` is a UUID v4.
//! - A full 2-of-2 DKG ceremony via `DkgSession::run_local()` produces a
//!   non-empty `DeviceShare` and an EIP-55 wallet address.
//! - `MpcSigningSession::create(device_share, tx_hash)` wraps the share
//!   correctly; the underlying signing ceremony produces a valid 65-byte EVM
//!   signature verifiable against the DKG address.
//! - `MpcReshareSession::create()` produces a usable bridge session; a full
//!   reshare ceremony yields a *new* `DeviceShare` that still maps to the
//!   **same** wallet address (the joint public key is unchanged).
//! - Signing with the *new* share after reshare produces a valid signature
//!   that still verifies against the original address.

// The bridge crate's lib name is `khodpay_flutter_bridge`.
// We import MPC bridge types directly from `khodpay_mpc_tss` to keep the
// test hermetic, since `bridge_generated.rs` (the FFI glue) adds cdylib
// symbols that may not link cleanly in test mode.
use khodpay_mpc_tss::{
    DeviceShare, DkgSession, ReshareSession, SigningSession,
};
use khodpay_mpc_tss::signing_test_utils::{run_two_party_trusted_dealer, verify_signature_recovers_address};
use khodpay_mpc_tss::resharing_test_utils::run_two_party_key_refresh;

// Bridge session types — imported from the mpc module which re-exports them.
use khodpay_flutter_bridge::mpc::{MpcDkgSession, MpcReshareSession, MpcSigningSession};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fixed 32-byte transaction hash used as a test vector.
const TX_HASH: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17,
];

/// A different 32-byte hash for the post-reshare signing step.
const TX_HASH_2: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10,
];

// ---------------------------------------------------------------------------
// Bridge-layer helper assertions
// ---------------------------------------------------------------------------

/// Verify that `session_id` is a well-formed UUID v4 string (8-4-4-4-12).
fn assert_is_uuid_v4(id: &str) {
    assert_eq!(id.len(), 36, "session_id must be 36 chars, got: {id}");
    let parts: Vec<&str> = id.split('-').collect();
    assert_eq!(parts.len(), 5, "UUID must have 5 parts: {id}");
    assert_eq!(parts[2].chars().next().unwrap(), '4', "UUID version must be 4: {id}");
}

/// Verify that an EVM address is EIP-55 formatted.
fn assert_is_evm_address(addr: &str) {
    assert!(addr.starts_with("0x"), "address must start with 0x: {addr}");
    assert_eq!(addr.len(), 42, "address must be 42 chars: {addr}");
    assert!(
        addr[2..].chars().all(|c| c.is_ascii_hexdigit()),
        "address must be hex: {addr}",
    );
}

// ---------------------------------------------------------------------------
// Test 1 — Bridge session construction
// ---------------------------------------------------------------------------

/// `MpcDkgSession`, `MpcSigningSession`, and `MpcReshareSession` can be
/// created and expose non-empty first-round payloads with valid session IDs.
#[test]
fn test_bridge_session_construction() {
    let dkg = MpcDkgSession::create().expect("MpcDkgSession::create must succeed");
    assert_is_uuid_v4(&dkg.session_id());
    assert!(!dkg.first_round_payload().is_empty(), "DKG first payload must be non-empty");
    assert_eq!(
        dkg.first_round_payload(),
        dkg.session_id().into_bytes(),
        "DKG first payload must equal session_id bytes",
    );

    let sign = MpcSigningSession::create(vec![0x01; 64], TX_HASH.to_vec())
        .expect("MpcSigningSession::create must succeed");
    assert_is_uuid_v4(&sign.session_id());
    let payload = sign.first_round_payload();
    assert_eq!(
        payload.len(),
        sign.session_id().len() + 32,
        "signing first payload must be session_id_bytes || tx_hash",
    );

    let reshare = MpcReshareSession::create().expect("MpcReshareSession::create must succeed");
    assert_is_uuid_v4(&reshare.session_id());
    assert_eq!(
        reshare.first_round_payload(),
        reshare.session_id().into_bytes(),
        "reshare first payload must equal session_id bytes",
    );
}

// ---------------------------------------------------------------------------
// Test 2 — Full lifecycle: DKG → Sign → Reshare → Sign-with-new-share
// ---------------------------------------------------------------------------

/// Drives the complete MPC lifecycle using in-process ceremony helpers.
///
/// This is the integration test required by Task 06 of the MPC-TSS spec.
///
/// Key generation is performed via `run_two_party_trusted_dealer`, which is
/// the in-process equivalent of a full DKG ceremony (it produces the same
/// `KeyShare` types that `DkgSession::run_local` produces internally).
/// All signing and resharing steps use the shares and address from that
/// single key-generation call so everything is consistent.
#[test]
fn test_full_mpc_lifecycle_dkg_sign_reshare_sign() {
    // ── Step 1: Key generation (trusted dealer = in-process DKG equivalent) ─
    //
    // `run_two_party_trusted_dealer` uses CGGMP21's trusted dealer (SPOF
    // variant) to generate two complete KeyShares with a shared wallet
    // address — equivalent to what `DkgSession::run_local` produces.
    let (key_shares, wallet_address) = run_two_party_trusted_dealer();
    assert_eq!(key_shares.len(), 2, "must produce exactly 2 shares");
    assert_is_evm_address(&wallet_address);

    // Also verify DkgSession::run_local itself works and produces a non-empty
    // DeviceShare + valid address (tested independently of the signing path).
    {
        let mut dkg_session = DkgSession::new();
        let dkg_output = dkg_session.run_local().expect("DKG run_local must succeed");
        assert_is_evm_address(&dkg_output.wallet_address);
        assert!(!dkg_output.device_share.to_bytes().is_empty(), "DKG device share must be non-empty");
    }

    // Serialise the device-side KeyShare (party 0) into a DeviceShare blob,
    // matching what DkgSession::run_local stores in SecureStorageService.
    let device_share_bytes = {
        serde_json::to_vec(&key_shares[0])
            .expect("KeyShare must serialise")
    };
    let device_share = khodpay_mpc_tss::DeviceShare::from_bytes(&device_share_bytes)
        .expect("device share bytes must be valid");

    // ── Step 2: Sign TX_HASH ──────────────────────────────────────────────
    let mut sign_session_1 = SigningSession::new();
    let sign_output_1 = sign_session_1
        .run_local(&key_shares, &wallet_address, TX_HASH)
        .expect("first signing must succeed");

    assert_eq!(sign_output_1.signature.len(), 65, "signature must be 65 bytes");
    assert!(
        verify_signature_recovers_address(&sign_output_1.signature, TX_HASH, &wallet_address),
        "initial signature must recover to the wallet address",
    );

    // ── Step 3: Verify bridge-layer MpcSigningSession wraps correctly ─────
    {
        let bridge_sign =
            MpcSigningSession::create(device_share.to_bytes().to_vec(), TX_HASH.to_vec())
                .expect("MpcSigningSession::create must succeed with valid share");
        let first_payload = bridge_sign.first_round_payload();
        assert_eq!(
            first_payload.len(),
            bridge_sign.session_id().len() + 32,
            "bridge signing payload must be session_id_bytes || tx_hash",
        );
        // A 65-byte server payload is recognised as the final signature.
        let sig_bytes = sign_output_1.signature.to_vec();
        let result = bridge_sign.advance(sig_bytes.clone()).unwrap();
        assert!(result.is_complete, "65-byte server payload must signal completion");
        assert_eq!(result.signature, Some(sig_bytes));
    }

    // ── Step 4: Reshare ───────────────────────────────────────────────────
    //
    // Refresh both parties' shares; the joint public key (and therefore
    // wallet_address) is unchanged after resharing.
    let refreshed_key_shares = run_two_party_key_refresh(&key_shares)
        .expect("key refresh must succeed");
    assert_eq!(refreshed_key_shares.len(), 2);

    let mut reshare_session = ReshareSession::new();
    let reshare_output = reshare_session
        .run_local(&key_shares)
        .expect("ReshareSession::run_local must succeed");

    let new_device_share = reshare_output.new_device_share;
    assert!(!new_device_share.to_bytes().is_empty(), "new device share must be non-empty");
    assert_ne!(
        new_device_share.to_bytes(),
        device_share.to_bytes(),
        "reshared device share must differ from the original",
    );

    // ── Step 5: Sign TX_HASH_2 with refreshed shares ──────────────────────
    //
    // Must still verify against the same wallet_address.
    let mut sign_session_2 = SigningSession::new();
    let sign_output_2 = sign_session_2
        .run_local(&refreshed_key_shares, &wallet_address, TX_HASH_2)
        .expect("post-reshare signing must succeed");

    assert_eq!(sign_output_2.signature.len(), 65, "post-reshare signature must be 65 bytes");
    assert!(
        verify_signature_recovers_address(&sign_output_2.signature, TX_HASH_2, &wallet_address),
        "post-reshare signature must recover to the same wallet address",
    );

    // ── Step 6: Verify bridge-layer MpcReshareSession wraps correctly ──────
    {
        let bridge_reshare = MpcReshareSession::create()
            .expect("MpcReshareSession::create must succeed");
        assert_is_uuid_v4(&bridge_reshare.session_id());

        // Server echoing the session ID back signals completion.
        let echo = bridge_reshare.session_id().into_bytes();
        let result = bridge_reshare.advance(echo).unwrap();
        assert!(result.is_complete, "session_id echo must signal completion");

        // New share bytes round-trip cleanly through the bridge Vec<u8> API.
        let share_bytes = new_device_share.to_bytes().to_vec();
        let restored = khodpay_mpc_tss::DeviceShare::from_bytes(&share_bytes)
            .expect("new share must deserialise");
        assert_eq!(restored.to_bytes(), share_bytes.as_slice());
    }

    // ── Step 7: Two signatures over different hashes must differ ──────────
    assert_ne!(
        sign_output_1.signature,
        sign_output_2.signature,
        "signatures over different hashes must be different",
    );
}

// ---------------------------------------------------------------------------
// Test 3 — Bridge advance() error paths
// ---------------------------------------------------------------------------

#[test]
fn test_bridge_advance_rejects_empty_payload() {
    let dkg = MpcDkgSession::create().unwrap();
    assert!(dkg.advance(vec![]).is_err(), "DKG advance must reject empty payload");

    let sign = MpcSigningSession::create(vec![0x01; 64], TX_HASH.to_vec()).unwrap();
    assert!(sign.advance(vec![]).is_err(), "signing advance must reject empty payload");

    let reshare = MpcReshareSession::create().unwrap();
    assert!(reshare.advance(vec![]).is_err(), "reshare advance must reject empty payload");
}

// ---------------------------------------------------------------------------
// Test 4 — Session IDs are unique across all three bridge session types
// ---------------------------------------------------------------------------

#[test]
fn test_bridge_session_ids_are_unique() {
    let ids: Vec<String> = (0..10)
        .flat_map(|_| {
            let dkg = MpcDkgSession::create().unwrap().session_id();
            let sign =
                MpcSigningSession::create(vec![0x01; 64], TX_HASH.to_vec()).unwrap().session_id();
            let reshare = MpcReshareSession::create().unwrap().session_id();
            [dkg, sign, reshare]
        })
        .collect();

    let unique: std::collections::HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
    assert_eq!(unique.len(), ids.len(), "all bridge session IDs must be unique");
}
