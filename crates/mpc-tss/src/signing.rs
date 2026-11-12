
//! EVM signature encoding and verification.
//!
//! The signing ceremony itself is in [`crate::aux_info`] (`spawn_signing_subset`).
//! This module turns its result, a `cggmp21::Signature` carrying `r` and `s`,
//! into the 65-byte `r || s || v` form EVM chains use, and checks such a
//! signature against a wallet address.
//!
//! `v` is the raw recovery id, `0` or `1` (callers add 27 or the chain offset).
//! It is found by trial: recover the public key for `v = 0`, compare with the
//! wallet address, and try `v = 1` if it does not match.

// ─── Signature encoding ───────────────────────────────────────────────────────

/// Encodes a `cggmp21::Signature` into the 65-byte EVM `r || s || v` format.
///
/// The recovery ID `v` (0 or 1) is determined by trial: we try both candidates
/// and pick whichever recovers to `expected_address`.
///
/// # Errors
///
/// Returns [`crate::MpcError::SigningFailed`] if neither recovery ID produces
/// the expected address (should never happen for a correctly-produced signature).
pub fn encode_signature_evm(
    sig: &cggmp21::Signature<cggmp21::supported_curves::Secp256k1>,
    expected_address: &str,
    tx_hash: [u8; 32],
) -> crate::error::Result<[u8; 65]> {
    use crate::error::MpcError;
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};

    // Extract r and s from the cggmp21 Signature.
    // generic_ec Scalar::to_be_bytes() returns EncodedScalar which implements
    // AsRef<[u8]> — copy into a fixed [u8; 32] array.
    let r_enc = sig.r.to_be_bytes();
    let s_enc = sig.s.to_be_bytes();
    let r_bytes: [u8; 32] = r_enc
        .as_ref()
        .try_into()
        .map_err(|_| MpcError::SigningFailed {
            reason: "r scalar is not 32 bytes".into(),
        })?;
    let s_bytes: [u8; 32] = s_enc
        .as_ref()
        .try_into()
        .map_err(|_| MpcError::SigningFailed {
            reason: "s scalar is not 32 bytes".into(),
        })?;

    // Build a k256 compact signature from r||s bytes.
    // Use from_slice to avoid the low-S normalisation that from_scalars applies,
    // which would change s and invalidate the recovery ID computation.
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&r_bytes);
    compact[32..].copy_from_slice(&s_bytes);
    let k256_sig = K256Sig::from_slice(&compact).map_err(|e| MpcError::SigningFailed {
        reason: format!("failed to construct k256 signature from r,s: {e}"),
    })?;

    // Trial recovery: try v=0 then v=1, pick the one that matches the wallet address.
    for v in [0u8, 1u8] {
        let recid = RecoveryId::try_from(v).expect("v is 0 or 1");

        let Ok(verifying_key) = VerifyingKey::recover_from_prehash(&tx_hash, &k256_sig, recid)
        else {
            continue;
        };

        // Derive the EVM address from the recovered public key.
        let recovered_address = k256_pubkey_to_evm_address(&verifying_key);

        if recovered_address.eq_ignore_ascii_case(expected_address) {
            let mut out = [0u8; 65];
            out[..32].copy_from_slice(&r_bytes);
            out[32..64].copy_from_slice(&s_bytes);
            out[64] = v;
            return Ok(out);
        }
    }

    Err(MpcError::SigningFailed {
        reason: format!(
            "signature does not recover to expected address {expected_address}; \
             this indicates a key-share mismatch"
        ),
    })
}

/// Derives an EVM address string from a `k256::ecdsa::VerifyingKey`.
///
/// Used internally for recovery-ID selection.  Returns a lowercase `0x...`
/// string (not checksummed — only used for comparison, not display).
fn k256_pubkey_to_evm_address(vk: &k256::ecdsa::VerifyingKey) -> String {
    use sha3::{Digest, Keccak256};

    // Uncompressed SEC1: 0x04 || x (32) || y (32) — total 65 bytes.
    // VerifyingKey wraps AffinePoint which implements ToEncodedPoint via k256.
    let encoded = vk.to_encoded_point(false);
    let raw = &encoded.as_bytes()[1..]; // drop the 0x04 prefix → 64 bytes

    let hash: [u8; 32] = Keccak256::digest(raw).into();
    let addr_bytes: [u8; 20] = hash[12..].try_into().expect("hash[12..] is 20 bytes");

    format!(
        "0x{}",
        addr_bytes
            .iter()
            .fold(String::with_capacity(40), |mut s, b| {
                s.push_str(&format!("{b:02x}"));
                s
            })
    )
}

/// Verifies that a 65-byte EVM signature `r || s || v` recovers to `expected_address`
/// for the given 32-byte prehash.
///
/// Returns `true` if and only if recovery succeeds and the recovered address
/// matches (case-insensitive comparison).
///
/// This is the canonical verification function for Task 04 acceptance criteria.
pub fn verify_signature_recovers_address(
    signature: &[u8; 65],
    tx_hash: [u8; 32],
    expected_address: &str,
) -> bool {
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};

    let r: [u8; 32] = signature[..32].try_into().expect("sig[..32] is 32 bytes");
    let s: [u8; 32] = signature[32..64]
        .try_into()
        .expect("sig[32..64] is 32 bytes");
    let v = signature[64];

    let Ok(k256_sig) = K256Sig::from_slice(&{
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&r);
        compact[32..].copy_from_slice(&s);
        compact
    }) else {
        return false;
    };
    let Ok(recid) = RecoveryId::try_from(v) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::recover_from_prehash(&tx_hash, &k256_sig, recid) else {
        return false;
    };

    let recovered = k256_pubkey_to_evm_address(&vk);
    recovered.eq_ignore_ascii_case(expected_address)
}


#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    const HASH: [u8; 32] = [0x24; 32];

    /// A recoverable signature over `HASH` and the address of its key, made
    /// with a plain single key, so these tests need no ceremony.
    fn signature_and_address() -> ([u8; 65], String) {
        let key = SigningKey::from_bytes((&[0x11u8; 32]).into()).expect("valid key");
        let (sig, recid) = key.sign_prehash_recoverable(&HASH).expect("signs");
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = recid.to_byte();
        (out, k256_pubkey_to_evm_address(key.verifying_key()))
    }

    #[test]
    fn a_signature_recovers_to_the_signing_address() {
        let (sig, address) = signature_and_address();
        assert!(verify_signature_recovers_address(&sig, HASH, &address));
    }

    #[test]
    fn address_comparison_ignores_case() {
        let (sig, address) = signature_and_address();
        let upper = format!("0x{}", address[2..].to_uppercase());
        assert!(verify_signature_recovers_address(&sig, HASH, &upper));
    }

    #[test]
    fn a_different_hash_does_not_verify() {
        let (sig, address) = signature_and_address();
        assert!(!verify_signature_recovers_address(&sig, [0x25; 32], &address));
    }

    #[test]
    fn a_different_address_does_not_verify() {
        let (sig, _) = signature_and_address();
        assert!(!verify_signature_recovers_address(
            &sig,
            HASH,
            "0x0000000000000000000000000000000000000001"
        ));
    }

    #[test]
    fn an_all_zero_signature_does_not_verify() {
        assert!(!verify_signature_recovers_address(&[0u8; 65], HASH, "0x0"));
    }

    #[test]
    fn an_invalid_recovery_id_does_not_verify() {
        let (mut sig, address) = signature_and_address();
        sig[64] = 255;
        assert!(!verify_signature_recovers_address(&sig, HASH, &address));
    }
}
