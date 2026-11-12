//! Aux-info generation and completion of key shares.
//!
//! Key generation ([`crate::transport::spawn_keygen_threshold`]) yields an *incomplete*
//! key share. A share can only sign once it is combined with *aux info*: the
//! party's Paillier key and the proofs and public parameters exchanged with the
//! other parties. Aux info comes from a second ceremony among the same parties,
//! which this module runs over the same round-by-round transport.
//!
//! # Cost
//!
//! Generating the Paillier primes ([`generate_primes`]) is the slow step:
//! seconds on a desktop and noticeably longer on a phone. It needs no network,
//! so callers should run it ahead of time on a background thread, not while the
//! user waits on a ceremony.
//!
//! # Security
//!
//! The primes, the aux info and the completed share are all secret. None of
//! them implements `Debug`, and the byte form of a completed share is zeroized
//! when the [`DeviceShare`] holding it is dropped.

use cggmp21::key_share::AnyKeyShare;
use cggmp21::supported_curves::Secp256k1;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::address::evm_address_from_public_key;
use crate::error::{MpcError, Result};
use crate::share::DeviceShare;
use crate::signing::encode_signature_evm;
use crate::transport::{drive, KeygenShare, ProtocolRunner, TransportError};

/// Security level used by every ceremony in this crate.
pub type SecurityLevel = cggmp21::security_level::SecurityLevel128;

/// A key share that can take part in signing.
pub type FullKeyShare = cggmp21::KeyShare<Secp256k1, SecurityLevel>;

/// The output of the aux-info ceremony.
pub type AuxInfoShare = cggmp21::key_share::AuxInfo<SecurityLevel>;

/// Pre-generated Paillier primes consumed by the aux-info ceremony.
pub type Primes = cggmp21::key_refresh::PregeneratedPrimes<SecurityLevel>;

/// Derives the 32-byte execution id for one ceremony.
///
/// Both parties derive it from the shared `session_id`. `purpose` (for example
/// `"keygen"` or `"aux"`) keeps ceremonies run under one session from sharing
/// an id.
pub fn execution_id(session_id: &str, purpose: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"khodpay-mpc-tss/v1/");
    hasher.update(purpose.as_bytes());
    hasher.update(b"/");
    hasher.update(session_id.as_bytes());
    hasher.finalize().into()
}

/// Generates the Paillier primes for one party. **Slow**: run it on a
/// background thread, ahead of the ceremony.
pub fn generate_primes() -> Primes {
    Primes::generate(&mut OsRng)
}

/// Starts one party of the aux-info ceremony. Every party that took part in key
/// generation takes part here, with the same index and the same `parties`.
pub fn spawn_aux_info_n(
    index: u16,
    parties: u16,
    execution_id: [u8; 32],
    primes: Primes,
) -> ProtocolRunner<AuxInfoShare> {
    use cggmp21::ExecutionId;

    ProtocolRunner::spawn(move |worker| {
        let eid = ExecutionId::new(&execution_id);
        let mut rng = OsRng;
        let sm = cggmp21::aux_info_gen::<SecurityLevel>(eid, index, parties, primes)
            .into_state_machine(&mut rng);
        drive(worker, sm, index, |result| {
            result.map_err(|e| {
                TransportError::Protocol(format!("aux info generation failed: {e}"))
            })
        });
    })
}

/// Combines a key-generation share with the aux info from the same party.
pub fn complete_key_share(incomplete: KeygenShare, aux: AuxInfoShare) -> Result<FullKeyShare> {
    FullKeyShare::from_parts((incomplete, aux)).map_err(|e| MpcError::InvalidShare {
        reason: format!("key share and aux info do not belong together: {e}"),
    })
}

/// The index this share's party had at key generation (0 device, 1 server,
/// 2 recovery in a 2-of-3 wallet).
pub fn share_index(share: &FullKeyShare) -> u16 {
    share.core.i
}

/// How many parties took part in key generation.
pub fn share_parties(share: &FullKeyShare) -> u16 {
    share.n()
}

/// How many shares are needed to sign.
pub fn share_threshold(share: &FullKeyShare) -> u16 {
    share.min_signers()
}

/// Signs `tx_hash` with two shares held in this process, without the server.
///
/// This is the recovery path: it needs the device share and the decrypted
/// recovery share together. `session_id` must be fresh for every signature.
/// Both shares are consumed and dropped with the worker threads.
pub fn sign_with_local_shares(
    first: FullKeyShare,
    second: FullKeyShare,
    session_id: &str,
    tx_hash: [u8; 32],
) -> std::result::Result<[u8; 65], TransportError> {
    let (mut a, mut b) = (first, second);
    if share_index(&a) > share_index(&b) {
        std::mem::swap(&mut a, &mut b);
    }
    let (index_a, index_b) = (share_index(&a), share_index(&b));
    if index_a == index_b {
        return Err(TransportError::Protocol(
            "both shares belong to the same party".into(),
        ));
    }
    if share_threshold(&a) != 2 || share_threshold(&b) != 2 {
        return Err(TransportError::Protocol(
            "local signing needs shares of a 2-signer wallet".into(),
        ));
    }
    let group = vec![index_a, index_b];
    let eid = execution_id(session_id, "sign");
    let mut run_a = spawn_signing_subset(0, group.clone(), eid, a, tx_hash);
    let mut run_b = spawn_signing_subset(1, group, eid, b, tx_hash);

    let (mut for_a, mut for_b) = (Vec::new(), Vec::new());
    let (mut out_a, mut out_b) = (None, None);
    for _ in 0..200 {
        let mut progressed = false;
        if out_a.is_none() {
            let step = run_a.step(std::mem::take(&mut for_a))?;
            progressed |= !step.outgoing.is_empty() || step.output.is_some();
            for_b.extend(step.outgoing);
            out_a = step.output;
        }
        if out_b.is_none() {
            let step = run_b.step(std::mem::take(&mut for_b))?;
            progressed |= !step.outgoing.is_empty() || step.output.is_some();
            for_a.extend(step.outgoing);
            out_b = step.output;
        }
        if let (Some(sig), Some(_)) = (&out_a, &out_b) {
            return Ok(*sig);
        }
        if !progressed {
            return Err(TransportError::Protocol("local signing stalled".into()));
        }
    }
    Err(TransportError::Protocol(
        "local signing did not finish in 200 rounds".into(),
    ))
}

/// The EIP-55 wallet address derived from the joint public key.
pub fn wallet_address(share: &FullKeyShare) -> Result<String> {
    evm_address_from_public_key(&share.core.shared_public_key)
}

/// Serializes a completed share into the opaque bytes kept in secure storage.
pub fn to_device_share(share: &FullKeyShare) -> Result<DeviceShare> {
    let mut bytes = serde_json::to_vec(share).map_err(|e| MpcError::ShareDeserializationError {
        reason: format!("failed to serialise key share: {e}"),
    })?;
    let result = DeviceShare::from_bytes(&bytes);
    bytes.zeroize();
    result
}

/// Restores a completed share from [`to_device_share`] bytes.
///
/// Fails for a share that has no aux info, such as one produced before aux-info
/// generation was added.
pub fn from_device_share(share: &DeviceShare) -> Result<FullKeyShare> {
    serde_json::from_slice(share.to_bytes()).map_err(|e| MpcError::InvalidShare {
        reason: format!("not a complete key share: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_id_depends_on_session_and_purpose() {
        let base = execution_id("session-1", "keygen");
        assert_eq!(base, execution_id("session-1", "keygen"));
        assert_ne!(base, execution_id("session-2", "keygen"));
        assert_ne!(base, execution_id("session-1", "aux"));
    }

}

// ─── Signing ─────────────────────────────────────────────────────────────────

/// The position of the party that had index `keygen_index` at key generation
/// within a signing group, or `None` if it is not in the group.
///
/// Signing groups are listed in ascending keygen order, so the same group is
/// described by the same list on every side. The position, not the keygen
/// index, is the party index used in the signing ceremony's messages.
pub fn signing_position(group: &[u16], keygen_index: u16) -> Option<u16> {
    group.iter().position(|&i| i == keygen_index).map(|p| p as u16)
}

/// Starts one party of a signing ceremony run by `group`: the keygen indexes of
/// the parties that sign, in ascending order, exactly as many as the key's
/// threshold. `position` is this party's place in `group` (see
/// [`signing_position`]); `share` must be the share that party holds.
///
/// The runner's output is the 65-byte EVM signature `r ‖ s ‖ v` (`v` is 0 or 1),
/// already checked to recover to the wallet address of `share`. All signers must
/// pass the same `group`, `execution_id` and `tx_hash`, and a new
/// `execution_id` for every signature (`execution_id(session_id, "sign")` with a
/// fresh session id does that). The share is moved into the worker thread and
/// dropped with it.
pub fn spawn_signing_subset(
    position: u16,
    group: Vec<u16>,
    execution_id: [u8; 32],
    share: FullKeyShare,
    tx_hash: [u8; 32],
) -> ProtocolRunner<[u8; 65]> {
    use cggmp21::{generic_ec::Scalar, DataToSign, ExecutionId};
    let index = position;

    ProtocolRunner::spawn(move |worker| {
        let address = match wallet_address(&share) {
            Ok(address) => address,
            Err(e) => {
                return worker.fail(TransportError::Protocol(format!(
                    "key share has no valid wallet address: {e}"
                )))
            }
        };

        let eid = ExecutionId::new(&execution_id);
        let mut rng = OsRng;
        // The 32-byte hash is signed as-is (reduced mod the group order), not
        // hashed again.
        let data = DataToSign::from_scalar(Scalar::from_be_bytes_mod_order(tx_hash));
        let sm = cggmp21::signing(eid, index, &group, &share)
            .sign_sync(&mut rng, data);

        drive(worker, sm, index, |result| {
            let signature = result
                .map_err(|e| TransportError::Protocol(format!("signing failed: {e}")))?;
            encode_signature_evm(&signature, &address, tx_hash)
                .map_err(|e| TransportError::Protocol(e.to_string()))
        });
    })
}
