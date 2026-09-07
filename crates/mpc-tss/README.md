# khodpay-mpc-tss

2-of-2 threshold ECDSA engine for secp256k1 / EVM — device-side implementation.

This crate provides the cryptographic core for the KhodPay MPC wallet. It
implements distributed key generation (DKG), threshold signing, and key
resharing for the user's device party in a 2-of-2 CGGMP21 ceremony with a
KhodPay-operated signer server.

---

## Protocol

**CGGMP21** (Canetti-Gennaro-Goldfeder-Makriyannis-Peled, 2021) implemented
by [`cggmp21 v0.6.3`](https://crates.io/crates/cggmp21) on the `secp256k1`
curve.

CGGMP21 was chosen over DKLS19 for its stronger security proofs (UC-security
in the random-oracle model) and active upstream maintenance. The trade-off is
a dependency on GMP via `fast-paillier` for the Paillier-modulus operations
used in the ZK proofs; mobile cross-compilation requires pre-building the GMP
cache (see `scripts/build_gmp_cache.sh`).

**Key property:** no single complete private key is ever assembled on either
party at any point — not during DKG, not during signing, not during resharing.

---

## API surface

### DKG — key generation

```rust
use khodpay_mpc_tss::{DkgSession, DeviceShare};

// Device side initiates a DKG ceremony.
// In production the Flutter bridge drives this round-by-round via gRPC.
let mut session = DkgSession::new();
let session_id = session.session_id(); // forward to signer server

// run_local() is available under #[cfg(any(test, feature = "test-utils"))].
// Production drives the rounds individually through the Flutter bridge.
let output = session.run_local()?;

// Store the device share in SecureStorageService under "mpc_device_share_v1".
let share_bytes: Vec<u8> = output.device_share.to_bytes().to_vec();
let wallet_address: String = output.wallet_address; // EIP-55 checksummed
```

### Threshold signing

```rust
use khodpay_mpc_tss::{SigningSession, DeviceShare};

let share = DeviceShare::from_bytes(&stored_bytes)?;
let tx_hash: [u8; 32] = keccak256_of_encoded_tx;

let mut session = SigningSession::new();
// In production: drive rounds via Flutter bridge gRPC transport.
// The 65-byte signature is r || s || v (EVM convention, v = 0 or 1).
```

### Resharing — device-loss recovery

```rust
use khodpay_mpc_tss::ReshareSession;

let mut session = ReshareSession::new();
// Server authorises via Google ID token (server-side concern).
// In production: drive rounds via Flutter bridge gRPC transport.
// On completion, store new_device_share, overwriting the old entry.
```

---

## Security properties

| Property | Detail |
|---|---|
| No key reconstruction | CGGMP21 splits the private key across both parties via Paillier-encrypted MtA; neither party's share alone is useful |
| Zeroize on drop | `DeviceShare` implements `ZeroizeOnDrop` — secret bytes are wiped from heap memory when the value is dropped |
| Redacted `Debug` | `Debug` impls for all secret-holding types print `[REDACTED]`; no key bytes appear in logs at any level |
| No BIP39 involvement | MPC key material is entirely independent of any mnemonic, seed, or derivation path |
| Resharing invalidation | After resharing, the server discards its old share; any signing attempt using the old device share is rejected |

---

## Features

| Feature | Description |
|---|---|
| *(default)* | Production API: `DkgSession`, `SigningSession`, `ReshareSession`, `DeviceShare` |
| `test-utils` | Exposes `run_local()`, `run_two_party_*`, and `trusted_dealer` helpers for integration tests in other crates. **Never enable in production.** |

---

## Crate layout

```
src/
  lib.rs          — public re-exports and crate-level docs
  error.rs        — MpcError enum + Result alias
  share.rs        — DeviceShare (opaque, zeroizing byte blob)
  session.rs      — MpcSession state machine + RoundPayload
  dkg.rs          — DkgSession + DkgOutput
  signing.rs      — SigningSession + SigningOutput + verify_signature_recovers_address
  resharing.rs    — ReshareSession + ReshareOutput
  address.rs      — EVM address derivation (public key → EIP-55 string)
```

---

## Flutter bridge

The Flutter-facing wrappers (`MpcDkgSession`, `MpcSigningSession`,
`MpcReshareSession`) live in `crates/flutter_bridge/src/mpc.rs`.
See `docs/FLUTTER_API_SUMMARY.md` for Dart API signatures.
