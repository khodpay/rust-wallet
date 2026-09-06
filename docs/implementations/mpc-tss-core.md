# US-004.1 (khodpay-wallet): MPC TSS Core & Flutter Bridge

**Status:** 📋 Draft
**Priority:** High
**Epic:** MPC Wallet (Security & Backup)
**Created:** 2026-09-06
**Last Updated:** 2026-09-06
**Assignee:** -
**Related Story:** [`docs/stories/US-004.1-mpc-wallet-creation.md`](../../../AndroidStudioProjects/paypax_wallet_app/docs/stories/US-004.1-mpc-wallet-creation.md) (PayPax app — authoritative spec)
**Depends On:** —
**Blocks:** `US-004.2` (Flutter UI), `US-001.13` (MPC restore UI)

---

## Background

This is the `khodpay-wallet` scope of `US-004.1`. That story is split across
two repos: this file owns the **Rust cryptographic engine** (a new
`crates/mpc-tss` crate) and the **`flutter_rust_bridge` exposure** of it
(additions to `crates/flutter_bridge`).

The `khodpay_backend` scope (the signer server binary) lives in
`khodpay_backend/docs/stories/US-004.1-mpc-signer-server.md`.

**Architecture recap** (from `mpc-wallet-overview.md`):
- Self-hosted 2-of-2 threshold ECDSA for secp256k1/EVM.
- Two parties: the user's device (this crate) and a KhodPay-operated signer
  server (the backend story). The full private key is never assembled
  anywhere, including during signing.
- Protocol family: **CGGMP21 or DKLS19** (final pick is an open question —
  see Open Questions below; `taurushq-io/multi-party-sig` is the reference
  Rust library).
- This crate's output slots into the existing Flutter app next to the BIP39
  HD-wallet path: `flutter_rust_bridge` OOP types following the existing
  `Mnemonic` / `Bip44Wallet` / `EvmSigner` pattern.

---

## Goal

**As the Flutter app**
**I want to** call DKG, threshold signing, and resharing through a
`flutter_rust_bridge`-exposed Rust API backed by a real 2-of-2 TSS
implementation
**So that** `US-004.2` and `US-001.13` can build production UI against a
functioning cryptographic engine instead of a stub

---

## Acceptance Criteria

- [ ] A new `crates/mpc-tss` crate implements 2-party DKG, threshold
      signing, and resharing for secp256k1/ECDSA; no single complete private
      key is ever assembled on either side at any point
- [ ] DKG produces a device share and a joint EVM address; the device share
      plus the server's cooperating share are sufficient to sign; neither
      alone is sufficient
- [ ] Threshold signing produces a valid ECDSA signature over a given 32-byte
      hash, verifiable against the address derived during DKG
- [ ] Resharing issues a new device share bound to the same public key,
      rendering the previous device share invalid, without changing the
      on-chain address
- [ ] All three operations are exposed via `flutter_rust_bridge` in
      `crates/flutter_bridge`, following the OOP pattern of existing types
- [ ] The device share is returned as an opaque byte blob suitable for
      storage via `SecureStorageService` under the key `mpc_device_share_v1`
- [ ] No mnemonic, BIP39 seed, or BIP32 derivation path is involved in any
      MPC code path
- [ ] No key material (shares, DKG intermediate messages, signing-round
      payloads) is ever written to a log at any log level
- [ ] Unit tests cover: DKG round execution, signing a known hash, resharing
      invalidation, all error/failure paths
- [ ] Integration test in `crates/flutter_bridge` drives the full
      DKG → sign → reshare lifecycle using a mock/local server transport,
      with no UI harness

---

## Crate Structure

```
crates/
  mpc-tss/
    Cargo.toml
    src/
      lib.rs
      error.rs
      session.rs        — session state machine shared by DKG/sign/reshare
      dkg.rs            — 2-party DKG: key generation ceremony
      signing.rs        — 2-party threshold signing
      resharing.rs      — resharing: issue new device share, invalidate old
      share.rs          — DeviceShare: opaque serialisable type
      address.rs        — derive EVM address from joint public key
  flutter_bridge/
    src/
      mpc.rs            — #[frb]-annotated OOP types exposed to Dart
      bridge.rs         — existing file, re-export new MPC symbols
```

---

## Tasks

---

### Task 01 — Crate scaffold & error types

**Phase:** Foundation
**Effort:** 1 day

- [ ] Create `crates/mpc-tss/` with `Cargo.toml`; add dependency on the
      chosen threshold-ECDSA library (CGGMP21 or DKLS19 from
      `taurushq-io/multi-party-sig`, pinned exact version), plus
      `thiserror`, `zeroize`, `serde`, `k256`, `rand`
- [ ] Add `crates/mpc-tss` to the workspace `Cargo.toml` `members` list
- [ ] Define `MpcError` enum covering all failure modes: `DkgFailed`,
      `SigningFailed`, `ResharingFailed`, `InvalidShare`, `ProtocolViolation`,
      `NetworkRoundFailed { round: u8 }`, `ShareDeserializationError`,
      with `#[derive(thiserror::Error)]`
- [ ] Define `DeviceShare` struct: newtype over `Vec<u8>`, implements
      `Serialize`/`Deserialize`, `Zeroize`, `ZeroizeOnDrop`; expose
      `to_bytes() -> &[u8]` and `from_bytes(b: &[u8]) -> Result<Self,
      MpcError>`
- [ ] Confirm `cargo check` and `cargo test` (no tests yet, just clean build)

---

### Task 02 — Session state machine

**Phase:** Foundation
**Effort:** 1 day

- [ ] Define `SessionState` enum: `Pending`, `InProgress { round: u8 }`,
      `Complete`, `Failed(MpcError)` with `#[derive(Clone, Debug)]`
- [ ] Define `RoundPayload` newtype over `Vec<u8>` — opaque wire bytes for
      one protocol round (maps to the `round_payload` field in the gRPC
      contract)
- [ ] Implement `MpcSession` struct holding `session_id: String`, current
      `SessionState`, and the internal protocol state from the chosen library;
      expose `session_id(&self) -> &str`, `is_complete(&self) -> bool`,
      `is_failed(&self) -> bool`
- [ ] Implement `session_id` generation: UUID v4 (`uuid` crate,
      `gen_random` feature)
- [ ] Unit tests: session transitions through all states, double-complete
      panics/errors

---

### Task 03 — 2-party DKG

**Phase:** Core Protocol
**Effort:** 3–4 days

- [ ] Implement `DkgSession` (wraps `MpcSession`) with:
  - `start() -> Result<(DkgSession, RoundPayload), MpcError>` — initialises
    the party-1 DKG state; returns the first-round message to be forwarded
    to the server
  - `advance(server_payload: RoundPayload) -> Result<DkgRoundResult,
    MpcError>` — processes one round of server response; returns either
    `DkgRoundResult::Round { next_payload }` or
    `DkgRoundResult::Complete { device_share, wallet_address }`
- [ ] Ensure the joint public key (and therefore `wallet_address`) is
      derived from the combined key material of both parties; neither party's
      share alone yields the address
- [ ] Add `wallet_address` derivation: from joint public key → uncompressed
      SEC1 → keccak256 of last 64 bytes → last 20 bytes → EIP-55 checksum
      (reuse `address.rs` helper, consistent with `khodpay-signing`'s
      existing `Address` type if compatible)
- [ ] Ensure that if DKG is interrupted at any round (simulated by dropping
      `DkgSession` mid-flow), no usable share is left; the incomplete session
      produces only `SessionState::Failed`
- [ ] Unit tests: complete 2-party DKG against a local simulated second
      party; verify resulting address is deterministic for fixed inputs;
      verify interrupted-session path; verify neither party's share alone
      yields a usable private key

---

### Task 04 — 2-party threshold signing

**Phase:** Core Protocol
**Effort:** 2–3 days

- [ ] Implement `SigningSession` (wraps `MpcSession`) with:
  - `start(device_share: &DeviceShare, tx_hash: [u8; 32]) -> Result<(SigningSession, RoundPayload), MpcError>`
  - `advance(server_payload: RoundPayload) -> Result<SigningRoundResult, MpcError>`
    where `SigningRoundResult::Complete { signature: [u8; 65] }` holds the
    compact ECDSA signature (r || s || v, 65 bytes, EVM convention)
- [ ] Verify the produced signature recovers to the wallet address from DKG
      (use `k256::ecdsa::recoverable::Signature` or equivalent)
- [ ] Return a distinct `MpcError::NetworkRoundFailed` (not a generic error)
      when a round payload from the server is malformed or the session ID is
      unknown — callers use this to distinguish a retry-safe protocol failure
      from a data-corruption problem
- [ ] Unit tests: sign a known 32-byte hash using shares produced by Task 03's
      DKG; verify signature is valid against the DKG-derived address; verify
      that a device share from a different DKG session cannot complete signing

---

### Task 05 — Resharing (device-loss recovery)

**Phase:** Core Protocol
**Effort:** 2 days

- [ ] Implement `ReshareSession` (wraps `MpcSession`) with:
  - `start() -> Result<(ReshareSession, RoundPayload), MpcError>` — device
    side initiates the resharing ceremony (server authorises this via Google
    ID token, handled on the server side)
  - `advance(server_payload: RoundPayload) -> Result<ReshareRoundResult, MpcError>`
    where `ReshareRoundResult::Complete { new_device_share: DeviceShare }`
- [ ] Verify that:
  1. The new device share, combined with the (unchanged) server share,
     produces valid signatures over the same address as before resharing
  2. The old device share, combined with the server share, fails to produce
     a valid signing session after resharing completes (server-side
     invalidation is enforced server-side; this test simulates the server
     rejecting the old session)
- [ ] Unit tests: full reshare lifecycle; sign with new share, verify
      address unchanged; confirm old share is unusable post-reshare

---

### Task 06 — Flutter bridge exposure (`crates/flutter_bridge`)

**Phase:** Bridge
**Effort:** 2 days

- [ ] Add `crates/mpc-tss` as a dependency to `crates/flutter_bridge/Cargo.toml`
- [ ] Create `crates/flutter_bridge/src/mpc.rs` with `#[frb]`-annotated OOP types:
  - `MpcDkgSession` — wraps `DkgSession`; exposes:
    - `static create() -> Result<MpcDkgSession>`
    - `first_round_payload(&self) -> Vec<u8>`
    - `advance(server_payload: Vec<u8>) -> Result<MpcDkgAdvanceResult>`
    - `MpcDkgAdvanceResult { is_complete: bool, next_payload: Option<Vec<u8>>, device_share: Option<Vec<u8>>, wallet_address: Option<String> }`
  - `MpcSigningSession` — wraps `SigningSession`; exposes:
    - `static create(device_share: Vec<u8>, tx_hash: Vec<u8>) -> Result<MpcSigningSession>`
    - `first_round_payload(&self) -> Vec<u8>`
    - `advance(server_payload: Vec<u8>) -> Result<MpcSigningAdvanceResult>`
    - `MpcSigningAdvanceResult { is_complete: bool, next_payload: Option<Vec<u8>>, signature: Option<Vec<u8>> }`
  - `MpcReshareSession` — wraps `ReshareSession`; exposes:
    - `static create() -> Result<MpcReshareSession>`
    - `first_round_payload(&self) -> Vec<u8>`
    - `advance(server_payload: Vec<u8>) -> Result<MpcReshareAdvanceResult>`
    - `MpcReshareAdvanceResult { is_complete: bool, next_payload: Option<Vec<u8>>, new_device_share: Option<Vec<u8>> }`
- [ ] Re-export new types from `bridge.rs` consistent with the existing
      `Mnemonic`, `Bip44Wallet`, `EvmSigner` export pattern
- [ ] Run `flutter_rust_bridge_codegen` and confirm generated Dart bindings
      compile without errors
- [ ] Integration test in `crates/flutter_bridge` exercising the full
      DKG → Sign → Reshare → Sign-with-new-share lifecycle using a
      local loopback transport (no live server required)

---

### Task 07 — Security audit pass & zeroization

**Phase:** Security
**Effort:** 1 day

- [ ] Audit every code path for accidental key reconstruction: confirm no
      code path concatenates, XORs, or otherwise combines both shares into
      a usable full private key (grep for obvious patterns; annotate in code
      where shares are in scope together)
- [ ] Apply `Zeroize` / `ZeroizeOnDrop` to all in-memory types that hold
      share bytes, DKG intermediate state, signing-round state, and derived
      keys; verify via `cargo test` that drop behaviour zeroes the memory
- [ ] Confirm zero log output at `tracing::debug`, `tracing::info`,
      `tracing::warn`, and `tracing::error` levels for any value that contains
      or is derived from share bytes; add a lint comment where a log
      statement is intentionally near sensitive data
- [ ] Run `cargo clippy -- -D warnings` and `cargo fmt --check` with zero
      violations

---

### Task 08 — Documentation & examples

**Phase:** Polish
**Effort:** 0.5 day

- [ ] Add `crates/mpc-tss/README.md` covering: what the crate does, which
      TSS protocol is used and why, the 2-party DKG/sign/reshare API surface,
      security properties (no key reconstruction, zeroize on drop), and a
      minimal code example showing the round-trip for DKG and signing
- [ ] Add doc-comments (`///`) to all public types and their methods
- [ ] Add `crates/mpc-tss` to the workspace-level `LIBRARY_ORGANIZATION.md`
      alongside the existing crate descriptions
- [ ] Update `FLUTTER_API_SUMMARY.md` with the new `MpcDkgSession`,
      `MpcSigningSession`, and `MpcReshareSession` Dart types and their
      method signatures

---

## Dependencies

| Dependency | Notes |
|---|---|
| `taurushq-io/multi-party-sig` (or equivalent) | Candidate Rust TSS library; pinned exact version |
| `k256` | secp256k1 operations, signature verification |
| `zeroize` | Memory zeroing for all sensitive types |
| `serde` + `serde_json` | Share serialization |
| `uuid` | Session ID generation |
| `thiserror` | Error types |
| Existing `khodpay-signing` `Address` type | Reuse or align EVM address format |
| `flutter_rust_bridge` codegen | Existing setup, no new tooling needed |

---

## Out of Scope

- UI / BLoC / navigation (owned by `US-004.2` and `US-001.13`)
- The signer server itself (owned by `khodpay_backend` story)
- Google Sign-In token acquisition (UI concern, owned by `US-004.2`)
- Apple Sign-In as a parallel recovery factor (deferred)
- Multi-chain / ed25519 / Schnorr support (secp256k1/EVM only for v1)
- 3-of-5 server-side threshold topology (v2 item)
- Migrating existing BIP39 wallets to MPC

---

## Open Questions

1. **CGGMP21 vs DKLS19** — which protocol for the 2-party secp256k1
   implementation? Both are supported by `taurushq-io/multi-party-sig`. DKLS19
   is used by MetaMask Embedded Wallets and has a broader reference
   implementation set; CGGMP21 is newer with stronger security proofs.
   Needs a decision before Task 03.
2. **Address type reuse** — should `crates/mpc-tss` depend on
   `khodpay-signing`'s `Address` type, or define its own? Avoiding a
   circular dep is the constraint.
3. **Transport abstraction** — the `advance()` functions take/return
   `Vec<u8>` (opaque round payloads). The actual gRPC transport to the
   server is the Flutter/use-case layer's responsibility, but we should
   confirm the bridge API surface maps cleanly to the gRPC wire format
   before finalising Task 06.

---

## Estimation

| Task | Effort |
|---|---|
| Task 01 — Crate scaffold & error types | 1 day |
| Task 02 — Session state machine | 1 day |
| Task 03 — 2-party DKG | 3–4 days |
| Task 04 — 2-party threshold signing | 2–3 days |
| Task 05 — Resharing | 2 days |
| Task 06 — Flutter bridge exposure | 2 days |
| Task 07 — Security audit & zeroization | 1 day |
| Task 08 — Documentation & examples | 0.5 day |
| **Total** | **12.5–14.5 days** |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-06 | Initial draft — khodpay-wallet scope of US-004.1 |
