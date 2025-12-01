# 📋 Khodpay-Signing Library Implementation Task List

This crate provides EVM transaction signing for BSC (BNB Smart Chain) using EIP-1559 (Type 2) transactions. Integrates with `khodpay-bip44` for key derivation.

---

## 🚀 PHASE 1: Foundation & Core Types (HIGH Priority)

- [x] **Task 01**: Create crate structure, Cargo.toml, and Error types
  - Create `crates/khodpay-signing` directory
  - Add dependencies: `khodpay-bip32`, `khodpay-bip44`, `thiserror`, `rlp`, `k256`, `sha3`, `primitive-types`
  - Define `Error` enum: `InvalidChainId`, `InvalidAddress`, `InvalidGas`, `SigningError`, `RlpEncodingError`, `Bip44Error`

- [ ] **Task 02**: Define ChainId enum with BSC support (TDD)
  ```rust
  pub enum ChainId {
      BscMainnet,      // 56
      BscTestnet,      // 97
      Custom(u64),
  }
  ```
  > **Note**: `ChainId` ≠ `CoinType`. CoinType (60) → derivation path. ChainId (56) → transaction.

- [ ] **Task 03**: Define Address and Wei types (TDD)
  - `Address`: 20-byte EVM address with hex parsing, EIP-55 checksum, derivation from public key
  - `Wei`: U256 wrapper with `from_gwei()`, `from_ether()` helpers

---

## 📝 PHASE 2: Transaction Structure (HIGH Priority)

- [ ] **Task 04**: Define Eip1559Transaction and builder (TDD)
  ```rust
  pub struct Eip1559Transaction {
      chain_id: ChainId,
      nonce: u64,
      max_priority_fee_per_gas: Wei,
      max_fee_per_gas: Wei,
      gas_limit: u64,
      to: Option<Address>,
      value: Wei,
      data: Vec<u8>,
      access_list: Vec<AccessListItem>,
  }
  ```

- [ ] **Task 05**: Implement RLP encoding for unsigned transaction (TDD)
  - Encode: `0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list])`
  - Implement `signing_hash()`: `keccak256(encoded)`

---

## ✍️ PHASE 3: Signing (HIGH Priority)

- [ ] **Task 06**: Define Signature struct and Bip44Signer (TDD)
  - `Signature { r, s, v }` for ECDSA signature
  - `Bip44Signer` wrapping `khodpay_bip44::Account`
  - Implement `sign()` and `address()` methods

- [ ] **Task 07**: Implement SignedTransaction and raw output (TDD)
  - RLP encode signed tx with signature
  - `to_raw_transaction()` → hex string
  - `tx_hash()` → `keccak256(raw_bytes)`

---

## 🔗 PHASE 4: BSC Helpers & BEP-20 (MEDIUM Priority)

- [ ] **Task 08**: Add BSC defaults and BEP-20 transfer encoding (TDD)
  - Gas constants: `TRANSFER_GAS`, `BEP20_TRANSFER_GAS`
  - `bep20_transfer_data(recipient, amount)` → encoded calldata

---

## 🧪 PHASE 5: Integration & Validation (MEDIUM Priority)

- [ ] **Task 09**: Integration tests and validation rules
  - Full workflow: mnemonic → bip44 → sign BSC transaction
  - Validation: `max_fee >= max_priority_fee`, `gas_limit >= 21000`

- [ ] **Task 10**: Security: zeroize sensitive data

---

## 🎯 PHASE 6: Documentation & Polish (LOW Priority)

- [ ] **Task 11**: Documentation, examples, and final polish
  - README.md, examples, serde feature, clippy/fmt

---

## 📊 Task Summary
**Total Tasks:** 11  
**Phases:** 6  
**Methodology:** Test-Driven Development (TDD)

---

## 🔍 Key Implementation Notes

### EIP-1559 Transaction Structure (Type 2)
```
0x02 || rlp([
    chain_id,
    nonce,
    max_priority_fee_per_gas,
    max_fee_per_gas,
    gas_limit,
    to,
    value,
    data,
    access_list,
    signature_y_parity,  // v (0 or 1)
    signature_r,
    signature_s
])
```

### BSC Chain IDs
- **BSC Mainnet:** 56
- **BSC Testnet:** 97

### BIP-44 Path for BSC/Ethereum
```
m/44'/60'/0'/0/0  - First address
m/44'/60'/0'/0/1  - Second address
```
Note: BSC uses Ethereum's coin type (60) as it's EVM-compatible.

### Gas Defaults for BSC
- **Standard Transfer:** 21,000 gas
- **BEP-20 Transfer:** ~65,000 gas
- **Priority Fee:** 1-3 gwei (BSC is generally low-fee)
- **Max Fee:** 5-10 gwei typical

### Signing Process
1. Build unsigned transaction
2. RLP encode with type prefix: `0x02 || rlp(unsigned_fields)`
3. Hash: `keccak256(encoded)`
4. Sign hash with secp256k1 ECDSA
5. Encode signed transaction: `0x02 || rlp(all_fields + signature)`

---

## 🔗 Dependencies

### Internal
- `khodpay-bip32` - Key derivation
- `khodpay-bip44` - Account management, address generation

### External
```toml
[dependencies]
thiserror = "1.0"
rlp = "0.5"
k256 = { version = "0.13", features = ["ecdsa"] }
sha3 = "0.10"
primitive-types = { version = "0.12", features = ["rlp"] }  # U256
zeroize = { version = "1.7", features = ["derive"] }

[dependencies.serde]
version = "1.0"
optional = true
features = ["derive"]

[features]
default = []
serde = ["dep:serde"]
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│   Eip1559Transaction + SignedTransaction │
├─────────────────────────────────────────┤
│   Bip44Signer (uses khodpay-bip44)       │
├─────────────────────────────────────────┤
│   Core: Address, Wei, ChainId, Signature │
├─────────────────────────────────────────┤
│   RLP Encoding + Keccak-256              │
└─────────────────────────────────────────┘
```

---

## 🚀 Future Extensions (Out of Scope)

These are noted for future planning but NOT part of this implementation:

1. **Legacy Transactions (Type 0)** - Pre-EIP-1559
2. **EIP-2930 Transactions (Type 1)** - Access list only
3. **Other EVM Chains** - Ethereum, Polygon, Arbitrum, Avalanche
4. **Contract Deployment** - `to: None` transactions
5. **Hardware Wallet Integration** - Ledger, Trezor signers
6. **Gas Estimation RPC** - `eth_estimateGas` integration
7. **Nonce Management** - `eth_getTransactionCount` integration

---

**Note:** This implementation focuses on EIP-1559 (Type 2) transactions for BSC. The architecture is designed to easily extend to other EVM chains and transaction types in the future. The crate integrates with `khodpay-bip44` for key management, allowing seamless wallet → signing workflows.
