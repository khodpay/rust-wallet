# BIP44 Integration in Flutter Bridge

This document describes the BIP44 functionality added to the `flutter_bridge` crate.

## Overview

BIP44 (Bitcoin Improvement Proposal 44) support has been integrated into the Flutter bridge, enabling multi-account hierarchical deterministic wallets with support for multiple cryptocurrencies.

## What Was Added

### 1. Dependencies
- Added `khodpay-bip44 = { version = "0.1.0", path = "../bip44" }` to `Cargo.toml`

### 2. New Enums

#### `PurposeType`
Defines the BIP standard to use:
- `BIP44` - Legacy P2PKH addresses
- `BIP49` - SegWit wrapped in P2SH
- `BIP84` - Native SegWit
- `BIP86` - Taproot

#### `CoinType`
Supported cryptocurrencies:
- `Bitcoin`
- `BitcoinTestnet`
- `Litecoin`
- `Dogecoin`
- `Ethereum`
- `Custom(u32)` - For any SLIP-44 registered coin

#### `ChainType`
Address chain types:
- `External` - Receiving addresses (chain 0)
- `Internal` - Change addresses (chain 1)

### 3. Object-Oriented API

#### `Bip44Wallet`
High-level wallet management:
```rust
// Create from mnemonic
let wallet = Bip44Wallet::from_mnemonic(
    mnemonic,
    Some("password"),
    NetworkType::BitcoinMainnet
)?;

// Create from seed
let wallet = Bip44Wallet::from_seed(seed_bytes, NetworkType::BitcoinMainnet)?;

// Get network
let network = wallet.network();

// Get an account
let account = wallet.get_account(
    PurposeType::BIP44,
    CoinType::Bitcoin,
    0  // account index
)?;
```

#### `Bip44Account`
Account-level operations:
```rust
// Derive external (receiving) address
let address = account.derive_external(0)?;

// Derive internal (change) address
let change = account.derive_internal(0)?;

// Derive multiple addresses
let addresses = account.derive_address_range(
    ChainType::External,
    0,   // start index
    20   // count
)?;
```

### 4. Utility Functions

#### `create_bip44_account()`
Create a wallet and derive an account in one call:
```rust
let account_key = create_bip44_account(
    mnemonic,
    Some("password"),
    PurposeType::BIP84,
    CoinType::Bitcoin,
    0,
    NetworkType::BitcoinMainnet
)?;
```

#### `derive_bip44_address()`
Derive an address from an account key:
```rust
let address = derive_bip44_address(
    account_key,
    ChainType::External,
    0  // address index
)?;
```

#### `parse_bip44_path()`
Parse and validate a BIP44 path string:
```rust
let result = parse_bip44_path("m/44'/0'/0'/0/0")?;
```

#### `get_coin_info()`
Get information about a coin type:
```rust
let info = get_coin_info(CoinType::Bitcoin);
// Returns: Name, Symbol, Index
```

#### `get_purpose_info()`
Get information about a purpose:
```rust
let info = get_purpose_info(PurposeType::BIP84);
// Returns: Name, Value, Description
```

## Usage Examples

### Example 1: Create Multi-Coin Wallet
```rust
let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mut wallet = Bip44Wallet::from_mnemonic(
    mnemonic.to_string(),
    None,
    NetworkType::BitcoinMainnet
)?;

// Get Bitcoin account
let btc_account = wallet.get_account(
    PurposeType::BIP84,
    CoinType::Bitcoin,
    0
)?;

// Get Ethereum account
let eth_account = wallet.get_account(
    PurposeType::BIP44,
    CoinType::Ethereum,
    0
)?;
```

### Example 2: Generate Addresses
```rust
// Derive first 20 receiving addresses
let addresses = account.derive_address_range(
    ChainType::External,
    0,
    20
)?;

// Derive first 10 change addresses
let change_addresses = account.derive_address_range(
    ChainType::Internal,
    0,
    10
)?;
```

### Example 3: Different Address Types
```rust
let mut wallet = Bip44Wallet::from_mnemonic(
    mnemonic,
    None,
    NetworkType::BitcoinMainnet
)?;

// Legacy addresses (1...)
let legacy = wallet.get_account(PurposeType::BIP44, CoinType::Bitcoin, 0)?;

// SegWit addresses (3...)
let segwit = wallet.get_account(PurposeType::BIP49, CoinType::Bitcoin, 0)?;

// Native SegWit addresses (bc1q...)
let native_segwit = wallet.get_account(PurposeType::BIP84, CoinType::Bitcoin, 0)?;

// Taproot addresses (bc1p...)
let taproot = wallet.get_account(PurposeType::BIP86, CoinType::Bitcoin, 0)?;
```

## Building

The existing build scripts work without modification:

```bash
# Generate Flutter bindings (requires Flutter project with freezed)
./scripts/generate_bridge.sh

# Build for all platforms
./scripts/build_all.sh

# Build for specific platform
./scripts/build_rust.sh release macos
./scripts/build_rust.sh release ios
./scripts/build_rust.sh release android
```

## Notes

1. **Bridge Generation**: The `generate_bridge.sh` script requires a Flutter project with `freezed` in `dev_dependencies`. If you're only building the Rust library, you can skip this step.

2. **Warnings**: The build may show warnings about `frb_expand` cfg conditions. These are harmless and come from the flutter_rust_bridge macros.

3. **Account Keys**: The `Bip44Account` struct stores the account-level extended private key as a string for easy serialization across the FFI boundary.

4. **Network Compatibility**: Make sure to use the correct network type (mainnet vs testnet) when creating wallets and deriving accounts.

## Integration with Flutter

After building, the generated Dart bindings will include:
- All enum types (`PurposeType`, `CoinType`, `ChainType`)
- Class wrappers (`Bip44Wallet`, `Bip44Account`)
- Utility functions (all `create_*`, `derive_*`, `get_*` functions)

The Flutter/Dart code can then use these APIs naturally with full type safety.
