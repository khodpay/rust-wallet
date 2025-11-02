# khodpay-bip44

[![Crates.io](https://img.shields.io/crates/v/khodpay-bip44.svg)](https://crates.io/crates/khodpay-bip44)
[![Documentation](https://docs.rs/khodpay-bip44/badge.svg)](https://docs.rs/khodpay-bip44)
[![License](https://img.shields.io/crates/l/khodpay-bip44.svg)](https://github.com/khodpay/rust-wallet)

Production-ready Rust implementation of [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) (Multi-Account Hierarchy for Deterministic Wallets).

## Features

- ✅ **Multi-Account Support** - Manage multiple accounts per cryptocurrency
- ✅ **Multi-Coin Support** - Bitcoin, Ethereum, Litecoin, Dogecoin, and more
- ✅ **BIP Standards** - Support for BIP-44, BIP-49, BIP-84, and BIP-86
- ✅ **Account Caching** - Efficient account derivation with built-in caching
- ✅ **Builder Pattern** - Fluent API for wallet construction
- ✅ **Type Safety** - Strong typing for paths, chains, and coin types
- ✅ **Serialization** - Optional serde support for persistence
- ✅ **No Unsafe Code** - 100% safe Rust
- ✅ **Comprehensive Tests** - 400+ tests including integration and edge cases

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
khodpay-bip44 = "0.1.0"
khodpay-bip32 = "0.2.0"
khodpay-bip39 = "0.2.0"
```

For serialization support:

```toml
[dependencies]
khodpay-bip44 = { version = "0.1.0", features = ["serde"] }
```

## Quick Start

```rust
use khodpay_bip44::{Wallet, Purpose, CoinType, Language};
use khodpay_bip32::Network;

// Create a wallet from a mnemonic
let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mut wallet = Wallet::from_mnemonic(
    mnemonic,
    "",  // password (optional)
    Language::English,
    Network::BitcoinMainnet,
)?;

// Get the first Bitcoin account
let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;

// Derive receiving addresses
let addr0 = account.derive_external(0)?;  // m/44'/0'/0'/0/0
let addr1 = account.derive_external(1)?;  // m/44'/0'/0'/0/1

// Derive change addresses
let change0 = account.derive_internal(0)?;  // m/44'/0'/0'/1/0
```

## BIP-44 Path Structure

BIP-44 defines a logical hierarchy for deterministic wallets:

```
m / purpose' / coin_type' / account' / change / address_index
```

### Path Levels

| Level | Hardened | Description | Example |
|-------|----------|-------------|---------|
| **purpose** | Yes (') | BIP standard (44, 49, 84, 86) | 44' |
| **coin_type** | Yes (') | Cryptocurrency type (SLIP-44) | 0' (Bitcoin) |
| **account** | Yes (') | Account index | 0' |
| **change** | No | 0=external (receiving), 1=internal (change) | 0 |
| **address_index** | No | Address index within chain | 0 |

### Example Paths

- **Bitcoin receiving**: `m/44'/0'/0'/0/0`
- **Bitcoin change**: `m/44'/0'/0'/1/0`
- **Ethereum receiving**: `m/44'/60'/0'/0/0`
- **Bitcoin SegWit**: `m/84'/0'/0'/0/0`
- **Bitcoin Taproot**: `m/86'/0'/0'/0/0`

## Usage Examples

### Multi-Coin Wallet

```rust
use khodpay_bip44::{Wallet, Purpose, CoinType};

let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet)?;

// Bitcoin account
let btc = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
let btc_addr = btc.derive_external(0)?;

// Ethereum account
let eth = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0)?;
let eth_addr = eth.derive_external(0)?;

// Litecoin account
let ltc = wallet.get_account(Purpose::BIP44, CoinType::Litecoin, 0)?;
let ltc_addr = ltc.derive_external(0)?;
```

### Builder Pattern

```rust
use khodpay_bip44::WalletBuilder;

let mut wallet = WalletBuilder::new()
    .mnemonic("your mnemonic phrase here")
    .password("optional-password")
    .language(Language::English)
    .network(Network::BitcoinMainnet)
    .build()?;
```

### Batch Address Generation

```rust
use khodpay_bip44::Chain;

let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;

// Generate 20 receiving addresses at once
let addresses = account.derive_address_range(Chain::External, 0, 20)?;

// Generate 10 change addresses
let change_addresses = account.derive_address_range(Chain::Internal, 0, 10)?;
```

### Path String Parsing

```rust
use khodpay_bip44::Bip44Path;

// Parse a BIP-44 path
let path: Bip44Path = "m/44'/0'/0'/0/0".parse()?;

// Access path components
println!("Purpose: {}", path.purpose().value());
println!("Coin: {}", path.coin_type().index());
println!("Account: {}", path.account());
println!("Chain: {:?}", path.chain());
println!("Index: {}", path.address_index());

// Convert back to string
assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
```

### SegWit and Taproot

```rust
// BIP-84: Native SegWit (bc1q... addresses)
let segwit = wallet.get_account(Purpose::BIP84, CoinType::Bitcoin, 0)?;
let segwit_addr = segwit.derive_external(0)?;

// BIP-86: Taproot (bc1p... addresses)
let taproot = wallet.get_account(Purpose::BIP86, CoinType::Bitcoin, 0)?;
let taproot_addr = taproot.derive_external(0)?;
```

### Account Caching

```rust
// First access - derives and caches
let account1 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;

// Second access - uses cached account (faster)
let account2 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;

// Check cache size
println!("Cached accounts: {}", wallet.cached_account_count());

// Clear cache if needed
wallet.clear_cache();
```

### Address Iterator

```rust
use khodpay_bip44::AddressIterator;

let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;

// Iterate over addresses
for (i, result) in AddressIterator::new_external(&account).take(10).enumerate() {
    let address = result?;
    println!("Address {}: depth={}", i, address.depth());
}
```

## Supported BIP Standards

| Standard | Purpose | Address Type | Example |
|----------|---------|--------------|---------|
| **BIP-44** | 44' | Legacy P2PKH | 1... |
| **BIP-49** | 49' | SegWit wrapped in P2SH | 3... |
| **BIP-84** | 84' | Native SegWit (Bech32) | bc1q... |
| **BIP-86** | 86' | Taproot (Bech32m) | bc1p... |

## Supported Cryptocurrencies

This crate supports all [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) registered coin types:

| Cryptocurrency | Coin Type | Enum |
|----------------|-----------|------|
| Bitcoin | 0 | `CoinType::Bitcoin` |
| Bitcoin Testnet | 1 | `CoinType::BitcoinTestnet` |
| Litecoin | 2 | `CoinType::Litecoin` |
| Dogecoin | 3 | `CoinType::Dogecoin` |
| Dash | 5 | `CoinType::Dash` |
| Ethereum | 60 | `CoinType::Ethereum` |
| Ethereum Classic | 61 | `CoinType::EthereumClassic` |
| Custom | Any | `CoinType::Custom(u32)` |

## Security Considerations

### ⚠️ Critical Security Guidelines

1. **Mnemonic Storage**
   - ❌ Never store mnemonics in plain text
   - ❌ Never log or print mnemonics
   - ✅ Use secure storage (encrypted keystore, hardware wallet)
   - ✅ Use strong passwords for BIP-39 passphrases

2. **Key Material Handling**
   - ❌ Never expose private keys over network
   - ❌ Never store private keys in databases
   - ✅ Keep keys in secure memory
   - ✅ Clear sensitive data after use

3. **Password Protection**
   - ✅ Use BIP-39 passphrase for additional security
   - ✅ Use strong, unique passwords
   - ✅ Consider using a password manager

4. **Gap Limit**
   - ✅ Follow BIP-44 gap limit (20 addresses)
   - ✅ Stop scanning after 20 consecutive unused addresses
   - ✅ Use `AccountDiscovery` trait for wallet recovery

5. **Network Security**
   - ✅ Use testnet for development
   - ✅ Verify addresses before sending funds
   - ✅ Double-check network parameter

### Best Practices

```rust
// ✅ Good: Use password protection
let wallet = Wallet::from_mnemonic(
    mnemonic,
    "strong-password-here",  // BIP-39 passphrase
    Language::English,
    Network::BitcoinMainnet,
)?;

// ✅ Good: Clear sensitive data
drop(wallet);  // Clears cached accounts

// ✅ Good: Use testnet for development
let test_wallet = Wallet::from_english_mnemonic(
    mnemonic,
    "",
    Network::BitcoinTestnet,  // Use testnet
)?;
```

## Account Discovery

For wallet recovery, use the gap limit to discover used accounts:

```rust
use khodpay_bip44::{AccountDiscovery, GapLimitChecker, DEFAULT_GAP_LIMIT};

// Implement AccountDiscovery trait for your blockchain client
struct MyBlockchain;

impl AccountDiscovery for MyBlockchain {
    fn has_transactions(&self, address: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // Check if address has transactions on blockchain
        Ok(false)  // Implement your logic here
    }
}

// Scan for used addresses
let blockchain = MyBlockchain;
let checker = GapLimitChecker::new(DEFAULT_GAP_LIMIT);

let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
let result = checker.scan_chain(&account, Chain::External, &blockchain)?;

println!("Used addresses: {}", result.used_count);
println!("Last used index: {:?}", result.last_used_index);
```

## Serialization

Enable the `serde` feature for serialization support:

```rust
use khodpay_bip44::{Bip44Path, AccountMetadata};

// Serialize path
let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0)?;
let json = serde_json::to_string(&path)?;

// Deserialize path
let parsed: Bip44Path = serde_json::from_str(&json)?;

// Serialize account metadata (safe - no private keys)
let metadata = AccountMetadata::from_account(&account);
let metadata_json = serde_json::to_string(&metadata)?;
```

## Error Handling

```rust
use khodpay_bip44::Error;

match wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0) {
    Ok(account) => {
        // Use account
    }
    Err(Error::InvalidMnemonic(msg)) => {
        eprintln!("Invalid mnemonic: {}", msg);
    }
    Err(Error::KeyDerivation(msg)) => {
        eprintln!("Key derivation failed: {}", msg);
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

## Testing

Run the test suite:

```bash
# Run all tests
cargo test -p khodpay-bip44

# Run with serde feature
cargo test -p khodpay-bip44 --features serde

# Run doc tests
cargo test -p khodpay-bip44 --doc

# Run integration tests
cargo test -p khodpay-bip44 --test integration
cargo test -p khodpay-bip44 --test test_vectors
cargo test -p khodpay-bip44 --test compatibility
cargo test -p khodpay-bip44 --test edge_cases
```

## Performance

- **Account Caching**: Repeated access to the same account is O(1)
- **Batch Derivation**: More efficient than deriving addresses one by one
- **Zero-Copy**: Path parsing and formatting minimize allocations

## Compatibility

This implementation is compatible with:

- ✅ **Electrum** - Standard BIP-44 paths
- ✅ **Ledger** - Hardware wallet paths
- ✅ **Trezor** - Hardware wallet paths
- ✅ **MetaMask** - Ethereum account derivation
- ✅ **Trust Wallet** - Multi-coin support
- ✅ **Exodus** - Standard BIP-44 implementation

## Examples

See the [examples directory](examples/) for complete working examples:

- `basic.rs` - Basic wallet usage
- `multi_coin.rs` - Multi-cryptocurrency wallet
- `multi_account.rs` - Multiple accounts per coin
- `discovery.rs` - Account discovery with gap limit

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## References

- [BIP-44 Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [BIP-32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [SLIP-44 Coin Types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
- [BIP-49 Specification](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)
- [BIP-84 Specification](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
- [BIP-86 Specification](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
