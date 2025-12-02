# khodpay-signing

EVM transaction signing for BSC and other EVM-compatible chains.

## Features

- **EIP-1559 Transactions**: Full support for Type 2 transactions with priority fees
- **BIP-44 Integration**: Sign transactions using keys derived from HD wallets
- **BSC Support**: Built-in chain IDs for BSC Mainnet (56) and Testnet (97)
- **Security**: Automatic zeroization of sensitive key material
- **Type Safety**: Strong types for `Address`, `Wei`, `ChainId`, and `Signature`

## Quick Start

```rust
use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Purpose, Wallet};
use khodpay_signing::{
    Address, Bip44Signer, ChainId, Eip1559Transaction, 
    SignedTransaction, Wei, TRANSFER_GAS,
};

// 1. Create wallet from mnemonic
let mut wallet = Wallet::from_english_mnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "",
    Network::BitcoinMainnet,
).unwrap();

// 2. Get Ethereum account (CoinType 60 for EVM chains)
let account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0).unwrap();

// 3. Create signer
let signer = Bip44Signer::new(&account, 0).unwrap();
println!("Address: {}", signer.address());

// 4. Build transaction
let recipient: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap();

let tx = Eip1559Transaction::builder()
    .chain_id(ChainId::BscMainnet)
    .nonce(0)
    .max_priority_fee_per_gas(Wei::from_gwei(1))
    .max_fee_per_gas(Wei::from_gwei(5))
    .gas_limit(TRANSFER_GAS)
    .to(recipient)
    .value(Wei::from_ether(1))
    .build()
    .unwrap();

// 5. Sign transaction
let signature = signer.sign_transaction(&tx).unwrap();
let signed_tx = SignedTransaction::new(tx, signature);

// 6. Get raw transaction for broadcast
let raw_tx = signed_tx.to_raw_transaction();
println!("Raw TX: {}", raw_tx);
println!("TX Hash: {}", signed_tx.tx_hash_hex());
```

## Types

### `ChainId`

Network identifier for replay protection:

```rust
use khodpay_signing::ChainId;

let mainnet = ChainId::BscMainnet;  // 56
let testnet = ChainId::BscTestnet;  // 97
let custom = ChainId::Custom(1);    // Ethereum mainnet
```

### `Address`

20-byte EVM address with EIP-55 checksum:

```rust
use khodpay_signing::Address;

// Parse from hex
let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap();

// Display with checksum
println!("{}", addr);  // 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
```

### `Wei`

256-bit unsigned integer for Ether/BNB amounts:

```rust
use khodpay_signing::Wei;

let one_ether = Wei::from_ether(1);
let one_gwei = Wei::from_gwei(1);
let one_wei = Wei::from_wei(1u64);

// Arithmetic
let total = one_ether + one_gwei;
```

### `Eip1559Transaction`

EIP-1559 (Type 2) transaction with builder pattern:

```rust
use khodpay_signing::{Eip1559Transaction, ChainId, Wei, TRANSFER_GAS};

let tx = Eip1559Transaction::builder()
    .chain_id(ChainId::BscMainnet)
    .nonce(0)
    .max_priority_fee_per_gas(Wei::from_gwei(1))  // Tip
    .max_fee_per_gas(Wei::from_gwei(5))           // Max total fee
    .gas_limit(TRANSFER_GAS)                       // 21,000 for transfers
    .to("0x...".parse().unwrap())
    .value(Wei::from_ether(1))
    .data(vec![])                                  // Optional calldata
    .build()
    .unwrap();
```

### `Bip44Signer`

Signs transactions using BIP-44 derived keys:

```rust
use khodpay_signing::Bip44Signer;

// From BIP-44 account
let signer = Bip44Signer::new(&account, 0).unwrap();

// Or from raw private key (for testing)
let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();

let address = signer.address();
let signature = signer.sign_transaction(&tx).unwrap();
```

### `SignedTransaction`

Signed transaction ready for broadcast:

```rust
use khodpay_signing::SignedTransaction;

let signed = SignedTransaction::new(tx, signature);

// For eth_sendRawTransaction
let raw = signed.to_raw_transaction();  // "0x02f86c..."

// Transaction hash
let hash = signed.tx_hash_hex();  // "0x..."
```

## Gas Constants

```rust
use khodpay_signing::{TRANSFER_GAS, TOKEN_TRANSFER_GAS};

// Standard ETH/BNB transfer
assert_eq!(TRANSFER_GAS, 21_000);

// Typical BEP-20/ERC-20 token transfer
assert_eq!(TOKEN_TRANSFER_GAS, 65_000);
```

## Security

- Private keys are wrapped in `Zeroizing` to ensure they're cleared from memory
- `Signature` implements `Zeroize` to clear `r`, `s`, `v` when dropped
- The underlying `k256::SigningKey` also implements `Zeroize`

## Optional Features

### `serde`

Enable serialization support:

```toml
[dependencies]
khodpay-signing = { version = "0.1", features = ["serde"] }
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.
