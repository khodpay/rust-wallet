# khodpay-signing

EVM signing library for BSC and other EVM-compatible chains.

Provides **EIP-1559** transaction signing, **EIP-712** typed structured data signing, and
**ERC-4337 v0.7** `PackedUserOperation` support — all built on BIP-44 HD wallet key derivation.

## Features

- **EIP-1559 Transactions**: Type-2 transactions for EOA wallets
- **EIP-712 Typed Data**: Generic, protocol-agnostic structured data signing (any struct)
- **ERC-4337 Account Abstraction**: `PackedUserOperation` v0.7 — build, hash, sign, verify
- **BIP-44 Integration**: Sign using keys derived from HD wallets
- **BSC Support**: Built-in chain IDs for BSC Mainnet (56) and Testnet (97)
- **Security**: Automatic zeroization of sensitive key material
- **Type Safety**: Strong types for `Address`, `Wei`, `ChainId`, and `Signature`

## Quick Start — EIP-1559 (EOA Wallet)

```rust
use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Purpose, Wallet};
use khodpay_signing::{
    Address, Bip44Signer, ChainId, Eip1559Transaction,
    SignedTransaction, Wei, TRANSFER_GAS,
};

let mut wallet = Wallet::from_english_mnemonic(
    "abandon abandon ...",
    "",
    Network::BitcoinMainnet,
).unwrap();
let account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0).unwrap();
let signer = Bip44Signer::new(account, 0).unwrap();

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

let signature = signer.sign_transaction(&tx).unwrap();
let signed_tx = SignedTransaction::new(tx, signature);
println!("Raw TX: {}", signed_tx.to_raw_transaction()); // "0x02..."
println!("TX Hash: {}", signed_tx.tx_hash_hex());
```

## Quick Start — EIP-712 Typed Data

Implement `Eip712Type` for any struct to get standards-compliant typed data signing:

```rust
use khodpay_signing::eip712::{
    Eip712Domain, Eip712Type, encode_address, encode_uint64,
    sign_typed_data, verify_typed_data,
};
use khodpay_signing::Address;

struct PaymentIntent {
    business: Address,
    amount: u64,
    nonce: u64,
}

impl Eip712Type for PaymentIntent {
    fn type_string() -> &'static str {
        "PaymentIntent(address business,uint64 amount,uint64 nonce)"
    }
    fn encode_data(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_address(&self.business));
        buf.extend_from_slice(&encode_uint64(self.amount));
        buf.extend_from_slice(&encode_uint64(self.nonce));
        buf
    }
}

let gateway: Address = "0x1111111111111111111111111111111111111111".parse().unwrap();
let domain = Eip712Domain::new("MyApp", "1", 56, gateway);

let intent = PaymentIntent { business: signer.address(), amount: 1_000_000, nonce: 0 };
let sig = sign_typed_data(&signer, &domain, &intent).unwrap();
let valid = verify_typed_data(&domain, &intent, &sig, signer.address()).unwrap();
assert!(valid);
```

## Quick Start — ERC-4337 Smart Wallet (Gasless)

```rust
use khodpay_signing::erc4337::{
    PackedUserOperation, sign_user_operation, verify_user_operation, ENTRY_POINT_V07,
};
use khodpay_signing::Address;

let entry_point: Address = ENTRY_POINT_V07.parse().unwrap();

let user_op = PackedUserOperation::builder()
    .sender(smart_account_address)
    .nonce(0)
    .call_data(encoded_calldata)           // any contract call
    .account_gas_limits(150_000, 300_000)  // verificationGas, callGas
    .pre_verification_gas(50_000)
    .gas_fees(1_000_000_000, 5_000_000_000) // maxPriorityFee, maxFee (wei)
    .paymaster(paymaster_address, vec![])
    .build()
    .unwrap();

let sig = sign_user_operation(&signer, &user_op, entry_point, 56).unwrap();

let mut signed_op = user_op;
signed_op.signature = sig.to_bytes().to_vec(); // submit to bundler
```

## Types

### `ChainId`

```rust
use khodpay_signing::ChainId;

let mainnet = ChainId::BscMainnet;  // 56
let testnet = ChainId::BscTestnet;  // 97
let custom  = ChainId::Custom(1);   // Ethereum mainnet
```

### `Address`

20-byte EVM address with EIP-55 checksum:

```rust
use khodpay_signing::Address;

let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap();
println!("{}", addr); // 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
```

### `Wei`

256-bit unsigned integer for Ether/BNB amounts:

```rust
use khodpay_signing::Wei;

let one_ether = Wei::from_ether(1);
let one_gwei  = Wei::from_gwei(1);
let total     = one_ether + one_gwei;
```

### `Bip44Signer`

```rust
use khodpay_signing::Bip44Signer;

let signer = Bip44Signer::new(account, 0).unwrap();
// or for testing:
let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();

let address   = signer.address();
let signature = signer.sign_transaction(&tx).unwrap();
let sig712    = sign_typed_data(&signer, &domain, &message).unwrap();
let sig4337   = sign_user_operation(&signer, &user_op, entry_point, 56).unwrap();
```

## Gas Constants

```rust
use khodpay_signing::{TRANSFER_GAS, TOKEN_TRANSFER_GAS};

assert_eq!(TRANSFER_GAS, 21_000);       // Standard ETH/BNB transfer
assert_eq!(TOKEN_TRANSFER_GAS, 65_000); // Typical BEP-20/ERC-20 transfer
```

## EIP-712 Encoding Helpers

Available inside `Eip712Type::encode_data()` implementations:

| Helper | Solidity type |
|---|---|
| `encode_address(&addr)` | `address` |
| `encode_uint64(n)` | `uint64` |
| `encode_u256_bytes(&bytes)` | `uint256` |
| `encode_bool(b)` | `bool` |
| `encode_bytes32(bytes)` | `bytes32` |
| `encode_bytes_dynamic(&bytes)` | `bytes` / `string` |

## Optional Features

| Feature | Enables |
|---|---|
| `serde` | Serialization for core types |
| `eip712` | `eip712` module (implies `serde`) |
| `erc4337` | `erc4337` module (implies `eip712`) |

```toml
[dependencies]
khodpay-signing = { version = "0.2", features = ["erc4337"] }
```

## Security

- Private keys are wrapped in `Zeroizing` — cleared from memory on drop
- `Signature` implements `Zeroize` to clear `r`, `s`, `v`
- The underlying `k256::SigningKey` also implements `Zeroize`
- Zero unsafe code

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.
