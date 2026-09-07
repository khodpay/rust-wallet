# KhodPay Signing Integration in Flutter Bridge

This document describes the EVM transaction signing functionality available in the `flutter_bridge` crate via the `khodpay-signing` library.

## Overview

The `khodpay-signing` crate provides secure EVM (Ethereum Virtual Machine) transaction signing capabilities. It supports EIP-1559 transactions (Type 2) used by Ethereum, BSC, Polygon, and other EVM-compatible chains.

## What's Included

### 1. Dependencies
- Added `khodpay-signing = { version = "0.1.0", path = "../khodpay-signing" }` to `Cargo.toml`

### 2. Enums

#### `ChainId`
EVM chain identifiers for transaction signing:
- `BscMainnet` - BSC Mainnet (chain ID 56)
- `BscTestnet` - BSC Testnet (chain ID 97)
- `EthereumMainnet` - Ethereum Mainnet (chain ID 1)
- `Polygon` - Polygon Mainnet (chain ID 137)
- `Arbitrum` - Arbitrum One (chain ID 42161)
- `Optimism` - Optimism (chain ID 10)
- `Avalanche` - Avalanche C-Chain (chain ID 43114)

For custom chain IDs, use the `chainIdToU64()` utility function.

### 3. Object-Oriented API

#### `EvmSigner`
The main signer for EVM transactions:

```rust
// Create from BIP44 account
let signer = EvmSigner::from_account(&account, 0)?;

// Create from private key hex
let signer = EvmSigner::from_private_key_hex("0x...")?;

// Get address
let address = signer.address();
let address_string = signer.address_string();

// Sign a message hash
let signature = signer.sign_hash(&hash_bytes)?;

// Sign a transaction
let signature = signer.sign_transaction(&tx)?;

// Sign and build a complete signed transaction
let signed_tx = signer.sign_and_build(&tx)?;
```

#### `EvmAddress`
EVM address handling with EIP-55 checksum support:

```rust
// Parse from hex string
let address = EvmAddress::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f...")?;

// Create from bytes
let address = EvmAddress::from_bytes(bytes)?;

// Derive from public key
let address = EvmAddress::from_public_key(pubkey_bytes)?;

// Get checksummed string
let checksum_addr = address.to_checksum_string();

// Get lowercase hex
let hex_addr = address.to_hex_string();

// Validate checksum
let is_valid = EvmAddress::validate_checksum("0x742d35Cc...")?;

// Create zero address
let zero = EvmAddress::zero();
```

#### `Eip1559Transaction`
EIP-1559 transaction structure:

```rust
// Create using builder pattern (in Dart, use constructor directly)
let tx = Eip1559Transaction {
    chain_id: ChainId::BscMainnet,
    nonce: 0,
    max_priority_fee_per_gas: "1000000000".to_string(),  // 1 gwei
    max_fee_per_gas: "2000000000".to_string(),           // 2 gwei
    gas_limit: 21000,
    to: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f...".to_string()),
    value: "1000000000000000000".to_string(),            // 1 ETH/BNB
    data_hex: "".to_string(),
};

// Validate transaction
tx.validate()?;

// Check transaction type
let is_transfer = tx.is_transfer();
let is_contract_creation = tx.is_contract_creation();
```

#### `Eip1559TransactionBuilder`
Builder for creating transactions:

```rust
// In Rust
let builder = Eip1559TransactionBuilder::new();
let tx = builder.build()?;

// In Dart, construct directly:
// var builder = Eip1559TransactionBuilder(
//   chainId: ChainId.bscMainnet,
//   nonce: BigInt.from(0),
//   maxPriorityFeePerGas: "1000000000",
//   maxFeePerGas: "2000000000",
//   gasLimit: BigInt.from(21000),
//   to: "0x...",
//   value: "1000000000000000000",
// );
// var tx = await builder.build();
```

#### `EvmSignature`
ECDSA signature with recovery ID:

```rust
// Create from components
let sig = EvmSignature::new(r_hex, s_hex, v)?;

// Create from 65 bytes
let sig = EvmSignature::from_bytes(bytes)?;

// Get components
let r = sig.r_hex;
let s = sig.s_hex;
let v = sig.v;

// Convert to bytes
let bytes = sig.to_bytes();

// Convert to hex string
let hex = sig.to_hex_string();
```

#### `SignedEvmTransaction`
A fully signed transaction ready for broadcast:

```rust
// Create from transaction and signature
let signed = SignedEvmTransaction::new(tx, signature)?;

// Encode for broadcast
let raw_bytes = signed.encode();

// Get raw transaction hex (for eth_sendRawTransaction)
let raw_tx = signed.to_raw_transaction();

// Get transaction hash
let tx_hash = signed.tx_hash();
let tx_hash_hex = signed.tx_hash_hex();
```

#### `EvmWei`
Wei value handling for large numbers:

```rust
// Create from different units
let wei = EvmWei::from_wei_u64(1000000000)?;
let wei = EvmWei::from_wei_string("1000000000000000000")?;
let wei = EvmWei::from_gwei(1)?;    // 1 gwei = 10^9 wei
let wei = EvmWei::from_ether(1)?;   // 1 ether = 10^18 wei

// Convert to different units
let gwei = wei.to_gwei();
let ether = wei.to_ether();
let decimal_string = wei.to_decimal_string();
let u64_value = wei.to_u64();  // Returns None if too large

// Arithmetic
let sum = wei.add(&other_wei)?;
let product = wei.multiply(2)?;

// Check if zero
let is_zero = wei.is_zero();
```

### 4. Utility Functions

#### Chain ID Functions

```rust
// Get numeric value of a chain ID
let value = chain_id_to_u64(ChainId::BscMainnet);  // Returns 56

// Get chain ID value for custom chains
let custom_value = custom_chain_id_value(137);  // Polygon

// Get chain name
let name = get_chain_name(ChainId::BscMainnet);  // "BSC Mainnet"

// Check if testnet
let is_testnet = is_testnet_chain(ChainId::BscTestnet);  // true
```

#### Gas Constants

```rust
// Standard ETH/BNB transfer gas
let transfer_gas = get_transfer_gas();  // 21000

// Token transfer gas (ERC-20/BEP-20)
let token_gas = get_token_transfer_gas();  // 65000
```

#### Wei Conversion

```rust
// Get wei constants
let gwei_in_wei = get_gwei_in_wei();    // 10^9
let ether_in_wei = get_ether_in_wei();  // 10^18

// Convert values
let wei_string = gwei_to_wei(10);   // "10000000000"
let wei_string = ether_to_wei(1);   // "1000000000000000000"
```

#### Address Functions

```rust
// Parse and validate address
let normalized = parse_evm_address("0x742d35Cc...")?;

// Validate checksum
let is_valid = validate_evm_address_checksum("0x742d35Cc...")?;

// Get address from private key
let address = get_evm_address_from_private_key("0xprivatekey...")?;

// Derive address from extended private key
let address = derive_evm_address(xprv, 0, 0)?;
```

#### Signing Functions

```rust
// Create signer from mnemonic (convenience function)
let address = create_evm_signer_from_mnemonic(
    mnemonic,
    Some("passphrase"),
    0,  // account index
    0,  // address index
)?;

// Sign EIP-1559 transaction (convenience function)
let raw_tx = sign_eip1559_transaction(
    private_key_hex,
    ChainId::BscMainnet,
    nonce,
    to_address,
    value_wei,
    gas_limit,
    max_priority_fee_gwei,
    max_fee_gwei,
    Some(data_hex),
)?;

// Recover signer from signature
let signer_address = recover_signer_address(hash_hex, signature_hex)?;
```

## Usage Examples

### Example 1: Create Signer from BIP44 Account

```rust
// Create wallet
let mut wallet = Bip44Wallet::from_mnemonic(
    mnemonic,
    None,
    Network::BitcoinMainnet
)?;

// Get Ethereum account (coin type 60)
let account = wallet.get_account(
    Purpose::Bip44,
    CoinType::Ethereum,
    0
)?;

// Create signer for first address
let signer = EvmSigner::from_account(&account, 0)?;

// Get address
let address = signer.address_string();
println!("Address: {}", address);
```

### Example 2: Sign a Simple Transfer

```rust
// Create signer
let signer = EvmSigner::from_private_key_hex(private_key)?;

// Build transaction
let tx = Eip1559Transaction {
    chain_id: ChainId::BscMainnet,
    nonce: 0,
    max_priority_fee_per_gas: "1000000000".to_string(),  // 1 gwei
    max_fee_per_gas: "5000000000".to_string(),           // 5 gwei
    gas_limit: 21000,
    to: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f...".to_string()),
    value: "100000000000000000".to_string(),             // 0.1 BNB
    data_hex: "".to_string(),
};

// Sign and build
let signed_tx = signer.sign_and_build(&tx)?;

// Get raw transaction for broadcast
let raw_tx = signed_tx.to_raw_transaction();
println!("Raw TX: {}", raw_tx);

// Get transaction hash
let tx_hash = signed_tx.tx_hash_hex();
println!("TX Hash: {}", tx_hash);
```

### Example 3: Sign a Token Transfer (ERC-20/BEP-20)

```rust
// ERC-20 transfer function signature: transfer(address,uint256)
// Function selector: 0xa9059cbb
let recipient = "742d35Cc6634C0532925a3b844Bc9e7595f...";  // without 0x
let amount = "0000000000000000000000000000000000000000000000000de0b6b3a7640000";  // 1 token (18 decimals)
let data = format!("0xa9059cbb000000000000000000000000{}{}", recipient, amount);

let tx = Eip1559Transaction {
    chain_id: ChainId::BscMainnet,
    nonce: 1,
    max_priority_fee_per_gas: "1000000000".to_string(),
    max_fee_per_gas: "5000000000".to_string(),
    gas_limit: 65000,  // Token transfers need more gas
    to: Some("0xTokenContractAddress...".to_string()),
    value: "0".to_string(),  // No BNB sent
    data_hex: data,
};

let signed_tx = signer.sign_and_build(&tx)?;
```

### Example 4: Using Wei for Precise Calculations

```rust
// Calculate total transaction cost
let gas_limit = 21000u64;
let max_fee_per_gas = EvmWei::from_gwei(5)?;
let value = EvmWei::from_ether(1)?;

let max_gas_cost = max_fee_per_gas.multiply(gas_limit)?;
let total_max_cost = value.add(&max_gas_cost)?;

println!("Max total cost: {} wei", total_max_cost.to_decimal_string());
println!("Max total cost: {} gwei", total_max_cost.to_gwei());
```

### Example 5: Validate and Parse Addresses

```rust
// Validate user input
let user_address = "0x742d35Cc6634C0532925a3b844Bc9e7595f...";

if validate_evm_address_checksum(user_address.to_string()) {
    let address = EvmAddress::from_hex(user_address.to_string())?;
    println!("Valid address: {}", address.to_checksum_string());
} else {
    println!("Invalid checksum!");
}
```

## Flutter/Dart Usage

After building and generating bindings:

```dart
import 'package:my_app/rust/bridge.dart';

// Initialize the library
await RustLib.init();

// Create signer from mnemonic
final address = await createEvmSignerFromMnemonic(
  mnemonic: 'abandon abandon abandon...',
  passphrase: null,
  accountIndex: 0,
  addressIndex: 0,
);
print('Address: $address');

// Create wallet and signer
final wallet = await Bip44Wallet.fromMnemonic(
  mnemonic: 'abandon abandon abandon...',
  passphrase: null,
  network: Network.bitcoinMainnet,
);

final account = await wallet.getAccount(
  purpose: Purpose.bip44,
  coinType: CoinType.ethereum,
  accountIndex: 0,
);

final signer = await EvmSigner.fromAccount(
  account: account,
  addressIndex: 0,
);

// Build transaction
final builder = Eip1559TransactionBuilder(
  chainId: ChainId.bscMainnet,
  nonce: BigInt.zero,
  maxPriorityFeePerGas: '1000000000',
  maxFeePerGas: '5000000000',
  gasLimit: BigInt.from(21000),
  to: '0x742d35Cc6634C0532925a3b844Bc9e7595f...',
  value: '100000000000000000',
  dataHex: '',
);

final tx = await builder.build();

// Sign transaction
final signedTx = await signer.signAndBuild(tx: tx);

// Get raw transaction for broadcast
final rawTx = await signedTx.toRawTransaction();
print('Raw TX: $rawTx');

// Get transaction hash
final txHash = await signedTx.txHashHex();
print('TX Hash: $txHash');
```

### Working with Wei in Dart

```dart
// Create Wei values
final weiFromGwei = await EvmWei.fromGwei(gwei: BigInt.from(5));
final weiFromEther = await EvmWei.fromEther(ether: BigInt.one);
final weiFromString = await EvmWei.fromWeiString(weiString: '1000000000000000000');

// Convert Wei
final gweiValue = await weiFromEther.toGwei();
final etherValue = await weiFromEther.toEther();
final decimalString = await weiFromEther.toDecimalString();

// Arithmetic
final sum = await weiFromGwei.add(other: weiFromEther);
final product = await weiFromGwei.multiply(scalar: BigInt.from(2));
```

## Security Considerations

### 🔒 Private Key Security

1. **Never expose private keys**
   - Private key hex strings contain sensitive material
   - Never log, transmit, or store unencrypted
   - Use secure storage mechanisms

2. **Signer lifecycle**
   - Create signers only when needed
   - Don't cache signers longer than necessary
   - Clear references when done

3. **Transaction validation**
   - Always validate transactions before signing
   - Verify recipient addresses
   - Check gas parameters are reasonable

### 🔐 Address Validation

1. **Always validate checksums**
   - Use `validate_evm_address_checksum()` for user input
   - Display addresses with proper checksums

2. **Verify chain IDs**
   - Ensure chain ID matches intended network
   - Prevent cross-chain replay attacks

### ⚠️ Gas Estimation

1. **Use appropriate gas limits**
   - 21000 for simple transfers
   - 65000+ for token transfers
   - Estimate for complex contracts

2. **Set reasonable fee caps**
   - Check current network conditions
   - Set `maxFeePerGas` to acceptable maximum
   - `maxPriorityFeePerGas` is the tip to validators

## Error Handling

```rust
// Rust
match signer.sign_and_build(&tx) {
    Ok(signed_tx) => {
        let raw = signed_tx.to_raw_transaction();
        println!("Success: {}", raw);
    }
    Err(e) => {
        println!("Signing failed: {}", e);
    }
}
```

```dart
// Dart
try {
  final signedTx = await signer.signAndBuild(tx: tx);
  final rawTx = await signedTx.toRawTransaction();
  print('Success: $rawTx');
} catch (e) {
  print('Signing failed: $e');
}
```

## Standards Compliance

This implementation follows:
- **EIP-1559**: Fee market change for ETH 1.0 chain
- **EIP-155**: Simple replay attack protection
- **EIP-55**: Mixed-case checksum address encoding
- **EIP-2718**: Typed transaction envelope
- **EIP-2930**: Access list transaction type
- **Secp256k1**: ECDSA signing curve
- **Keccak-256**: Hashing algorithm

## Related Documentation

- [BIP32_INTEGRATION.md](./BIP32_INTEGRATION.md) - HD key derivation
- [BIP39_INTEGRATION.md](./BIP39_INTEGRATION.md) - Mnemonic generation
- [BIP44_INTEGRATION.md](./BIP44_INTEGRATION.md) - Multi-account hierarchy
- [FLUTTER_INTEGRATION_GUIDE.md](./FLUTTER_INTEGRATION_GUIDE.md) - Complete Flutter setup
- [EIP-1559 Specification](https://eips.ethereum.org/EIPS/eip-1559)
- [EIP-155 Specification](https://eips.ethereum.org/EIPS/eip-155)
