//! # Khodpay Signing
//!
//! EVM transaction signing library for BSC (BNB Smart Chain) and other EVM-compatible chains.
//!
//! This crate provides EIP-1559 transaction signing, EIP-712 typed data signing, and
//! ERC-4337 (Account Abstraction) `PackedUserOperation` support — all integrating with
//! `khodpay-bip44` for HD wallet key derivation.
//!
//! ## Modules
//!
//! | Module | Standard | Description |
//! |---|---|---|
//! | *(root)* | EIP-1559 | Type-2 transaction building and signing |
//! | [`eip712`] | EIP-712 | Generic typed structured data signing |
//! | [`erc4337`] | ERC-4337 v0.7 | `PackedUserOperation` build / hash / sign |
//!
//! ## Features
//!
//! - **EIP-1559 Transactions**: Modern fee market transactions for EOA wallets
//! - **EIP-712 Typed Data**: Generic, protocol-agnostic structured data signing
//! - **ERC-4337 Account Abstraction**: `PackedUserOperation` v0.7 for gasless smart wallets
//! - **BSC Support**: Native support for BNB Smart Chain (mainnet/testnet)
//! - **BIP-44 Integration**: Seamless key derivation from HD wallets
//! - **BEP-20 Helpers**: Token transfer encoding utilities
//!
//! ## Quick Start — EIP-1559 (EOA Wallet)
//!
//! ```rust,ignore
//! use khodpay_signing::{Eip1559Transaction, ChainId, Wei, Bip44Signer};
//! use khodpay_bip44::{Wallet, Purpose, CoinType};
//! use khodpay_bip32::Network;
//!
//! let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet)?;
//! let account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0)?;
//! let signer = Bip44Signer::new(account, 0)?;
//!
//! let tx = Eip1559Transaction::builder()
//!     .chain_id(ChainId::BscMainnet)
//!     .nonce(0)
//!     .to("0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse()?)
//!     .value(Wei::from_ether(1))
//!     .gas_limit(21_000)
//!     .max_fee_per_gas(Wei::from_gwei(5))
//!     .max_priority_fee_per_gas(Wei::from_gwei(1))
//!     .build()?;
//!
//! let signature = signer.sign_transaction(&tx)?;
//! let signed_tx = khodpay_signing::SignedTransaction::new(tx, signature);
//! let raw_tx = signed_tx.to_raw_transaction(); // "0x02..."
//! ```
//!
//! ## Quick Start — EIP-712 Typed Data
//!
//! ```rust,ignore
//! use khodpay_signing::eip712::{
//!     Eip712Domain, Eip712Type, encode_address, encode_uint64, sign_typed_data,
//! };
//!
//! struct PaymentIntent { business: Address, amount: u64, nonce: u64 }
//!
//! impl Eip712Type for PaymentIntent {
//!     fn type_string() -> &'static str {
//!         "PaymentIntent(address business,uint64 amount,uint64 nonce)"
//!     }
//!     fn encode_data(&self) -> Vec<u8> {
//!         let mut buf = Vec::new();
//!         buf.extend_from_slice(&encode_address(&self.business));
//!         buf.extend_from_slice(&encode_uint64(self.amount));
//!         buf.extend_from_slice(&encode_uint64(self.nonce));
//!         buf
//!     }
//! }
//!
//! let domain = Eip712Domain::new("MyApp", "1", 56, gateway_address);
//! let sig = sign_typed_data(&signer, &domain, &intent)?;
//! ```
//!
//! ## Quick Start — ERC-4337 Smart Wallet
//!
//! ```rust,ignore
//! use khodpay_signing::erc4337::{PackedUserOperation, sign_user_operation, ENTRY_POINT_V07};
//!
//! let user_op = PackedUserOperation::builder()
//!     .sender(smart_account_address)
//!     .nonce(0)
//!     .call_data(encoded_calldata)
//!     .account_gas_limits(150_000, 300_000)
//!     .pre_verification_gas(50_000)
//!     .gas_fees(1_000_000_000, 5_000_000_000)
//!     .paymaster(paymaster_address, vec![])
//!     .build()?;
//!
//! let entry_point: Address = ENTRY_POINT_V07.parse().unwrap();
//! let sig = sign_user_operation(&signer, &user_op, entry_point, 56)?;
//! let mut signed_op = user_op;
//! signed_op.signature = sig.to_bytes().to_vec();
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![deny(unsafe_code)]

mod access_list;
mod address;
mod chain_id;
mod error;
mod rlp_encode;
mod signature;
mod signed_transaction;
mod signer;
mod transaction;
mod wei;
pub mod eip712;
pub mod erc4337;

pub use access_list::{AccessList, AccessListItem};
pub use address::Address;
pub use chain_id::ChainId;
pub use error::Error;
pub use signature::Signature;
pub use signed_transaction::SignedTransaction;
pub use signer::{recover_signer, Bip44Signer};
pub use transaction::{
    Eip1559Transaction, Eip1559TransactionBuilder, TOKEN_TRANSFER_GAS, TRANSFER_GAS,
};
pub use wei::{Wei, ETHER, GWEI};

/// Result type alias for signing operations.
pub type Result<T> = std::result::Result<T, Error>;
