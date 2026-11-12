//! Flutter Rust Bridge definitions for KhodPay Wallet
//!
//! This module provides both Object-Oriented (struct wrappers) and
//! Procedural (utility functions) APIs for Flutter integration.
//!
//! # MPC (seedless) wallets
//!
//! A seedless wallet's key never exists in one place. It is split into three
//! shares and any two can sign (2-of-3): the device share (party 0), the
//! KhodPay signer server's share (party 1) and a recovery share (party 2). The
//! device creates parties 0 and 2 together at key generation, encrypts the
//! recovery share with the user's passphrase for backup on Google Drive, and
//! keeps only party 0. Every key generation and every signature is a CGGMP21
//! ceremony run one network round at a time. The cryptography and the round-by-round transport live in
//! `khodpay-mpc-tss`; this module only exposes them to Dart.
//!
//! ## Requirements
//!
//! 1. **Roles.** Party 0 is the device share, party 1 the server and party 2
//!    the recovery share. Everyday signing is parties 0 and 1; after the device
//!    share is lost, parties 2 and 1 (the server then requires a Google token);
//!    with the server unavailable, parties 0 and 2 on one device
//!    ([`mpc_sign_locally`]). Both sides derive each ceremony's execution id from the same session id, which
//!    the server creates and the device receives (at most 128 bytes).
//! 2. **Opaque payloads.** Dart only moves bytes between a session and the
//!    network. Each gRPC round trip carries one CBOR-encoded batch of protocol
//!    messages in each direction; an empty batch is allowed and is how a party
//!    is asked to start.
//! 3. **Always send `next_payload`.** Whenever `next_payload` is set it must be
//!    sent to the server and the reply fed to the next `advance`, even when
//!    `is_complete` is `true`: the server may still need the device's last
//!    messages to finish.
//! 4. **Single use.** A session ends when it completes or fails. Further
//!    `advance` calls return an error and a new session must be created.
//! 5. **Blocking.** `advance` runs cryptography (prime generation, zero-knowledge
//!    proofs) and can take a long time. Dart must call it off the UI isolate.
//! 6. **Primes.** Key generation needs Paillier primes, which are slow to make
//!    (about a minute on a desktop, longer on a phone) and secret. Generate them
//!    ahead of time with [`mpc_generate_primes`], keep them in secure storage,
//!    use fresh primes for every key generation, and pass them to
//!    [`MpcDkgSession::create`]. Without them the session generates its own,
//!    which can take minutes.
//! 7. **Key generation result.** On completion the device receives
//!    `device_share` (secret bytes, for secure storage), `recovery_backup` (the
//!    recovery share already encrypted with the passphrase given to
//!    [`MpcDkgSession::create`], safe to upload) and `wallet_address` (EIP-55).
//!    The plain recovery share never reaches Dart; [`mpc_unlock_recovery_backup`]
//!    opens a backup when it is needed. The share is a complete key share including aux info; a share
//!    from before aux info existed cannot sign and is rejected.
//! 8. **Signing input.** `tx_hash` is exactly 32 bytes and is signed as given,
//!    not hashed again. The device and the server must be given the same hash.
//! 9. **Signing output.** A 65-byte `r || s || v` signature with `v` equal to 0
//!    or 1. The device checks that it recovers to the wallet address before
//!    returning it.
//! 10. **Transactions.** To send from a seedless wallet: build an
//!     [`Eip1559Transaction`], take [`Eip1559Transaction::signing_hash`], sign
//!     that hash with [`MpcSigningSession`], turn the result into an
//!     [`EvmSignature`] with [`EvmSignature::from_bytes`], and assemble the raw
//!     transaction with [`SignedEvmTransaction::new`]. A seed-based wallet uses
//!     [`EvmSigner::sign_and_build`] instead.
//! 11. **Secrets.** Key shares, primes and signatures are never written to
//!     `Debug` output or error strings.
//!
//! ## Exports
//!
//! | Export | Purpose | Status |
//! |---|---|---|
//! | [`mpc_generate_primes`] | Make Paillier primes ahead of time | Implemented |
//! | [`MpcDkgSession`] (`create`, `session_id`, `advance`) | Device side of the 2-of-3 key generation (parties 0 and 2) | Implemented. Unit tests cover input checks; a slow `#[ignore]` end-to-end test runs it against a server-side party |
//! | [`MpcDkgAdvanceResult`] | Result of one key generation step | Implemented |
//! | [`MpcSigningSession`] (`create`, `session_id`, `advance`) | Device side of a signature | Implemented. Same test coverage as above |
//! | [`MpcSigningAdvanceResult`] | Result of one signing step | Implemented |
//! | [`Eip1559Transaction::signing_hash`] | Hash to sign for a transaction | Implemented; already used by the app |
//! | [`mpc_unlock_recovery_backup`], [`mpc_change_recovery_passphrase`], [`mpc_recovery_backup_wallet_address`], [`mpc_validate_passphrase`], [`mpc_min_passphrase_chars`] | Passphrase-protected recovery backup (Argon2id + AES-256-GCM) | Implemented. Unit tests cover wrong passphrase, tampering and unsafe settings |
//! | [`mpc_pairing_new_request`], [`mpc_pairing_export_share`], [`mpc_pairing_import_share`] | Copy the device share to a second device, encrypted to a one-time key shown on the new device | Implemented. Unit tests cover wrong key, tampering and non-share input; the slow end-to-end test covers a real share |
//! | [`mpc_share_info`], [`mpc_sign_locally`], [`mpc_is_valid_device_share`], [`mpc_wallet_address_from_device_share`] | Inspect a share; sign with two local shares and no server | Implemented. Slow `#[ignore]` end-to-end test covers all three signing pairs |
//! | [`EvmSignature::from_bytes`], [`SignedEvmTransaction`] | Turn a signature into a raw transaction | Already existed and are used as described in requirement 10 |
//! | PART 6 free functions and extra methods | Full coverage of bip39, bip32, bip44, khodpay-signing and mpc-tss helpers: languages, word counts, entropy, derivation-path and BIP-44 path operations, key tweaks, gap-limit discovery, EIP-712 encoders and domain hashes, ERC-4337 packing, wei bytes, unsigned tx encoding, wire batches, device-share checks | Implemented. Covered by the `coverage_tests` module |
//! | [`wpgp_encode_register_business`], [`wpgp_register_business_selector`], [`wpgp_generate_business_id`], [`wpgp_decode_gateway_revert`], [`wpgp_decode_business_info`] | Gateway business registration (US-009.1): call data, random id, revert decoding, `getBusinessInfo` decoding | Implemented. Checked against `cast` output in `gateway_tests` |
//!
//! ### Library items not exported, with the reason
//!
//! * Generic functions and traits (`hash_typed_data`, `AccountDiscovery`, `drive`, `spawn`): FFI cannot carry type parameters. Concrete versions exist (`wpgp_*`, `bip44_find_*`).
//! * Builders (`Eip1559TransactionBuilder`, `Bip44PathBuilder`, `WalletBuilder`, `PackedUserOperationBuilder`): replaced by the plain data structs and `bip44_path_build` / `from_mnemonic_in_language`.
//! * Getter/setter pairs on borrowed internals (`as_bytes`, `as_slice`, `iter`, `secret_key`): their values are returned by value through the methods above.
//! * secp256k1 `Message` / `Signature` types (`PublicKey::verify_signature`): not representable; use `recover_signer_address` or `eip712_verify`.
//! * The in-process simulation (`DkgSession::run_local`, `ReshareSession`, `MpcSession`) no longer exists in `khodpay-mpc-tss`. It kept every key share in one process.
//! * Internal MPC plumbing (`spawn_keygen_threshold`, `spawn_aux_info_n`, `spawn_signing_subset`, `complete_key_share`, `ProtocolRunner`): driven for you by `MpcDkgSession` and `MpcSigningSession`.
//!
//! ## Not available yet
//!
//! * **Resharing and share rotation.** There is no way to replace a lost or
//!   leaked share with a fresh one under the same address. Recovery uses the
//!   recovery share instead. A removed device still holds a usable copy of its
//!   share; the server stops signing for it, but the device share together
//!   with the recovery share can still sign without the server.
//! * **Pre-generating primes in the background** is left to the app; nothing
//!   here schedules it.

use flutter_rust_bridge::frb;
use khodpay_bip32::{
    ChildNumber, DerivationPath, ExtendedPrivateKey as RustExtendedPrivateKey,
    ExtendedPublicKey as RustExtendedPublicKey,
};
use khodpay_bip39::{Language, Mnemonic as RustMnemonic, WordCount};
use khodpay_bip44::{
    Account as RustAccount, Bip44Path as RustBip44Path, Chain as RustChain,
    CoinType as RustCoinType, Purpose as RustPurpose, Wallet as RustWallet,
};
use khodpay_signing::eip712::{
    encode_address, encode_bytes32, sign_typed_data, verify_typed_data,
    Eip712Domain, Eip712Type,
};
use khodpay_signing::erc4337::{
    sign_user_operation, verify_user_operation, PackedUserOperation, ENTRY_POINT_V07,
};
use khodpay_signing::{
    recover_signer as rust_recover_signer, Address as RustAddress, Bip44Signer as RustBip44Signer,
    ChainId as RustChainId, Eip1559Transaction as RustEip1559Transaction,
    Signature as RustSignature, SignedTransaction as RustSignedTransaction, Wei as RustWei, ETHER,
    GWEI, TOKEN_TRANSFER_GAS, TRANSFER_GAS,
};
use std::str::FromStr;
use std::sync::Mutex;
use khodpay_mpc_tss::aux_info::{self, Primes};
use khodpay_mpc_tss::dkg_flow::{DeviceDkg, PrimesSource, PARTY_DEVICE, PARTY_RECOVERY, PARTY_SERVER};
use khodpay_mpc_tss::transport::{
    decode_batch, encode_batch, ProtocolRunner, TransportError, WireMessage,
};
use khodpay_mpc_tss::{DeviceShare, MpcError};

// =============================================================================
// PART 1: ENUMS AND DATA TYPES (Mirrored from external crates)
// =============================================================================

// =============================================================================
// Simple enums without data variants (to avoid freezed dependency)
// =============================================================================

/// Network type for the wallet
#[frb]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    BitcoinMainnet,
    BitcoinTestnet,
}

impl From<Network> for khodpay_bip32::Network {
    fn from(n: Network) -> Self {
        match n {
            Network::BitcoinMainnet => khodpay_bip32::Network::BitcoinMainnet,
            Network::BitcoinTestnet => khodpay_bip32::Network::BitcoinTestnet,
        }
    }
}

impl From<khodpay_bip32::Network> for Network {
    fn from(n: khodpay_bip32::Network) -> Self {
        match n {
            khodpay_bip32::Network::BitcoinMainnet => Network::BitcoinMainnet,
            khodpay_bip32::Network::BitcoinTestnet => Network::BitcoinTestnet,
        }
    }
}

/// BIP44 Purpose types (derivation standards)
#[frb]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Bip44,
    Bip49,
    Bip84,
    Bip86,
}

impl From<Purpose> for RustPurpose {
    fn from(p: Purpose) -> Self {
        match p {
            Purpose::Bip44 => RustPurpose::BIP44,
            Purpose::Bip49 => RustPurpose::BIP49,
            Purpose::Bip84 => RustPurpose::BIP84,
            Purpose::Bip86 => RustPurpose::BIP86,
        }
    }
}

impl From<RustPurpose> for Purpose {
    fn from(p: RustPurpose) -> Self {
        match p {
            RustPurpose::BIP44 => Purpose::Bip44,
            RustPurpose::BIP49 => Purpose::Bip49,
            RustPurpose::BIP84 => Purpose::Bip84,
            RustPurpose::BIP86 => Purpose::Bip86,
        }
    }
}

/// BIP44 Coin types (common cryptocurrencies)
/// For custom coin types, use the `custom_coin_type_index` parameter in functions
#[frb]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinType {
    Bitcoin,
    BitcoinTestnet,
    Litecoin,
    Dogecoin,
    Dash,
    Ethereum,
    EthereumClassic,
    BitcoinCash,
    BinanceCoin,
    Solana,
    Cardano,
    Polkadot,
    Cosmos,
    Tron,
}

impl From<CoinType> for RustCoinType {
    fn from(c: CoinType) -> Self {
        match c {
            CoinType::Bitcoin => RustCoinType::Bitcoin,
            CoinType::BitcoinTestnet => RustCoinType::BitcoinTestnet,
            CoinType::Litecoin => RustCoinType::Litecoin,
            CoinType::Dogecoin => RustCoinType::Dogecoin,
            CoinType::Dash => RustCoinType::Dash,
            CoinType::Ethereum => RustCoinType::Ethereum,
            CoinType::EthereumClassic => RustCoinType::EthereumClassic,
            CoinType::BitcoinCash => RustCoinType::BitcoinCash,
            CoinType::BinanceCoin => RustCoinType::BinanceCoin,
            CoinType::Solana => RustCoinType::Solana,
            CoinType::Cardano => RustCoinType::Cardano,
            CoinType::Polkadot => RustCoinType::Polkadot,
            CoinType::Cosmos => RustCoinType::Cosmos,
            CoinType::Tron => RustCoinType::Tron,
        }
    }
}

impl From<RustCoinType> for CoinType {
    fn from(c: RustCoinType) -> Self {
        match c {
            RustCoinType::Bitcoin => CoinType::Bitcoin,
            RustCoinType::BitcoinTestnet => CoinType::BitcoinTestnet,
            RustCoinType::Litecoin => CoinType::Litecoin,
            RustCoinType::Dogecoin => CoinType::Dogecoin,
            RustCoinType::Dash => CoinType::Dash,
            RustCoinType::Ethereum => CoinType::Ethereum,
            RustCoinType::EthereumClassic => CoinType::EthereumClassic,
            RustCoinType::BitcoinCash => CoinType::BitcoinCash,
            RustCoinType::BinanceCoin => CoinType::BinanceCoin,
            RustCoinType::Solana => CoinType::Solana,
            RustCoinType::Cardano => CoinType::Cardano,
            RustCoinType::Polkadot => CoinType::Polkadot,
            RustCoinType::Cosmos => CoinType::Cosmos,
            RustCoinType::Tron => CoinType::Tron,
            // For custom types, default to Ethereum (most common for EVM)
            RustCoinType::Custom(_) => CoinType::Ethereum,
        }
    }
}

/// BIP44 Chain type (external/internal)
#[frb]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    External,
    Internal,
}

impl From<Chain> for RustChain {
    fn from(c: Chain) -> Self {
        match c {
            Chain::External => RustChain::External,
            Chain::Internal => RustChain::Internal,
        }
    }
}

impl From<RustChain> for Chain {
    fn from(c: RustChain) -> Self {
        match c {
            RustChain::External => Chain::External,
            RustChain::Internal => Chain::Internal,
        }
    }
}

/// EVM Chain ID for transaction signing
/// For custom chain IDs, use the `custom_chain_id` parameter in functions
#[frb]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainId {
    /// BSC Mainnet (chain ID 56)
    BscMainnet,
    /// BSC Testnet (chain ID 97)
    BscTestnet,
    /// Ethereum Mainnet (chain ID 1)
    EthereumMainnet,
    /// Polygon Mainnet (chain ID 137)
    Polygon,
    /// Arbitrum One (chain ID 42161)
    Arbitrum,
    /// Optimism (chain ID 10)
    Optimism,
    /// Avalanche C-Chain (chain ID 43114)
    Avalanche,
}

impl From<ChainId> for RustChainId {
    fn from(c: ChainId) -> Self {
        match c {
            ChainId::BscMainnet => RustChainId::BscMainnet,
            ChainId::BscTestnet => RustChainId::BscTestnet,
            ChainId::EthereumMainnet => RustChainId::Custom(1),
            ChainId::Polygon => RustChainId::Custom(137),
            ChainId::Arbitrum => RustChainId::Custom(42161),
            ChainId::Optimism => RustChainId::Custom(10),
            ChainId::Avalanche => RustChainId::Custom(43114),
        }
    }
}

impl From<RustChainId> for ChainId {
    fn from(c: RustChainId) -> Self {
        match c {
            RustChainId::BscMainnet => ChainId::BscMainnet,
            RustChainId::BscTestnet => ChainId::BscTestnet,
            RustChainId::Custom(1) => ChainId::EthereumMainnet,
            RustChainId::Custom(137) => ChainId::Polygon,
            RustChainId::Custom(42161) => ChainId::Arbitrum,
            RustChainId::Custom(10) => ChainId::Optimism,
            RustChainId::Custom(43114) => ChainId::Avalanche,
            // Default to BSC for unknown custom chain IDs
            RustChainId::Custom(_) => ChainId::BscMainnet,
        }
    }
}

/// Get the numeric chain ID value
#[frb]
pub fn chain_id_to_u64(chain_id: ChainId) -> u64 {
    let rust_chain: RustChainId = chain_id.into();
    rust_chain.value()
}

/// Create a custom chain ID from a numeric value (for chains not in the enum)
#[frb]
pub fn custom_chain_id_value(chain_id: u64) -> u64 {
    chain_id
}

/// Get the SLIP-44 coin type index
#[frb]
pub fn coin_type_to_index(coin_type: CoinType) -> u32 {
    let rust_coin: RustCoinType = coin_type.into();
    rust_coin.index()
}

/// Result type for wallet operations (used by utility functions)
#[frb]
#[derive(Debug, Clone)]
pub struct WalletResult {
    pub success: bool,
    pub message: String,
    pub data: Option<String>,
}

// =============================================================================
// PART 2: STRUCT WRAPPERS (Object-Oriented API)
// =============================================================================

/// Flutter wrapper for Mnemonic - provides OOP interface
#[frb]
pub struct Mnemonic {
    inner: RustMnemonic,
}

#[frb]
impl Mnemonic {
    /// Generate a new mnemonic with specified word count
    #[frb]
    pub fn generate(word_count: u32) -> Result<Self, String> {
        let count = match word_count {
            12 => WordCount::Twelve,
            15 => WordCount::Fifteen,
            18 => WordCount::Eighteen,
            21 => WordCount::TwentyOne,
            24 => WordCount::TwentyFour,
            _ => return Err("Invalid word count. Use 12, 15, 18, 21, or 24".to_string()),
        };

        let mnemonic = RustMnemonic::generate(count, Language::English)
            .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;

        Ok(Self { inner: mnemonic })
    }

    /// Parse mnemonic from phrase string
    #[frb]
    pub fn from_phrase(phrase: String) -> Result<Self, String> {
        let mnemonic = RustMnemonic::from_phrase(&phrase, Language::English)
            .map_err(|e| format!("Invalid mnemonic: {}", e))?;
        Ok(Self { inner: mnemonic })
    }

    /// Convert mnemonic to string phrase
    #[frb]
    pub fn to_phrase(&self) -> String {
        self.inner.phrase().to_string()
    }

    /// Get the word count
    #[frb]
    pub fn word_count(&self) -> u32 {
        self.inner.phrase().split_whitespace().count() as u32
    }

    /// Validate that this mnemonic is valid (always true for constructed mnemonics)
    #[frb]
    pub fn is_valid(&self) -> bool {
        true
    }

    /// Convert mnemonic to BIP39 seed bytes (64 bytes)
    #[frb]
    pub fn to_seed(&self, passphrase: Option<String>) -> Result<Vec<u8>, String> {
        self.inner
            .to_seed(&passphrase.unwrap_or_default())
            .map(|seed| seed.to_vec())
            .map_err(|e| format!("Failed to generate seed: {}", e))
    }
}

/// Flutter wrapper for ExtendedPrivateKey - provides OOP interface
#[frb]
pub struct ExtendedPrivateKey {
    inner: RustExtendedPrivateKey,
}

#[frb]
impl ExtendedPrivateKey {
    /// Create master key from seed bytes
    #[frb]
    pub fn from_seed(seed: Vec<u8>, network: Network) -> Result<Self, String> {
        let key = RustExtendedPrivateKey::from_seed(&seed, network.into())
            .map_err(|e| format!("Failed to create key from seed: {}", e))?;
        Ok(Self { inner: key })
    }

    /// Create master key from mnemonic
    #[frb]
    pub fn from_mnemonic(
        mnemonic: &Mnemonic,
        passphrase: Option<String>,
        network: Network,
    ) -> Result<Self, String> {
        let key = RustExtendedPrivateKey::from_mnemonic(
            &mnemonic.inner,
            passphrase.as_deref(),
            network.into(),
        )
        .map_err(|e| format!("Failed to create key from mnemonic: {}", e))?;
        Ok(Self { inner: key })
    }

    /// Parse from string (xprv... format)
    #[frb]
    pub fn from_string(s: String) -> Result<Self, String> {
        let key = RustExtendedPrivateKey::from_str(&s)
            .map_err(|e| format!("Invalid extended private key: {}", e))?;
        Ok(Self { inner: key })
    }

    /// Serialize to extended key string (xprv... format)
    #[frb]
    pub fn to_extended_string(&self) -> String {
        self.inner.to_string()
    }

    /// Get the network this key belongs to
    #[frb]
    pub fn network(&self) -> Network {
        self.inner.network().into()
    }

    /// Get the depth in derivation tree (0 = master, 1 = level-1 child, etc.)
    #[frb]
    pub fn depth(&self) -> u8 {
        self.inner.depth()
    }

    /// Get the parent fingerprint (4 bytes)
    #[frb]
    pub fn parent_fingerprint(&self) -> Vec<u8> {
        self.inner.parent_fingerprint().to_vec()
    }

    /// Get this key's fingerprint (4 bytes)
    #[frb]
    pub fn fingerprint(&self) -> Vec<u8> {
        self.inner.fingerprint().to_vec()
    }

    /// Get the child number index
    #[frb]
    pub fn child_number_index(&self) -> u32 {
        match self.inner.child_number() {
            ChildNumber::Normal(n) | ChildNumber::Hardened(n) => n,
        }
    }

    /// Check if this is a hardened key
    #[frb]
    pub fn is_hardened(&self) -> bool {
        matches!(self.inner.child_number(), ChildNumber::Hardened(_))
    }

    /// Derive a single child key
    #[frb]
    pub fn derive_child(&self, index: u32, hardened: bool) -> Result<Self, String> {
        let child_num = if hardened {
            ChildNumber::Hardened(index)
        } else {
            ChildNumber::Normal(index)
        };

        let child = self
            .inner
            .derive_child(child_num)
            .map_err(|e| format!("Failed to derive child: {}", e))?;

        Ok(Self { inner: child })
    }

    /// Derive using a path string (e.g., "m/44'/0'/0'/0/0")
    #[frb]
    pub fn derive_path(&self, path: String) -> Result<Self, String> {
        let derivation_path = DerivationPath::from_str(&path)
            .map_err(|e| format!("Invalid derivation path: {}", e))?;

        let derived = self
            .inner
            .derive_path(&derivation_path)
            .map_err(|e| format!("Failed to derive path: {}", e))?;

        Ok(Self { inner: derived })
    }

    /// Convert to extended public key
    #[frb]
    pub fn to_extended_public_key(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            inner: self.inner.to_extended_public_key(),
        }
    }
}

/// Flutter wrapper for ExtendedPublicKey - provides OOP interface
#[frb]
pub struct ExtendedPublicKey {
    inner: RustExtendedPublicKey,
}

#[frb]
impl ExtendedPublicKey {
    /// Parse from string (xpub... format)
    #[frb]
    pub fn from_string(s: String) -> Result<Self, String> {
        let key = RustExtendedPublicKey::from_str(&s)
            .map_err(|e| format!("Invalid extended public key: {}", e))?;
        Ok(Self { inner: key })
    }

    /// Serialize to extended key string (xpub... format)
    #[frb]
    pub fn to_extended_string(&self) -> String {
        self.inner.to_string()
    }

    /// Get the network this key belongs to
    #[frb]
    pub fn network(&self) -> Network {
        self.inner.network().into()
    }

    /// Get the depth in derivation tree
    #[frb]
    pub fn depth(&self) -> u8 {
        self.inner.depth()
    }

    /// Get the parent fingerprint (4 bytes)
    #[frb]
    pub fn parent_fingerprint(&self) -> Vec<u8> {
        self.inner.parent_fingerprint().to_vec()
    }

    /// Get this key's fingerprint (4 bytes)
    #[frb]
    pub fn fingerprint(&self) -> Vec<u8> {
        self.inner.fingerprint().to_vec()
    }

    /// Get the child number index
    #[frb]
    pub fn child_number_index(&self) -> u32 {
        match self.inner.child_number() {
            ChildNumber::Normal(n) | ChildNumber::Hardened(n) => n,
        }
    }

    /// Check if this is a hardened key (public keys can only have non-hardened children)
    #[frb]
    pub fn is_hardened(&self) -> bool {
        matches!(self.inner.child_number(), ChildNumber::Hardened(_))
    }

    /// Derive a child public key (non-hardened only)
    #[frb]
    pub fn derive_child(&self, index: u32) -> Result<Self, String> {
        let child = self
            .inner
            .derive_child(ChildNumber::Normal(index))
            .map_err(|e| format!("Failed to derive child: {}", e))?;
        Ok(Self { inner: child })
    }

    /// Derive using a path string (only non-hardened paths allowed)
    #[frb]
    pub fn derive_path(&self, path: String) -> Result<Self, String> {
        let derivation_path = DerivationPath::from_str(&path)
            .map_err(|e| format!("Invalid derivation path: {}", e))?;

        let derived = self.inner.derive_path(&derivation_path).map_err(|e| {
            format!(
                "Failed to derive path (hardened derivation not allowed): {}",
                e
            )
        })?;

        Ok(Self { inner: derived })
    }
}

/// Flutter wrapper for BIP44 Wallet - provides OOP interface
#[frb]
pub struct Bip44Wallet {
    inner: RustWallet,
}

#[frb]
impl Bip44Wallet {
    /// Create a new BIP44 wallet from mnemonic
    #[frb]
    pub fn from_mnemonic(
        mnemonic: String,
        passphrase: Option<String>,
        network: Network,
    ) -> Result<Self, String> {
        let wallet = RustWallet::from_english_mnemonic(
            &mnemonic,
            passphrase.as_deref().unwrap_or(""),
            network.into(),
        )
        .map_err(|e| format!("Failed to create wallet: {}", e))?;

        Ok(Self { inner: wallet })
    }

    /// Create a new BIP44 wallet from seed
    #[frb]
    pub fn from_seed(seed: Vec<u8>, network: Network) -> Result<Self, String> {
        let wallet = RustWallet::from_seed(&seed, network.into())
            .map_err(|e| format!("Failed to create wallet: {}", e))?;

        Ok(Self { inner: wallet })
    }

    /// Get the network this wallet operates on
    #[frb]
    pub fn network(&self) -> Network {
        self.inner.network().into()
    }

    /// Get an account for a specific coin type
    #[frb]
    pub fn get_account(
        &mut self,
        purpose: Purpose,
        coin_type: CoinType,
        account_index: u32,
    ) -> Result<Bip44Account, String> {
        let account = self
            .inner
            .get_account(purpose.into(), coin_type.into(), account_index)
            .map_err(|e| format!("Failed to get account: {}", e))?;

        Ok(Bip44Account {
            inner: account.clone(),
        })
    }
}

/// Flutter wrapper for BIP44 Account - wraps the actual RustAccount
#[frb]
pub struct Bip44Account {
    inner: RustAccount,
}

#[frb]
impl Bip44Account {
    /// Get the purpose (BIP standard) for this account
    #[frb]
    pub fn purpose(&self) -> Purpose {
        self.inner.purpose().into()
    }

    /// Get the coin type for this account
    #[frb]
    pub fn coin_type(&self) -> CoinType {
        self.inner.coin_type().into()
    }

    /// Get the account index
    #[frb]
    pub fn account_index(&self) -> u32 {
        self.inner.account_index()
    }

    /// Get the network for this account
    #[frb]
    pub fn network(&self) -> Network {
        self.inner.network().into()
    }

    /// Get the extended key as a string (xprv format)
    #[frb]
    pub fn extended_key_string(&self) -> String {
        self.inner.extended_key().to_string()
    }

    /// Derive an external (receiving) address at the given index
    #[frb]
    pub fn derive_external(&self, index: u32) -> Result<String, String> {
        let key = self
            .inner
            .derive_external(index)
            .map_err(|e| format!("Failed to derive external address: {}", e))?;

        // For EVM chains (Ethereum, BSC, Polygon, etc.), derive the address from public key
        if self.inner.coin_type().is_evm_compatible() {
            // Get the uncompressed public key (65 bytes with 0x04 prefix)
            let public_key = key.private_key().public_key();
            let pubkey_uncompressed = public_key.serialize_uncompressed();

            // Skip the 0x04 prefix and derive EVM address from 64-byte public key
            let address = RustAddress::from_public_key_bytes(&pubkey_uncompressed[1..])
                .map_err(|e| format!("Failed to derive EVM address: {}", e))?;
            Ok(address.to_checksum_string())
        } else {
            // For non-EVM chains, return the extended key string
            Ok(key.to_string())
        }
    }

    /// Derive an internal (change) address at the given index
    #[frb]
    pub fn derive_internal(&self, index: u32) -> Result<String, String> {
        let key = self
            .inner
            .derive_internal(index)
            .map_err(|e| format!("Failed to derive internal address: {}", e))?;

        // For EVM chains (Ethereum, BSC, Polygon, etc.), derive the address from public key
        if self.inner.coin_type().is_evm_compatible() {
            // Get the uncompressed public key (65 bytes with 0x04 prefix)
            let public_key = key.private_key().public_key();
            let pubkey_uncompressed = public_key.serialize_uncompressed();

            // Skip the 0x04 prefix and derive EVM address from 64-byte public key
            let address = RustAddress::from_public_key_bytes(&pubkey_uncompressed[1..])
                .map_err(|e| format!("Failed to derive EVM address: {}", e))?;
            Ok(address.to_checksum_string())
        } else {
            // For non-EVM chains, return the extended key string
            Ok(key.to_string())
        }
    }

    /// Derive an address for the specified chain and index
    #[frb]
    pub fn derive_address(&self, chain: Chain, index: u32) -> Result<String, String> {
        let key = self
            .inner
            .derive_address(chain.into(), index)
            .map_err(|e| format!("Failed to derive address: {}", e))?;

        // For EVM chains (Ethereum, BSC, Polygon, etc.), derive the address from public key
        if self.inner.coin_type().is_evm_compatible() {
            // Get the uncompressed public key (65 bytes with 0x04 prefix)
            let public_key = key.private_key().public_key();
            let pubkey_uncompressed = public_key.serialize_uncompressed();

            // Skip the 0x04 prefix and derive EVM address from 64-byte public key
            let address = RustAddress::from_public_key_bytes(&pubkey_uncompressed[1..])
                .map_err(|e| format!("Failed to derive EVM address: {}", e))?;
            Ok(address.to_checksum_string())
        } else {
            // For non-EVM chains, return the extended key string
            Ok(key.to_string())
        }
    }

    /// Derive a range of addresses
    #[frb]
    pub fn derive_address_range(
        &self,
        chain: Chain,
        start: u32,
        count: u32,
    ) -> Result<Vec<String>, String> {
        let keys = self
            .inner
            .derive_address_range(chain.into(), start, count)
            .map_err(|e| format!("Failed to derive address range: {}", e))?;

        // For EVM chains (Ethereum, BSC, Polygon, etc.), derive addresses from public keys
        if self.inner.coin_type().is_evm_compatible() {
            keys.iter()
                .map(|key| {
                    // Get the uncompressed public key (65 bytes with 0x04 prefix)
                    let public_key = key.private_key().public_key();
                    let pubkey_uncompressed = public_key.serialize_uncompressed();

                    // Skip the 0x04 prefix and derive EVM address from 64-byte public key
                    let address = RustAddress::from_public_key_bytes(&pubkey_uncompressed[1..])
                        .map_err(|e| format!("Failed to derive EVM address: {}", e))?;
                    Ok(address.to_checksum_string())
                })
                .collect()
        } else {
            // For non-EVM chains, return the extended key strings
            Ok(keys.iter().map(|k| k.to_string()).collect())
        }
    }
}

// =============================================================================
// PART 2.5: EVM SIGNING STRUCT WRAPPERS
// =============================================================================

/// Flutter wrapper for EVM Address - 20-byte Ethereum-compatible address
#[frb]
pub struct EvmAddress {
    inner: RustAddress,
}

#[frb]
impl EvmAddress {
    /// The length of an address in bytes (20)
    pub const LENGTH: usize = 20;

    /// Create the zero address (0x0000...0000)
    #[frb]
    pub fn zero() -> Self {
        Self {
            inner: RustAddress::ZERO,
        }
    }

    /// Parse an address from a hex string (with or without 0x prefix)
    #[frb]
    pub fn from_hex(hex_string: String) -> Result<Self, String> {
        let addr =
            RustAddress::from_str(&hex_string).map_err(|e| format!("Invalid address: {}", e))?;
        Ok(Self { inner: addr })
    }

    /// Create an address from 20 bytes
    #[frb]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let addr =
            RustAddress::from_slice(&bytes).map_err(|e| format!("Invalid address bytes: {}", e))?;
        Ok(Self { inner: addr })
    }

    /// Derive an address from an uncompressed public key (64 bytes, without 0x04 prefix)
    #[frb]
    pub fn from_public_key(pubkey: Vec<u8>) -> Result<Self, String> {
        let addr = RustAddress::from_public_key_bytes(&pubkey)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        Ok(Self { inner: addr })
    }

    /// Returns the address as a byte array (20 bytes)
    #[frb]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Returns the EIP-55 checksummed hex string (with 0x prefix)
    #[frb]
    pub fn to_checksum_string(&self) -> String {
        self.inner.to_checksum_string()
    }

    /// Returns the lowercase hex string (with 0x prefix)
    #[frb]
    pub fn to_hex_string(&self) -> String {
        format!("{:#x}", self.inner)
    }

    /// Validate an EIP-55 checksummed address string
    #[frb]
    pub fn validate_checksum(address: String) -> bool {
        RustAddress::validate_checksum(&address)
    }

    /// Check if this is the zero address
    #[frb]
    pub fn is_zero(&self) -> bool {
        self.inner == RustAddress::ZERO
    }
}

/// Flutter wrapper for Wei - EVM currency value (smallest unit)
#[frb]
pub struct EvmWei {
    /// Internal representation as hex string for large number support
    pub value_hex: String,
}

#[frb]
impl EvmWei {
    /// Create zero wei
    #[frb]
    pub fn zero() -> Self {
        Self {
            value_hex: "0".to_string(),
        }
    }

    /// Create Wei from a u64 value (in wei)
    #[frb]
    pub fn from_wei_u64(wei: u64) -> Self {
        let rust_wei = RustWei::from_wei(wei);
        Self {
            value_hex: rust_wei.to_string(),
        }
    }

    /// Create Wei from a decimal string (in wei)
    #[frb]
    pub fn from_wei_string(wei_string: String) -> Result<Self, String> {
        let rust_wei: RustWei = wei_string
            .parse()
            .map_err(|e| format!("Invalid wei value: {}", e))?;
        Ok(Self {
            value_hex: rust_wei.to_string(),
        })
    }

    /// Create Wei from gwei (1 gwei = 10^9 wei)
    #[frb]
    pub fn from_gwei(gwei: u64) -> Self {
        let rust_wei = RustWei::from_gwei(gwei);
        Self {
            value_hex: rust_wei.to_string(),
        }
    }

    /// Create Wei from ether/BNB (1 ether = 10^18 wei)
    #[frb]
    pub fn from_ether(ether: u64) -> Self {
        let rust_wei = RustWei::from_ether(ether);
        Self {
            value_hex: rust_wei.to_string(),
        }
    }

    /// Returns the value as a decimal string
    #[frb]
    pub fn to_decimal_string(&self) -> String {
        self.value_hex.clone()
    }

    /// Returns the value as u64 if it fits, None otherwise
    #[frb]
    pub fn to_u64(&self) -> Option<u64> {
        let rust_wei: RustWei = self.value_hex.parse().ok()?;
        rust_wei.as_u64()
    }

    /// Convert to gwei (truncates)
    #[frb]
    pub fn to_gwei(&self) -> u64 {
        let rust_wei: RustWei = self.value_hex.parse().unwrap_or(RustWei::ZERO);
        rust_wei.to_gwei()
    }

    /// Convert to ether (truncates)
    #[frb]
    pub fn to_ether(&self) -> u64 {
        let rust_wei: RustWei = self.value_hex.parse().unwrap_or(RustWei::ZERO);
        rust_wei.to_ether()
    }

    /// Check if the value is zero
    #[frb]
    pub fn is_zero(&self) -> bool {
        self.value_hex == "0" || self.value_hex.is_empty()
    }

    /// Add two Wei values
    #[frb]
    pub fn add(&self, other: &EvmWei) -> Result<Self, String> {
        let a: RustWei = self
            .value_hex
            .parse()
            .map_err(|e| format!("Invalid wei value: {}", e))?;
        let b: RustWei = other
            .value_hex
            .parse()
            .map_err(|e| format!("Invalid wei value: {}", e))?;
        Ok(Self {
            value_hex: (a + b).to_string(),
        })
    }

    /// Multiply Wei by a u64 scalar
    #[frb]
    pub fn multiply(&self, scalar: u64) -> Result<Self, String> {
        let a: RustWei = self
            .value_hex
            .parse()
            .map_err(|e| format!("Invalid wei value: {}", e))?;
        Ok(Self {
            value_hex: (a * scalar).to_string(),
        })
    }
}

/// Flutter wrapper for ECDSA Signature with recovery ID
#[frb]
#[derive(Debug, Clone)]
pub struct EvmSignature {
    /// R component (32 bytes as hex)
    pub r_hex: String,
    /// S component (32 bytes as hex)
    pub s_hex: String,
    /// Recovery ID (0 or 1)
    pub v: u8,
}

#[frb]
impl EvmSignature {
    /// Create a new signature from components
    #[frb]
    pub fn new(r_hex: String, s_hex: String, v: u8) -> Self {
        Self { r_hex, s_hex, v }
    }

    /// Create a signature from 65 raw bytes (r || s || v)
    #[frb]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let sig = RustSignature::from_bytes(&bytes)
            .ok_or_else(|| "Invalid signature bytes (expected 65 bytes)".to_string())?;
        Ok(Self {
            r_hex: hex::encode(sig.r),
            s_hex: hex::encode(sig.s),
            v: sig.v,
        })
    }

    /// Returns the signature as 65 raw bytes (r || s || v)
    #[frb]
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let r = hex::decode(&self.r_hex).map_err(|e| format!("Invalid r hex: {}", e))?;
        let s = hex::decode(&self.s_hex).map_err(|e| format!("Invalid s hex: {}", e))?;

        if r.len() != 32 || s.len() != 32 {
            return Err("r and s must be 32 bytes each".to_string());
        }

        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&r);
        bytes.extend_from_slice(&s);
        bytes.push(self.v);
        Ok(bytes)
    }

    /// Returns the signature as a hex string (0x prefix + r + s + v)
    #[frb]
    pub fn to_hex_string(&self) -> String {
        format!("0x{}{}{:02x}", self.r_hex, self.s_hex, self.v)
    }
}

impl From<RustSignature> for EvmSignature {
    fn from(sig: RustSignature) -> Self {
        Self {
            r_hex: hex::encode(sig.r),
            s_hex: hex::encode(sig.s),
            v: sig.v,
        }
    }
}

impl TryFrom<&EvmSignature> for RustSignature {
    type Error = String;

    fn try_from(sig: &EvmSignature) -> Result<Self, Self::Error> {
        let r = hex::decode(&sig.r_hex).map_err(|e| format!("Invalid r hex: {}", e))?;
        let s = hex::decode(&sig.s_hex).map_err(|e| format!("Invalid s hex: {}", e))?;

        if r.len() != 32 || s.len() != 32 {
            return Err("r and s must be 32 bytes each".to_string());
        }

        let mut r_arr = [0u8; 32];
        let mut s_arr = [0u8; 32];
        r_arr.copy_from_slice(&r);
        s_arr.copy_from_slice(&s);

        Ok(RustSignature::new(r_arr, s_arr, sig.v))
    }
}

/// Flutter wrapper for EIP-1559 Transaction
#[frb]
#[derive(Debug, Clone)]
pub struct Eip1559Transaction {
    /// Chain ID for replay protection
    pub chain_id: ChainId,
    /// Transaction nonce (sender's transaction count)
    pub nonce: u64,
    /// Maximum priority fee per gas (tip to validator) in wei
    pub max_priority_fee_per_gas: String,
    /// Maximum total fee per gas in wei
    pub max_fee_per_gas: String,
    /// Gas limit for the transaction
    pub gas_limit: u64,
    /// Recipient address (None for contract creation)
    pub to: Option<String>,
    /// Value to transfer in wei
    pub value: String,
    /// Transaction data (contract call data) as hex
    pub data_hex: String,
}

#[frb]
impl Eip1559Transaction {
    /// Transaction type identifier for EIP-1559
    pub const TYPE: u8 = 0x02;

    /// Standard gas limit for ETH/BNB transfer
    #[frb]
    pub fn transfer_gas() -> u64 {
        TRANSFER_GAS
    }

    /// Typical gas limit for BEP-20/ERC-20 token transfer
    #[frb]
    pub fn token_transfer_gas() -> u64 {
        TOKEN_TRANSFER_GAS
    }

    /// Create a new transaction builder
    #[frb]
    pub fn builder() -> Eip1559TransactionBuilder {
        Eip1559TransactionBuilder::new()
    }

    /// Validate the transaction
    #[frb]
    pub fn validate(&self) -> Result<(), String> {
        let rust_tx = self.to_rust_transaction()?;
        rust_tx.validate().map_err(|e| e.to_string())
    }

    /// The 32-byte hash that is signed to authorise this transaction:
    /// `keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas,
    /// maxFeePerGas, gasLimit, to, value, data, accessList]))`.
    ///
    /// Seedless (MPC) wallets sign this hash jointly with the signer server,
    /// because no single party holds the key. Pair it with
    /// [`SignedEvmTransaction::new`] and the resulting signature to build the
    /// raw transaction.
    #[frb]
    pub fn signing_hash(&self) -> Result<Vec<u8>, String> {
        let rust_tx = self.to_rust_transaction()?;
        Ok(rust_tx.signing_hash().to_vec())
    }

    /// Check if this is a contract creation transaction
    #[frb]
    pub fn is_contract_creation(&self) -> bool {
        self.to.is_none()
    }

    /// Check if this is a simple value transfer (no data)
    #[frb]
    pub fn is_transfer(&self) -> bool {
        self.to.is_some() && (self.data_hex.is_empty() || self.data_hex == "0x")
    }

    /// Convert to internal Rust transaction type
    fn to_rust_transaction(&self) -> Result<RustEip1559Transaction, String> {
        let max_priority_fee: RustWei = self
            .max_priority_fee_per_gas
            .parse()
            .map_err(|e| format!("Invalid max_priority_fee_per_gas: {}", e))?;
        let max_fee: RustWei = self
            .max_fee_per_gas
            .parse()
            .map_err(|e| format!("Invalid max_fee_per_gas: {}", e))?;
        let value: RustWei = self
            .value
            .parse()
            .map_err(|e| format!("Invalid value: {}", e))?;

        let data = if self.data_hex.is_empty() || self.data_hex == "0x" {
            Vec::new()
        } else {
            let hex_str = self.data_hex.strip_prefix("0x").unwrap_or(&self.data_hex);
            hex::decode(hex_str).map_err(|e| format!("Invalid data hex: {}", e))?
        };

        let mut builder = RustEip1559Transaction::builder()
            .chain_id(self.chain_id.into())
            .nonce(self.nonce)
            .max_priority_fee_per_gas(max_priority_fee)
            .max_fee_per_gas(max_fee)
            .gas_limit(self.gas_limit)
            .value(value)
            .data(data);

        if let Some(ref to_addr) = self.to {
            let addr =
                RustAddress::from_str(to_addr).map_err(|e| format!("Invalid to address: {}", e))?;
            builder = builder.to(addr);
        }

        builder.build().map_err(|e| e.to_string())
    }
}

/// Builder for EIP-1559 transactions
#[frb]
#[derive(Debug, Clone, Default)]
pub struct Eip1559TransactionBuilder {
    pub chain_id: Option<ChainId>,
    pub nonce: Option<u64>,
    pub max_priority_fee_per_gas: Option<String>,
    pub max_fee_per_gas: Option<String>,
    pub gas_limit: Option<u64>,
    pub to: Option<String>,
    pub value: Option<String>,
    pub data_hex: Option<String>,
}

#[frb]
impl Eip1559TransactionBuilder {
    /// Create a new transaction builder
    #[frb]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the transaction from the current builder state
    ///
    /// In Dart, construct the builder with fields directly:
    /// ```dart
    /// var builder = Eip1559TransactionBuilder(
    ///   chainId: ChainId.bscMainnet(),
    ///   nonce: 0,
    ///   maxPriorityFeePerGas: "1000000000",
    ///   maxFeePerGas: "2000000000",
    ///   gasLimit: 21000,
    ///   to: "0x...",
    ///   value: "1000000000000000000",
    /// );
    /// var tx = await builder.build();
    /// ```
    #[frb]
    pub fn build(&self) -> Result<Eip1559Transaction, String> {
        let tx = Eip1559Transaction {
            chain_id: self
                .chain_id
                .clone()
                .ok_or_else(|| "chain_id is required".to_string())?,
            nonce: self.nonce.ok_or_else(|| "nonce is required".to_string())?,
            max_priority_fee_per_gas: self
                .max_priority_fee_per_gas
                .clone()
                .ok_or_else(|| "max_priority_fee_per_gas is required".to_string())?,
            max_fee_per_gas: self
                .max_fee_per_gas
                .clone()
                .ok_or_else(|| "max_fee_per_gas is required".to_string())?,
            gas_limit: self
                .gas_limit
                .ok_or_else(|| "gas_limit is required".to_string())?,
            to: self.to.clone(),
            value: self.value.clone().unwrap_or_else(|| "0".to_string()),
            data_hex: self.data_hex.clone().unwrap_or_default(),
        };

        // Validate the transaction
        tx.validate()?;
        Ok(tx)
    }
}

/// Flutter wrapper for a signed EIP-1559 transaction
#[frb]
#[derive(Debug, Clone)]
pub struct SignedEvmTransaction {
    /// The unsigned transaction
    pub transaction: Eip1559Transaction,
    /// The ECDSA signature
    pub signature: EvmSignature,
}

#[frb]
impl SignedEvmTransaction {
    /// Create a new signed transaction
    #[frb]
    pub fn new(transaction: Eip1559Transaction, signature: EvmSignature) -> Self {
        Self {
            transaction,
            signature,
        }
    }

    /// Encode the signed transaction as raw bytes
    #[frb]
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let rust_tx = self.transaction.to_rust_transaction()?;
        let rust_sig: RustSignature = (&self.signature).try_into()?;
        let signed = RustSignedTransaction::new(rust_tx, rust_sig);
        Ok(signed.encode())
    }

    /// Returns the raw transaction as a hex string with 0x prefix
    /// This is the format expected by eth_sendRawTransaction
    #[frb]
    pub fn to_raw_transaction(&self) -> Result<String, String> {
        let rust_tx = self.transaction.to_rust_transaction()?;
        let rust_sig: RustSignature = (&self.signature).try_into()?;
        let signed = RustSignedTransaction::new(rust_tx, rust_sig);
        Ok(signed.to_raw_transaction())
    }

    /// Compute the transaction hash
    #[frb]
    pub fn tx_hash(&self) -> Result<Vec<u8>, String> {
        let rust_tx = self.transaction.to_rust_transaction()?;
        let rust_sig: RustSignature = (&self.signature).try_into()?;
        let signed = RustSignedTransaction::new(rust_tx, rust_sig);
        Ok(signed.tx_hash().to_vec())
    }

    /// Returns the transaction hash as a hex string with 0x prefix
    #[frb]
    pub fn tx_hash_hex(&self) -> Result<String, String> {
        let rust_tx = self.transaction.to_rust_transaction()?;
        let rust_sig: RustSignature = (&self.signature).try_into()?;
        let signed = RustSignedTransaction::new(rust_tx, rust_sig);
        Ok(signed.tx_hash_hex())
    }
}

/// Flutter wrapper for BIP-44 transaction signer
#[frb]
pub struct EvmSigner {
    inner: RustBip44Signer,
}

#[frb]
impl EvmSigner {
    /// Create a signer from a BIP-44 account and address index
    #[frb]
    pub fn from_account(account: &Bip44Account, address_index: u32) -> Result<Self, String> {
        // Use RustBip44Signer::new which takes a RustAccount reference
        let signer = RustBip44Signer::new(&account.inner, address_index)
            .map_err(|e| format!("Failed to create signer: {}", e))?;

        Ok(Self { inner: signer })
    }

    /// Create a signer directly from a 32-byte private key (hex string)
    #[frb]
    pub fn from_private_key_hex(private_key_hex: String) -> Result<Self, String> {
        let hex_str = private_key_hex
            .strip_prefix("0x")
            .unwrap_or(&private_key_hex);
        let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid private key hex: {}", e))?;

        if bytes.len() != 32 {
            return Err("Private key must be 32 bytes".to_string());
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&bytes);

        let signer = RustBip44Signer::from_private_key(&key_arr)
            .map_err(|e| format!("Failed to create signer: {}", e))?;

        Ok(Self { inner: signer })
    }

    /// Returns the EVM address associated with this signer
    #[frb]
    pub fn address(&self) -> EvmAddress {
        EvmAddress {
            inner: self.inner.address(),
        }
    }

    /// Returns the EVM address as a checksummed hex string
    #[frb]
    pub fn address_string(&self) -> String {
        self.inner.address().to_checksum_string()
    }

    /// Sign a message hash (32 bytes)
    #[frb]
    pub fn sign_hash(&self, hash: Vec<u8>) -> Result<EvmSignature, String> {
        if hash.len() != 32 {
            return Err("Hash must be 32 bytes".to_string());
        }

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash);

        let sig = self
            .inner
            .sign_hash(&hash_arr)
            .map_err(|e| format!("Signing failed: {}", e))?;

        Ok(sig.into())
    }

    /// Sign an EIP-1559 transaction
    #[frb]
    pub fn sign_transaction(&self, tx: &Eip1559Transaction) -> Result<EvmSignature, String> {
        let rust_tx = tx.to_rust_transaction()?;
        let sig = self
            .inner
            .sign_transaction(&rust_tx)
            .map_err(|e| format!("Signing failed: {}", e))?;
        Ok(sig.into())
    }

    /// Sign a transaction and return the signed transaction
    #[frb]
    pub fn sign_and_build(&self, tx: Eip1559Transaction) -> Result<SignedEvmTransaction, String> {
        let signature = self.sign_transaction(&tx)?;
        Ok(SignedEvmTransaction::new(tx, signature))
    }
}

/// Access list item for EIP-2930/EIP-1559 transactions
#[frb]
#[derive(Debug, Clone)]
pub struct EvmAccessListItem {
    /// The address being accessed
    pub address: String,
    /// The storage keys being accessed (as hex strings)
    pub storage_keys: Vec<String>,
}

#[frb]
impl EvmAccessListItem {
    /// Create a new access list item
    #[frb]
    pub fn new(address: String, storage_keys: Vec<String>) -> Self {
        Self {
            address,
            storage_keys,
        }
    }

    /// Create an access list item with only an address (no storage keys)
    #[frb]
    pub fn address_only(address: String) -> Self {
        Self {
            address,
            storage_keys: Vec::new(),
        }
    }
}

// =============================================================================
// PART 3: UTILITY FUNCTIONS (Convenience API)
// =============================================================================

/// Generate a new BIP39 mnemonic phrase (returns string)
#[frb]
pub fn generate_mnemonic(word_count: u32) -> Result<String, String> {
    let count = match word_count {
        12 => WordCount::Twelve,
        15 => WordCount::Fifteen,
        18 => WordCount::Eighteen,
        21 => WordCount::TwentyOne,
        24 => WordCount::TwentyFour,
        _ => return Err("Invalid word count. Use 12, 15, 18, 21, or 24".to_string()),
    };

    let mnemonic = RustMnemonic::generate(count, Language::English)
        .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;

    Ok(mnemonic.phrase().to_string())
}

/// Create mnemonic from entropy bytes
///
/// Entropy must be 16, 20, 24, 28, or 32 bytes for 12, 15, 18, 21, or 24 words respectively.
#[frb]
pub fn generate_mnemonic_from_entropy(entropy: Vec<u8>) -> Result<String, String> {
    let mnemonic = RustMnemonic::new(&entropy, Language::English)
        .map_err(|e| format!("Failed to create mnemonic from entropy: {}", e))?;
    Ok(mnemonic.phrase().to_string())
}

/// Validate a mnemonic phrase
#[frb]
pub fn validate_mnemonic(phrase: String) -> bool {
    RustMnemonic::from_phrase(&phrase, Language::English).is_ok()
}

/// Convert a mnemonic phrase to a BIP39 seed (64 bytes as hex string)
#[frb(name = "mnemonicPhraseToSeedHex")]
pub fn mnemonic_phrase_to_seed_hex(
    phrase: String,
    passphrase: Option<String>,
) -> Result<String, String> {
    let mnemonic = RustMnemonic::from_phrase(&phrase, Language::English)
        .map_err(|e| format!("Invalid mnemonic: {}", e))?;
    let seed = mnemonic
        .to_seed(&passphrase.unwrap_or_default())
        .map_err(|e| format!("Failed to generate seed: {}", e))?;
    Ok(hex::encode(seed))
}

/// Create a master extended private key from a mnemonic string
#[frb]
pub fn create_master_key(
    mnemonic: String,
    passphrase: Option<String>,
    network: Network,
) -> Result<String, String> {
    let mnemonic = RustMnemonic::from_phrase(&mnemonic, Language::English)
        .map_err(|e| format!("Invalid mnemonic: {}", e))?;

    let master_key =
        RustExtendedPrivateKey::from_mnemonic(&mnemonic, passphrase.as_deref(), network.into())
            .map_err(|e| format!("Failed to create master key: {}", e))?;

    Ok(master_key.to_string())
}

/// Derive a child key from an extended private key using a derivation path
#[frb]
pub fn derive_key(extended_key: String, derivation_path: String) -> Result<String, String> {
    let master_key = RustExtendedPrivateKey::from_str(&extended_key)
        .map_err(|e| format!("Invalid extended key: {}", e))?;

    let path = DerivationPath::from_str(&derivation_path)
        .map_err(|e| format!("Invalid derivation path: {}", e))?;

    let derived_key = master_key
        .derive_path(&path)
        .map_err(|e| format!("Failed to derive key: {}", e))?;

    Ok(derived_key.to_string())
}

/// Get the public key from an extended private key string
#[frb]
pub fn get_public_key(extended_private_key: String) -> Result<String, String> {
    let private_key = RustExtendedPrivateKey::from_str(&extended_private_key)
        .map_err(|e| format!("Invalid extended private key: {}", e))?;

    let public_key = private_key.to_extended_public_key();
    Ok(public_key.to_string())
}

/// Get address from an extended private key at specific index
#[frb]
pub fn get_address(extended_private_key: String, address_index: u32) -> Result<String, String> {
    let private_key = RustExtendedPrivateKey::from_str(&extended_private_key)
        .map_err(|e| format!("Invalid extended private key: {}", e))?;

    // Derive the address key (m/0/address_index)
    let path = DerivationPath::from_str(&format!("m/0/{}", address_index))
        .map_err(|e| format!("Invalid path: {}", e))?;

    let address_key = private_key
        .derive_path(&path)
        .map_err(|e| format!("Failed to derive address: {}", e))?;

    let public_key = address_key.to_extended_public_key();

    // Return the extended public key (you may want to convert to Bitcoin address format)
    Ok(public_key.to_string())
}

/// Create a complete BIP44 wallet and return the account key
#[frb]
pub fn create_bip44_wallet(
    mnemonic: String,
    passphrase: Option<String>,
    account_index: u32,
    network: Network,
) -> Result<WalletResult, String> {
    let mnemonic = RustMnemonic::from_phrase(&mnemonic, Language::English)
        .map_err(|e| format!("Invalid mnemonic: {}", e))?;

    let master_key =
        RustExtendedPrivateKey::from_mnemonic(&mnemonic, passphrase.as_deref(), network.into())
            .map_err(|e| format!("Failed to create master key: {}", e))?;

    // BIP44 path: m/44'/0'/account_index'
    let coin_type = match network {
        Network::BitcoinMainnet => 0,
        Network::BitcoinTestnet => 1,
    };

    let path_str = format!("m/44'/{}'/{}'", coin_type, account_index);
    let path = DerivationPath::from_str(&path_str)
        .map_err(|e| format!("Invalid derivation path: {}", e))?;

    let account_key = master_key
        .derive_path(&path)
        .map_err(|e| format!("Failed to derive account key: {}", e))?;

    Ok(WalletResult {
        success: true,
        message: format!("Wallet created with path: {}", path_str),
        data: Some(account_key.to_string()),
    })
}

/// Create a BIP44 wallet from mnemonic and derive an account (utility function)
#[frb]
pub fn create_bip44_account(
    mnemonic: String,
    passphrase: Option<String>,
    purpose: Purpose,
    coin_type: CoinType,
    account_index: u32,
    network: Network,
) -> Result<String, String> {
    let mut wallet = RustWallet::from_english_mnemonic(
        &mnemonic,
        passphrase.as_deref().unwrap_or(""),
        network.into(),
    )
    .map_err(|e| format!("Failed to create wallet: {}", e))?;

    let account = wallet
        .get_account(purpose.into(), coin_type.into(), account_index)
        .map_err(|e| format!("Failed to get account: {}", e))?;

    Ok(account.extended_key().to_string())
}

/// Derive a BIP44 address from account key
#[frb]
pub fn derive_bip44_address(
    account_key: String,
    chain: Chain,
    address_index: u32,
) -> Result<String, String> {
    let account = RustExtendedPrivateKey::from_str(&account_key)
        .map_err(|e| format!("Invalid account key: {}", e))?;

    let chain_value = match chain {
        Chain::External => 0,
        Chain::Internal => 1,
    };

    let chain_key = account
        .derive_child(ChildNumber::Normal(chain_value))
        .map_err(|e| format!("Failed to derive chain: {}", e))?;

    let address_key = chain_key
        .derive_child(ChildNumber::Normal(address_index))
        .map_err(|e| format!("Failed to derive address: {}", e))?;

    Ok(address_key.to_string())
}

/// Parse a BIP44 path string (e.g., "m/44'/0'/0'/0/0")
#[frb]
pub fn parse_bip44_path(path: String) -> Result<WalletResult, String> {
    let bip44_path =
        RustBip44Path::from_str(&path).map_err(|e| format!("Invalid BIP44 path: {}", e))?;

    let purpose: Purpose = bip44_path.purpose().into();
    let coin_type: CoinType = bip44_path.coin_type().into();
    let chain: Chain = bip44_path.chain().into();

    let info = format!(
        "Purpose: {:?}, Coin: {:?}, Account: {}, Chain: {:?}, Index: {}",
        purpose,
        coin_type,
        bip44_path.account(),
        chain,
        bip44_path.address_index()
    );

    Ok(WalletResult {
        success: true,
        message: "Path parsed successfully".to_string(),
        data: Some(info),
    })
}

/// Get coin type information
#[frb]
pub fn get_coin_info(coin_type: CoinType) -> WalletResult {
    let rust_coin: RustCoinType = coin_type.into();

    let info = format!(
        "Name: {}, Symbol: {}, Index: {}",
        rust_coin.name(),
        rust_coin.symbol(),
        rust_coin.index()
    );

    WalletResult {
        success: true,
        message: "Coin info retrieved".to_string(),
        data: Some(info),
    }
}

/// Get purpose information
#[frb]
pub fn get_purpose_info(purpose: Purpose) -> WalletResult {
    let rust_purpose: RustPurpose = purpose.into();

    let info = format!(
        "Name: {}, Value: {}, Description: {}",
        rust_purpose.name(),
        rust_purpose.value(),
        rust_purpose.description()
    );

    WalletResult {
        success: true,
        message: "Purpose info retrieved".to_string(),
        data: Some(info),
    }
}

// =============================================================================
// PART 4: EVM SIGNING UTILITY FUNCTIONS
// =============================================================================

/// Get the standard gas limit for ETH/BNB transfer
#[frb]
pub fn get_transfer_gas() -> u64 {
    TRANSFER_GAS
}

/// Get the typical gas limit for BEP-20/ERC-20 token transfer
#[frb]
pub fn get_token_transfer_gas() -> u64 {
    TOKEN_TRANSFER_GAS
}

/// Get the number of wei in one gwei (10^9)
#[frb]
pub fn get_gwei_in_wei() -> u64 {
    GWEI
}

/// Get the number of wei in one ether/BNB (10^18)
#[frb]
pub fn get_ether_in_wei() -> u64 {
    ETHER
}

/// Convert gwei to wei string
#[frb]
pub fn gwei_to_wei(gwei: u64) -> String {
    RustWei::from_gwei(gwei).to_string()
}

/// Convert ether to wei string
#[frb]
pub fn ether_to_wei(ether: u64) -> String {
    RustWei::from_ether(ether).to_string()
}

/// Parse an EVM address from hex string
#[frb]
pub fn parse_evm_address(address: String) -> Result<String, String> {
    let addr = RustAddress::from_str(&address).map_err(|e| format!("Invalid address: {}", e))?;
    Ok(addr.to_checksum_string())
}

/// Validate an EVM address checksum
#[frb]
pub fn validate_evm_address_checksum(address: String) -> bool {
    RustAddress::validate_checksum(&address)
}

/// Get chain ID value for a known chain
#[frb]
pub fn get_chain_id_value(chain_id: ChainId) -> u64 {
    let rust_chain: RustChainId = chain_id.into();
    rust_chain.value()
}

/// Get chain name for a chain ID
#[frb]
pub fn get_chain_name(chain_id: ChainId) -> String {
    let rust_chain: RustChainId = chain_id.into();
    rust_chain.name().to_string()
}

/// Check if a chain ID is a testnet
#[frb]
pub fn is_testnet_chain(chain_id: ChainId) -> bool {
    let rust_chain: RustChainId = chain_id.into();
    rust_chain.is_testnet()
}

/// Create an EVM signer from mnemonic and derive address
#[frb]
pub fn create_evm_signer_from_mnemonic(
    mnemonic: String,
    passphrase: Option<String>,
    account_index: u32,
    address_index: u32,
) -> Result<String, String> {
    // Create wallet from mnemonic
    let mut wallet = RustWallet::from_english_mnemonic(
        &mnemonic,
        passphrase.as_deref().unwrap_or(""),
        Network::BitcoinMainnet.into(), // Network doesn't matter for Ethereum addresses
    )
    .map_err(|e| format!("Failed to create wallet: {}", e))?;

    // Get Ethereum account (coin type 60)
    let account = wallet
        .get_account(RustPurpose::BIP44, RustCoinType::Ethereum, account_index)
        .map_err(|e| format!("Failed to get account: {}", e))?;

    // Create signer from account
    let signer = RustBip44Signer::new(&account, address_index)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    Ok(signer.address().to_checksum_string())
}

/// Sign an EIP-1559 transaction and return the raw transaction hex
#[allow(clippy::too_many_arguments)]
#[frb]
pub fn sign_eip1559_transaction(
    private_key_hex: String,
    chain_id: ChainId,
    nonce: u64,
    to: String,
    value_wei: String,
    gas_limit: u64,
    max_priority_fee_gwei: u64,
    max_fee_gwei: u64,
    data_hex: Option<String>,
) -> Result<String, String> {
    // Parse private key
    let hex_str = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(&private_key_hex);
    let key_bytes = hex::decode(hex_str).map_err(|e| format!("Invalid private key hex: {}", e))?;

    if key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let signer = RustBip44Signer::from_private_key(&key_arr)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    // Parse recipient address
    let to_addr = RustAddress::from_str(&to).map_err(|e| format!("Invalid to address: {}", e))?;

    // Parse value
    let value: RustWei = value_wei
        .parse()
        .map_err(|e| format!("Invalid value: {}", e))?;

    // Parse data
    let data = if let Some(ref hex) = data_hex {
        let hex_str = hex.strip_prefix("0x").unwrap_or(hex);
        if hex_str.is_empty() {
            Vec::new()
        } else {
            hex::decode(hex_str).map_err(|e| format!("Invalid data hex: {}", e))?
        }
    } else {
        Vec::new()
    };

    // Build transaction
    let tx = RustEip1559Transaction::builder()
        .chain_id(chain_id.into())
        .nonce(nonce)
        .to(to_addr)
        .value(value)
        .gas_limit(gas_limit)
        .max_priority_fee_per_gas(RustWei::from_gwei(max_priority_fee_gwei))
        .max_fee_per_gas(RustWei::from_gwei(max_fee_gwei))
        .data(data)
        .build()
        .map_err(|e| format!("Failed to build transaction: {}", e))?;

    // Sign transaction
    let signature = signer
        .sign_transaction(&tx)
        .map_err(|e| format!("Failed to sign transaction: {}", e))?;

    // Create signed transaction
    let signed = RustSignedTransaction::new(tx, signature);

    Ok(signed.to_raw_transaction())
}

/// Recover signer address from a signature and message hash
#[frb]
pub fn recover_signer_address(hash_hex: String, signature_hex: String) -> Result<String, String> {
    // Parse hash
    let hash_str = hash_hex.strip_prefix("0x").unwrap_or(&hash_hex);
    let hash_bytes = hex::decode(hash_str).map_err(|e| format!("Invalid hash hex: {}", e))?;

    if hash_bytes.len() != 32 {
        return Err("Hash must be 32 bytes".to_string());
    }

    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash_bytes);

    // Parse signature (65 bytes: r || s || v)
    let sig_str = signature_hex.strip_prefix("0x").unwrap_or(&signature_hex);
    let sig_bytes = hex::decode(sig_str).map_err(|e| format!("Invalid signature hex: {}", e))?;

    let signature = RustSignature::from_bytes(&sig_bytes)
        .ok_or_else(|| "Invalid signature (expected 65 bytes)".to_string())?;

    // Recover signer
    let address = rust_recover_signer(&hash_arr, &signature)
        .map_err(|e| format!("Failed to recover signer: {}", e))?;

    Ok(address.to_checksum_string())
}

/// Derive EVM address from extended private key at specific path
#[frb]
pub fn derive_evm_address(
    extended_private_key: String,
    chain_index: u32,
    address_index: u32,
) -> Result<String, String> {
    let account_key = RustExtendedPrivateKey::from_str(&extended_private_key)
        .map_err(|e| format!("Invalid extended private key: {}", e))?;

    // Derive chain/address_index
    let chain_key = account_key
        .derive_child(ChildNumber::Normal(chain_index))
        .map_err(|e| format!("Failed to derive chain: {}", e))?;

    let address_key = chain_key
        .derive_child(ChildNumber::Normal(address_index))
        .map_err(|e| format!("Failed to derive address: {}", e))?;

    // Get private key bytes
    let private_key_bytes = address_key.private_key().to_bytes();

    // Create signer to get address
    let signer = RustBip44Signer::from_private_key(&private_key_bytes)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    Ok(signer.address().to_checksum_string())
}

/// Get EVM address from private key hex
#[frb]
pub fn get_evm_address_from_private_key(private_key_hex: String) -> Result<String, String> {
    let hex_str = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(&private_key_hex);
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid private key hex: {}", e))?;

    if bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&bytes);

    let signer = RustBip44Signer::from_private_key(&key_arr)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    Ok(signer.address().to_checksum_string())
}

// =============================================================================
// PART 5: SIMPLE UTILITY FUNCTIONS
// =============================================================================

/// Simple health check function
#[frb]
pub fn health_check() -> String {
    "KhodPay Wallet Bridge is working!".to_string()
}

/// Add two numbers (example from the article)
#[frb]
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

// =============================================================================
// PART 6: WPGP — EIP-712 + ERC-4337 BRIDGE
// =============================================================================

/// WPGP PaymentIntent — the structured data signed by the business via EIP-712.
///
/// All fields are passed as strings to avoid Dart integer overflow on u64/u128 values.
#[frb]
#[derive(Debug, Clone)]
pub struct WpgpPaymentIntent {
    /// Unique bytes32 business slot identifier (hex, with or without 0x prefix).
    /// Matches PaymentIntent.businessId on-chain; the business wallet address is
    /// NOT part of the struct — it is resolved from the registry by the contract.
    pub business_id: String,
    /// Actual payment recipient address (EIP-55 checksummed hex)
    pub recipient: String,
    /// ERC-20 token contract address (EIP-55 checksummed hex, address(0) for native)
    pub token: String,
    /// Total payment amount in token's smallest unit (decimal string — uint256)
    pub amount: String,
    /// Expiration timestamp in Unix seconds (decimal string — uint256)
    pub deadline: String,
    /// Business invoice reference, 32-byte hex (with or without 0x prefix)
    pub invoice_id: String,
    /// Replay-protection nonce for this businessId (decimal string — uint256)
    pub nonce: String,
}

/// Internal EIP-712 implementation for WpgpPaymentIntent.
struct WpgpPaymentIntentTyped {
    business_id: [u8; 32],
    recipient: RustAddress,
    token: RustAddress,
    amount: u128,
    deadline: u128,
    invoice_id: [u8; 32],
    nonce: u128,
}

impl Eip712Type for WpgpPaymentIntentTyped {
    fn type_string() -> &'static str {
        // Matches the on-chain WPGP PaymentIntent type (IWPGP.sol).
        // The business owner address is NOT in the struct — it is resolved
        // from the registry by the contract.
        "PaymentIntent(bytes32 businessId,address recipient,address token,uint256 amount,uint256 deadline,bytes32 invoiceId,uint256 nonce)"
    }

    fn encode_data(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_bytes32(self.business_id));
        buf.extend_from_slice(&encode_address(&self.recipient));
        buf.extend_from_slice(&encode_address(&self.token));
        // uint256 encoded as 32 BE bytes (u128 fits in the upper half)
        let mut amount_bytes = [0u8; 32];
        amount_bytes[16..].copy_from_slice(&self.amount.to_be_bytes());
        buf.extend_from_slice(&amount_bytes);
        let mut deadline_bytes = [0u8; 32];
        deadline_bytes[16..].copy_from_slice(&self.deadline.to_be_bytes());
        buf.extend_from_slice(&deadline_bytes);
        buf.extend_from_slice(&encode_bytes32(self.invoice_id));
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[16..].copy_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&nonce_bytes);
        buf
    }
}

/// Parse a WpgpPaymentIntent (from Dart) into the internal typed struct.
///
/// `business_id`, `invoice_id` — hex bytes32 (with or without 0x prefix).
/// `amount`, `deadline`, `nonce` — decimal strings representing uint256.
fn parse_payment_intent(intent: &WpgpPaymentIntent) -> Result<WpgpPaymentIntentTyped, String> {
    // business_id: bytes32
    let bid_hex = intent.business_id.strip_prefix("0x").unwrap_or(&intent.business_id);
    let bid_bytes = hex::decode(bid_hex)
        .map_err(|e| format!("Invalid business_id hex: {}", e))?;
    if bid_bytes.len() != 32 {
        return Err(format!("business_id must be 32 bytes, got {}", bid_bytes.len()));
    }
    let mut business_id = [0u8; 32];
    business_id.copy_from_slice(&bid_bytes);

    let recipient = RustAddress::from_str(&intent.recipient)
        .map_err(|e| format!("Invalid recipient address: {}", e))?;
    let token = RustAddress::from_str(&intent.token)
        .map_err(|e| format!("Invalid token address: {}", e))?;

    // amount, deadline, nonce: decimal string → u128
    let amount: u128 = intent.amount.parse()
        .map_err(|e| format!("Invalid amount (expected decimal uint256): {}", e))?;
    let deadline: u128 = intent.deadline.parse()
        .map_err(|e| format!("Invalid deadline (expected decimal uint256): {}", e))?;
    let nonce: u128 = intent.nonce.parse()
        .map_err(|e| format!("Invalid nonce (expected decimal uint256): {}", e))?;

    // invoice_id: bytes32
    let inv_hex = intent.invoice_id.strip_prefix("0x").unwrap_or(&intent.invoice_id);
    let inv_bytes = hex::decode(inv_hex)
        .map_err(|e| format!("Invalid invoice_id hex: {}", e))?;
    if inv_bytes.len() != 32 {
        return Err(format!("invoice_id must be 32 bytes, got {}", inv_bytes.len()));
    }
    let mut invoice_id = [0u8; 32];
    invoice_id.copy_from_slice(&inv_bytes);

    Ok(WpgpPaymentIntentTyped {
        business_id,
        recipient,
        token,
        amount,
        deadline,
        invoice_id,
        nonce,
    })
}

/// Build an `Eip712Domain` from Flutter-supplied strings.
fn parse_eip712_domain(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: Option<&str>,
) -> Result<Eip712Domain, String> {
    match verifying_contract {
        Some(addr_str) => {
            let addr = RustAddress::from_str(addr_str)
                .map_err(|e| format!("Invalid verifying_contract: {}", e))?;
            Ok(Eip712Domain::new(name, version, chain_id, addr))
        }
        None => Ok(Eip712Domain::builder()
            .name(name)
            .version(version)
            .chain_id(chain_id)
            .build()),
    }
}

/// Business-side: sign a WPGP PaymentIntent with EIP-712.
///
/// Returns the 65-byte signature as a `0x`-prefixed hex string.
///
/// Parameters:
/// - `private_key_hex`: 32-byte private key as hex (with or without `0x`)
/// - `intent`: the payment intent fields
/// - `domain_name`: EIP-712 domain name (e.g. `"WPGPPaymentGateway"`)
/// - `domain_version`: EIP-712 domain version (e.g. `"1"`)
/// - `chain_id`: numeric chain ID (e.g. `56` for BSC)
/// - `verifying_contract`: optional gateway contract address for domain separation
#[frb]
pub fn wpgp_sign_payment_intent(
    private_key_hex: String,
    intent: WpgpPaymentIntent,
    domain_name: String,
    domain_version: String,
    chain_id: u64,
    verifying_contract: Option<String>,
) -> Result<String, String> {
    let hex_str = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(&private_key_hex);
    let key_bytes = hex::decode(hex_str).map_err(|e| format!("Invalid private key hex: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let signer = RustBip44Signer::from_private_key(&key_arr)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    let domain = parse_eip712_domain(
        &domain_name,
        &domain_version,
        chain_id,
        verifying_contract.as_deref(),
    )?;
    let typed = parse_payment_intent(&intent)?;
    let sig =
        sign_typed_data(&signer, &domain, &typed).map_err(|e| format!("Signing failed: {}", e))?;

    Ok(format!(
        "0x{}{}{}",
        hex::encode(sig.r),
        hex::encode(sig.s),
        hex::encode([sig.v])
    ))
}

/// Business-side: verify a WPGP PaymentIntent EIP-712 signature.
///
/// Returns `true` if the signature was produced by `expected_signer`.
///
/// - `signature_hex`: 65-byte signature as hex (with or without `0x`)
/// - `expected_signer`: the address that should have signed
#[frb]
pub fn wpgp_verify_payment_signature(
    intent: WpgpPaymentIntent,
    domain_name: String,
    domain_version: String,
    chain_id: u64,
    verifying_contract: Option<String>,
    signature_hex: String,
    expected_signer: String,
) -> Result<bool, String> {
    let domain = parse_eip712_domain(
        &domain_name,
        &domain_version,
        chain_id,
        verifying_contract.as_deref(),
    )?;
    let typed = parse_payment_intent(&intent)?;

    let sig_str = signature_hex.strip_prefix("0x").unwrap_or(&signature_hex);
    let sig_bytes = hex::decode(sig_str).map_err(|e| format!("Invalid signature hex: {}", e))?;
    let sig = RustSignature::from_bytes(&sig_bytes)
        .ok_or_else(|| "Invalid signature (expected 65 bytes)".to_string())?;

    let expected = RustAddress::from_str(&expected_signer)
        .map_err(|e| format!("Invalid expected_signer address: {}", e))?;

    verify_typed_data(&domain, &typed, &sig, expected)
        .map_err(|e| format!("Verification failed: {}", e))
}

/// Low-level EIP-712 signing over an arbitrary struct hash.
///
/// Signs `keccak256(domainSeparator || structHash)` with the given private key.
///
/// Parameters:
/// - `private_key_hex`: 32-byte private key as hex (with or without `0x`)
/// - `domain_name`, `domain_version`, `chain_id`, `verifying_contract`: EIP-712 domain fields
/// - `struct_hash_hex`: 32-byte struct hash as hex (with or without `0x`)
///
/// Returns the 65-byte signature as a `0x`-prefixed hex string.
#[frb]
pub fn eip712_sign(
    private_key_hex: String,
    domain_name: String,
    domain_version: String,
    chain_id: u64,
    verifying_contract: Option<String>,
    struct_hash_hex: String,
) -> Result<String, String> {
    let hex_str = private_key_hex.strip_prefix("0x").unwrap_or(&private_key_hex);
    let key_bytes = hex::decode(hex_str)
        .map_err(|e| format!("Invalid private key hex: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let sh_str = struct_hash_hex.strip_prefix("0x").unwrap_or(&struct_hash_hex);
    let sh_bytes = hex::decode(sh_str)
        .map_err(|e| format!("Invalid struct_hash_hex: {}", e))?;
    if sh_bytes.len() != 32 {
        return Err(format!("struct_hash must be 32 bytes, got {}", sh_bytes.len()));
    }
    let mut struct_hash = [0u8; 32];
    struct_hash.copy_from_slice(&sh_bytes);

    let signer = RustBip44Signer::from_private_key(&key_arr)
        .map_err(|e| format!("Failed to create signer: {}", e))?;
    let domain = parse_eip712_domain(
        &domain_name,
        &domain_version,
        chain_id,
        verifying_contract.as_deref(),
    )?;

    // Build the EIP-712 digest manually: keccak256("" || domainSeparator || structHash)
    let domain_separator = domain.domain_separator();
    let mut digest_input = [0u8; 66];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    digest_input[2..34].copy_from_slice(&domain_separator);
    digest_input[34..66].copy_from_slice(&struct_hash);

    use sha3::{Digest, Keccak256};
    let digest: [u8; 32] = Keccak256::digest(&digest_input).into();

    let sig = signer.sign_hash(&digest)
        .map_err(|e| format!("Signing failed: {}", e))?;
    Ok(format!(
        "0x{}{}{}",
        hex::encode(sig.r),
        hex::encode(sig.s),
        hex::encode([sig.v])
    ))
}

/// Low-level EIP-712 signature verification over an arbitrary struct hash.
///
/// Verifies that `keccak256(domainSeparator || structHash)` was signed by `expected_signer`.
///
/// Parameters:
/// - `domain_name`, `domain_version`, `chain_id`, `verifying_contract`: EIP-712 domain fields
/// - `struct_hash_hex`: 32-byte struct hash as hex (with or without `0x`)
/// - `signature_hex`: 65-byte signature as hex (with or without `0x`)
/// - `expected_signer`: EIP-55 checksummed address of the expected signer
///
/// Returns `true` if the signature is valid and was produced by `expected_signer`.
#[frb]
pub fn eip712_verify(
    domain_name: String,
    domain_version: String,
    chain_id: u64,
    verifying_contract: Option<String>,
    struct_hash_hex: String,
    signature_hex: String,
    expected_signer: String,
) -> Result<bool, String> {
    let sh_str = struct_hash_hex.strip_prefix("0x").unwrap_or(&struct_hash_hex);
    let sh_bytes = hex::decode(sh_str)
        .map_err(|e| format!("Invalid struct_hash_hex: {}", e))?;
    if sh_bytes.len() != 32 {
        return Err(format!("struct_hash must be 32 bytes, got {}", sh_bytes.len()));
    }
    let mut struct_hash = [0u8; 32];
    struct_hash.copy_from_slice(&sh_bytes);

    let sig_str = signature_hex.strip_prefix("0x").unwrap_or(&signature_hex);
    let sig_bytes = hex::decode(sig_str)
        .map_err(|e| format!("Invalid signature hex: {}", e))?;
    let sig = RustSignature::from_bytes(&sig_bytes)
        .ok_or_else(|| "Invalid signature (expected 65 bytes)".to_string())?;

    let expected = RustAddress::from_str(&expected_signer)
        .map_err(|e| format!("Invalid expected_signer address: {}", e))?;

    let domain = parse_eip712_domain(
        &domain_name,
        &domain_version,
        chain_id,
        verifying_contract.as_deref(),
    )?;

    let domain_separator = domain.domain_separator();
    let mut digest_input = [0u8; 66];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    digest_input[2..34].copy_from_slice(&domain_separator);
    digest_input[34..66].copy_from_slice(&struct_hash);

    use sha3::{Digest, Keccak256};
    let digest: [u8; 32] = Keccak256::digest(&digest_input).into();

    let recovered = khodpay_signing::recover_signer(&digest, &sig)
        .map_err(|e| format!("Recovery failed: {}", e))?;

    Ok(recovered == expected)
}

/// ERC-4337 UserOperation fields for the Flutter layer.
///
/// All gas values are decimal strings to avoid Dart integer overflow.
#[frb]
#[derive(Debug, Clone)]
pub struct WpgpUserOperation {
    /// Smart account address (sender)
    pub sender: String,
    /// Anti-replay nonce
    pub nonce: u64,
    /// ABI-encoded contract call (hex, with or without `0x`)
    pub call_data_hex: String,
    /// verificationGasLimit packed with callGasLimit (decimal string)
    pub verification_gas_limit: u64,
    /// callGasLimit (decimal string)
    pub call_gas_limit: u64,
    /// Pre-verification gas
    pub pre_verification_gas: u64,
    /// maxPriorityFeePerGas in wei (decimal string)
    pub max_priority_fee_per_gas: String,
    /// maxFeePerGas in wei (decimal string)
    pub max_fee_per_gas: String,
    /// Optional paymaster address (empty string = no paymaster)
    pub paymaster: String,
    /// Optional paymaster data (hex, with or without `0x`)
    pub paymaster_data_hex: String,
}

/// User-side: build and sign an ERC-4337 v0.7 PackedUserOperation.
///
/// Returns the 65-byte signature as a `0x`-prefixed hex string.
///
/// - `entry_point`: EntryPoint contract address (defaults to canonical v0.7 if empty)
/// - `chain_id`: numeric chain ID
#[frb]
pub fn wpgp_sign_user_operation(
    private_key_hex: String,
    user_op: WpgpUserOperation,
    entry_point: String,
    chain_id: u64,
) -> Result<String, String> {
    let hex_str = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(&private_key_hex);
    let key_bytes = hex::decode(hex_str).map_err(|e| format!("Invalid private key hex: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let signer = RustBip44Signer::from_private_key(&key_arr)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    let packed_op = build_packed_user_op(&user_op)?;

    let ep_str = if entry_point.is_empty() {
        ENTRY_POINT_V07
    } else {
        entry_point.as_str()
    };
    let ep_addr =
        RustAddress::from_str(ep_str).map_err(|e| format!("Invalid entry_point address: {}", e))?;

    let sig = sign_user_operation(&signer, &packed_op, ep_addr, chain_id)
        .map_err(|e| format!("Signing failed: {}", e))?;

    Ok(format!(
        "0x{}{}{}",
        hex::encode(sig.r),
        hex::encode(sig.s),
        hex::encode([sig.v])
    ))
}

/// User-side: verify an ERC-4337 UserOperation signature.
///
/// Returns `true` if the signature was produced by `expected_signer`.
#[frb]
pub fn wpgp_verify_user_operation(
    user_op: WpgpUserOperation,
    entry_point: String,
    chain_id: u64,
    signature_hex: String,
    expected_signer: String,
) -> Result<bool, String> {
    let packed_op = build_packed_user_op(&user_op)?;

    let ep_str = if entry_point.is_empty() {
        ENTRY_POINT_V07
    } else {
        entry_point.as_str()
    };
    let ep_addr =
        RustAddress::from_str(ep_str).map_err(|e| format!("Invalid entry_point address: {}", e))?;

    let sig_str = signature_hex.strip_prefix("0x").unwrap_or(&signature_hex);
    let sig_bytes = hex::decode(sig_str).map_err(|e| format!("Invalid signature hex: {}", e))?;
    let sig = RustSignature::from_bytes(&sig_bytes)
        .ok_or_else(|| "Invalid signature (expected 65 bytes)".to_string())?;

    let expected = RustAddress::from_str(&expected_signer)
        .map_err(|e| format!("Invalid expected_signer address: {}", e))?;

    verify_user_operation(&packed_op, ep_addr, chain_id, &sig, expected)
        .map_err(|e| format!("Verification failed: {}", e))
}

/// Compute the ERC-4337 userOpHash without signing (useful for debugging).
///
/// Returns the 32-byte hash as a `0x`-prefixed hex string.
#[frb]
pub fn wpgp_user_operation_hash(
    user_op: WpgpUserOperation,
    entry_point: String,
    chain_id: u64,
) -> Result<String, String> {
    use khodpay_signing::erc4337::hash_user_operation;

    let packed_op = build_packed_user_op(&user_op)?;

    let ep_str = if entry_point.is_empty() {
        ENTRY_POINT_V07
    } else {
        entry_point.as_str()
    };
    let ep_addr =
        RustAddress::from_str(ep_str).map_err(|e| format!("Invalid entry_point address: {}", e))?;

    let hash = hash_user_operation(&packed_op, ep_addr, chain_id);
    Ok(format!("0x{}", hex::encode(hash)))
}

/// EOA path: build a signed EIP-1559 transaction that calls the payment gateway directly.
///
/// Returns the raw transaction as a `0x`-prefixed hex string ready for `eth_sendRawTransaction`.
///
/// - `call_data_hex`: ABI-encoded `executePayment(...)` calldata
/// - `gateway_address`: the PaymentGateway contract address
/// - `gas_limit`: recommended ~300_000 for a payment gateway call
#[allow(clippy::too_many_arguments)]
#[frb]
pub fn wpgp_build_eoa_transaction(
    private_key_hex: String,
    chain_id: ChainId,
    nonce: u64,
    gateway_address: String,
    call_data_hex: String,
    gas_limit: u64,
    max_priority_fee_gwei: u64,
    max_fee_gwei: u64,
) -> Result<String, String> {
    let hex_str = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(&private_key_hex);
    let key_bytes = hex::decode(hex_str).map_err(|e| format!("Invalid private key hex: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let signer = RustBip44Signer::from_private_key(&key_arr)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    let gateway = RustAddress::from_str(&gateway_address)
        .map_err(|e| format!("Invalid gateway_address: {}", e))?;

    let data_str = call_data_hex.strip_prefix("0x").unwrap_or(&call_data_hex);
    let data = if data_str.is_empty() {
        Vec::new()
    } else {
        hex::decode(data_str).map_err(|e| format!("Invalid call_data_hex: {}", e))?
    };

    let tx = RustEip1559Transaction::builder()
        .chain_id(chain_id.into())
        .nonce(nonce)
        .to(gateway)
        .value(RustWei::ZERO)
        .gas_limit(gas_limit)
        .max_priority_fee_per_gas(RustWei::from_gwei(max_priority_fee_gwei))
        .max_fee_per_gas(RustWei::from_gwei(max_fee_gwei))
        .data(data)
        .build()
        .map_err(|e| format!("Failed to build transaction: {}", e))?;

    let sig = signer
        .sign_transaction(&tx)
        .map_err(|e| format!("Signing failed: {}", e))?;

    Ok(RustSignedTransaction::new(tx, sig).to_raw_transaction())
}

/// Returns the canonical ERC-4337 v0.7 EntryPoint address.
#[frb]
pub fn wpgp_entry_point_v07() -> String {
    ENTRY_POINT_V07.to_string()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn build_packed_user_op(user_op: &WpgpUserOperation) -> Result<PackedUserOperation, String> {
    let sender = RustAddress::from_str(&user_op.sender)
        .map_err(|e| format!("Invalid sender address: {}", e))?;

    let call_data_str = user_op
        .call_data_hex
        .strip_prefix("0x")
        .unwrap_or(&user_op.call_data_hex);
    let call_data = if call_data_str.is_empty() {
        Vec::new()
    } else {
        hex::decode(call_data_str).map_err(|e| format!("Invalid call_data_hex: {}", e))?
    };

    let max_priority: u128 = user_op
        .max_priority_fee_per_gas
        .parse()
        .map_err(|e| format!("Invalid max_priority_fee_per_gas: {}", e))?;
    let max_fee: u128 = user_op
        .max_fee_per_gas
        .parse()
        .map_err(|e| format!("Invalid max_fee_per_gas: {}", e))?;

    let mut builder = PackedUserOperation::builder()
        .sender(sender)
        .nonce(user_op.nonce.into())
        .call_data(call_data)
        .account_gas_limits(
            user_op.verification_gas_limit.into(),
            user_op.call_gas_limit.into(),
        )
        .pre_verification_gas(user_op.pre_verification_gas.into())
        .gas_fees(max_priority, max_fee);

    if !user_op.paymaster.is_empty() {
        let pm_addr = RustAddress::from_str(&user_op.paymaster)
            .map_err(|e| format!("Invalid paymaster address: {}", e))?;
        let pm_data_str = user_op
            .paymaster_data_hex
            .strip_prefix("0x")
            .unwrap_or(&user_op.paymaster_data_hex);
        let pm_data = if pm_data_str.is_empty() {
            Vec::new()
        } else {
            hex::decode(pm_data_str).map_err(|e| format!("Invalid paymaster_data_hex: {}", e))?
        };
        builder = builder.paymaster(pm_addr, pm_data);
    }

    builder
        .build()
        .map_err(|e| format!("Failed to build UserOperation: {}", e))
}

// =============================================================================
// MPC OOP session wrappers (DkgSession, SigningSession)
//
// Result structs returned by advance()
// =============================================================================

/// Result of one `advance()` call on [`MpcDkgSession`].
///
/// Whenever `next_payload` is set, send it to the server and pass the server's
/// reply to the next `advance()`. Send it even when `is_complete` is `true`:
/// the server may still need this device's last messages to finish.
///
/// If `is_complete` is `true`, `device_share`, `recovery_backup` and
/// `wallet_address` are populated.
#[frb]
#[derive(Debug, Clone)]
pub struct MpcDkgAdvanceResult {
    /// `true` when the DKG ceremony has completed.
    pub is_complete: bool,
    /// The payload to forward to the server for the next round, even when
    /// `is_complete` is `true`: the server may still need it to finish.
    pub next_payload: Option<Vec<u8>>,
    /// The device-side key share (opaque bytes).
    /// Populated only when `is_complete` is `true`.
    /// Store under `SecureStorageService` key `mpc_device_share_v1`.
    pub device_share: Option<Vec<u8>>,
    /// The recovery share, already encrypted with the user's passphrase. Safe
    /// to upload to the user's Google Drive app-data folder. The unencrypted
    /// recovery share never leaves Rust.
    /// Populated only when `is_complete` is `true`.
    pub recovery_backup: Option<Vec<u8>>,
    /// EIP-55 checksummed EVM wallet address derived from the joint public key.
    /// Populated only when `is_complete` is `true`.
    pub wallet_address: Option<String>,
}

/// Result of one `advance()` call on [`MpcSigningSession`].
///
/// Whenever `next_payload` is set, send it to the server and pass the server's
/// reply to the next `advance()`, even when `is_complete` is `true`. When
/// `is_complete` is `true`, `signature` contains the 65-byte EVM signature
/// (`r || s || v`, with `v` equal to 0 or 1).
#[frb]
#[derive(Debug, Clone)]
pub struct MpcSigningAdvanceResult {
    /// `true` when the signing ceremony has completed.
    pub is_complete: bool,
    /// The payload to forward to the server for the next round.
    /// `None` when `is_complete` is `true`.
    pub next_payload: Option<Vec<u8>>,
    /// 65-byte EVM signature (`r || s || v`).
    /// Populated only when `is_complete` is `true`.
    pub signature: Option<Vec<u8>>,
}

// =============================================================================
// MpcDkgSession
// =============================================================================


/// Longest session id accepted from the server.
const MPC_MAX_SESSION_ID_LEN: usize = 128;

fn mpc_validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty() || session_id.len() > MPC_MAX_SESSION_ID_LEN {
        return Err(format!(
            "session_id must be 1 to {MPC_MAX_SESSION_ID_LEN} bytes, got {}",
            session_id.len()
        ));
    }
    Ok(())
}

/// Joins the messages held back at `create` with those from the latest step and
/// encodes them. `None` when there is nothing to send.
fn mpc_take_payload(
    held: &mut Vec<WireMessage>,
    produced: Vec<WireMessage>,
) -> Result<Option<Vec<u8>>, String> {
    let mut batch = std::mem::take(held);
    batch.extend(produced);
    if batch.is_empty() {
        return Ok(None);
    }
    encode_batch(&batch)
        .map(Some)
        .map_err(|e: TransportError| e.to_string())
}

/// Generates the Paillier primes needed by the aux-info phase of key
/// generation.
///
/// **Slow** (seconds on a desktop, longer on a phone) and needs no network, so
/// run it ahead of time on a background isolate. The returned bytes are secret:
/// keep them in secure storage and pass them to [`MpcDkgSession::create`], which
/// uses them once. Use fresh primes for every key generation.
#[frb]
pub fn mpc_generate_primes() -> Result<Vec<u8>, String> {
    serde_json::to_vec(&aux_info::generate_primes()).map_err(|e| e.to_string())
}

fn mpc_parse_primes(bytes: &[u8]) -> Result<Primes, String> {
    serde_json::from_slice(bytes).map_err(|_| "primes bytes are not valid".to_string())
}

// ── Recovery backup ──────────────────────────────────────────────────────────
//
// The recovery share (party 2 of the 2-of-3 wallet) is encrypted with a key
// derived from the user's passphrase, then stored by the app on the user's
// Google Drive. Neither Google nor the signer server can open it: they never
// see the passphrase. Anyone who holds both this backup and the passphrase,
// plus any one other share, can sign, so the passphrase is the protection.
//
// Layout (all integers big endian):
//   "KPRB" | version (1) | memory KiB (4) | iterations (4) | parallelism (4)
//   | salt (16) | nonce (12) | address length (1) | wallet address | ciphertext
// The whole header up to the ciphertext is authenticated as AES-GCM
// associated data, so the wallet address and the KDF cost cannot be changed
// without detection.

/// Shortest passphrase accepted, in characters.
pub const MPC_MIN_PASSPHRASE_CHARS: usize = 10;
const MPC_MAX_PASSPHRASE_BYTES: usize = 1024;
const MPC_BACKUP_MAGIC: &[u8; 4] = b"KPRB";
const MPC_BACKUP_VERSION: u8 = 1;
const MPC_BACKUP_SALT_LEN: usize = 16;
const MPC_BACKUP_NONCE_LEN: usize = 12;

/// Argon2id cost of a backup.
#[derive(Debug, Clone, Copy)]
struct MpcKdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// 64 MiB, 3 passes, one lane. Chosen to be slow for an attacker and still
/// tolerable on a phone (about a second).
const MPC_BACKUP_KDF_PARAMS: MpcKdfParams = MpcKdfParams {
    memory_kib: 64 * 1024,
    iterations: 3,
    parallelism: 1,
};

// Bounds applied to the parameters read from a backup, so that a tampered
// header cannot make the device allocate unbounded memory or spin for long.
const MPC_KDF_MIN_MEMORY_KIB: u32 = 8;
const MPC_KDF_MAX_MEMORY_KIB: u32 = 256 * 1024;
const MPC_KDF_MAX_ITERATIONS: u32 = 10;
const MPC_KDF_MAX_PARALLELISM: u32 = 4;

fn mpc_check_passphrase(passphrase: &str) -> Result<(), String> {
    if passphrase.chars().count() < MPC_MIN_PASSPHRASE_CHARS {
        return Err(format!(
            "passphrase must be at least {MPC_MIN_PASSPHRASE_CHARS} characters"
        ));
    }
    if passphrase.len() > MPC_MAX_PASSPHRASE_BYTES {
        return Err(format!("passphrase must be at most {MPC_MAX_PASSPHRASE_BYTES} bytes"));
    }
    Ok(())
}

fn mpc_derive_backup_key(
    passphrase: &str,
    salt: &[u8],
    params: MpcKdfParams,
) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    if params.memory_kib < MPC_KDF_MIN_MEMORY_KIB
        || params.memory_kib > MPC_KDF_MAX_MEMORY_KIB
        || params.iterations == 0
        || params.iterations > MPC_KDF_MAX_ITERATIONS
        || params.parallelism == 0
        || params.parallelism > MPC_KDF_MAX_PARALLELISM
    {
        return Err("backup uses unsupported key-derivation settings".into());
    }
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| format!("invalid key-derivation settings: {e}"))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypts the plain bytes of a recovery share for storage.
fn mpc_encrypt_recovery_share(
    share: &[u8],
    wallet_address: &str,
    passphrase: &str,
    params: MpcKdfParams,
) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use rand::RngCore;
    use zeroize::Zeroize;

    mpc_check_passphrase(passphrase)?;
    if wallet_address.is_empty() || wallet_address.len() > u8::MAX as usize {
        return Err("wallet address has an invalid length".into());
    }

    let mut salt = [0u8; MPC_BACKUP_SALT_LEN];
    let mut nonce = [0u8; MPC_BACKUP_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut header = Vec::with_capacity(48 + wallet_address.len());
    header.extend_from_slice(MPC_BACKUP_MAGIC);
    header.push(MPC_BACKUP_VERSION);
    header.extend_from_slice(&params.memory_kib.to_be_bytes());
    header.extend_from_slice(&params.iterations.to_be_bytes());
    header.extend_from_slice(&params.parallelism.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.push(wallet_address.len() as u8);
    header.extend_from_slice(wallet_address.as_bytes());

    let mut key = mpc_derive_backup_key(passphrase, &salt, params)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: share,
                aad: &header,
            },
        )
        .map_err(|_| "could not encrypt the recovery share".to_string())?;

    header.extend_from_slice(&ciphertext);
    Ok(header)
}

/// The parts of a backup that are readable without the passphrase.
struct MpcBackupHeader<'a> {
    params: MpcKdfParams,
    salt: &'a [u8],
    nonce: &'a [u8],
    wallet_address: String,
    /// The header bytes, which are the associated data of the encryption.
    aad: &'a [u8],
    ciphertext: &'a [u8],
}

fn mpc_parse_backup(backup: &[u8]) -> Result<MpcBackupHeader<'_>, String> {
    const BAD: &str = "not a KhodPay recovery backup";
    let fixed = 4 + 1 + 12 + MPC_BACKUP_SALT_LEN + MPC_BACKUP_NONCE_LEN + 1;
    if backup.len() < fixed || &backup[..4] != MPC_BACKUP_MAGIC {
        return Err(BAD.into());
    }
    if backup[4] != MPC_BACKUP_VERSION {
        return Err(format!("unsupported backup version {}", backup[4]));
    }
    let word = |at: usize| u32::from_be_bytes(backup[at..at + 4].try_into().expect("4 bytes"));
    let params = MpcKdfParams {
        memory_kib: word(5),
        iterations: word(9),
        parallelism: word(13),
    };
    let salt = &backup[17..17 + MPC_BACKUP_SALT_LEN];
    let nonce_at = 17 + MPC_BACKUP_SALT_LEN;
    let nonce = &backup[nonce_at..nonce_at + MPC_BACKUP_NONCE_LEN];
    let len_at = nonce_at + MPC_BACKUP_NONCE_LEN;
    let address_len = backup[len_at] as usize;
    let header_end = len_at + 1 + address_len;
    if address_len == 0 || backup.len() <= header_end {
        return Err(BAD.into());
    }
    let wallet_address = std::str::from_utf8(&backup[len_at + 1..header_end])
        .map_err(|_| BAD.to_string())?
        .to_owned();
    Ok(MpcBackupHeader {
        params,
        salt,
        nonce,
        wallet_address,
        aad: &backup[..header_end],
        ciphertext: &backup[header_end..],
    })
}

/// Opens a backup and returns the plain recovery share bytes and the wallet
/// address recorded in it. The share is checked to be the recovery share of
/// that wallet.
fn mpc_decrypt_recovery_backup(
    backup: &[u8],
    passphrase: &str,
) -> Result<(Vec<u8>, String), String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use zeroize::Zeroize;

    let parsed = mpc_parse_backup(backup)?;
    let mut key = mpc_derive_backup_key(passphrase, parsed.salt, parsed.params)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();
    // The same message for a wrong passphrase and for damaged data, so it does
    // not tell an attacker which one it was.
    let plain = cipher
        .decrypt(
            Nonce::from_slice(parsed.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: parsed.aad,
            },
        )
        .map_err(|_| "wrong passphrase, or the backup is damaged".to_string())?;

    let check = (|| -> Result<(), String> {
        let wrapped = DeviceShare::from_bytes(&plain).map_err(|e| e.to_string())?;
        let full = aux_info::from_device_share(&wrapped).map_err(|e| e.to_string())?;
        if aux_info::share_index(&full) != PARTY_RECOVERY {
            return Err("the backup does not hold a recovery share".into());
        }
        let address = aux_info::wallet_address(&full).map_err(|e| e.to_string())?;
        if address != parsed.wallet_address {
            return Err("the backup belongs to a different wallet".into());
        }
        Ok(())
    })();
    if let Err(e) = check {
        let mut plain = plain;
        plain.zeroize();
        return Err(e);
    }
    Ok((plain, parsed.wallet_address))
}

/// Shortest recovery passphrase accepted, in characters.
#[frb]
pub fn mpc_min_passphrase_chars() -> u32 {
    MPC_MIN_PASSPHRASE_CHARS as u32
}

/// Whether a passphrase is acceptable, with the reason it is not.
#[frb]
pub fn mpc_validate_passphrase(passphrase: String) -> Result<(), String> {
    mpc_check_passphrase(&passphrase)
}

/// The wallet a recovery backup belongs to. Readable without the passphrase,
/// so the app can show which wallet a downloaded backup is for.
#[frb]
pub fn mpc_recovery_backup_wallet_address(backup: Vec<u8>) -> Result<String, String> {
    Ok(mpc_parse_backup(&backup)?.wallet_address)
}

/// Opens a recovery backup with the user's passphrase and returns the plain
/// recovery share (opaque bytes). Keep it only in secure storage, as the share
/// of a recovered device; sign with it through [`MpcSigningSession::create`].
#[frb]
pub fn mpc_unlock_recovery_backup(backup: Vec<u8>, passphrase: String) -> Result<Vec<u8>, String> {
    mpc_decrypt_recovery_backup(&backup, &passphrase).map(|(share, _)| share)
}

/// Re-encrypts a recovery backup under a new passphrase.
#[frb]
pub fn mpc_change_recovery_passphrase(
    backup: Vec<u8>,
    old_passphrase: String,
    new_passphrase: String,
) -> Result<Vec<u8>, String> {
    use zeroize::Zeroize;
    mpc_check_passphrase(&new_passphrase)?;
    let (mut share, address) = mpc_decrypt_recovery_backup(&backup, &old_passphrase)?;
    let result = mpc_encrypt_recovery_share(&share, &address, &new_passphrase, MPC_BACKUP_KDF_PARAMS);
    share.zeroize();
    result
}

// ── Pairing a second device ──────────────────────────────────────────────────
//
// Every linked device holds a copy of the same device share. To add one, the
// new device makes a one-time key pair and shows its public key (for example as
// a QR code). The existing device scans it and encrypts its device share to
// that key. The package can travel over any channel, including the signer
// server, because only the new device's secret key can open it.
//
//   new device:       mpc_pairing_new_request()      -> public key (shown), secret key (kept)
//   existing device:  mpc_pairing_export_share(...)  -> package
//   new device:       mpc_pairing_import_share(...)  -> device share
//
// Package layout: "KPPK" | version (1) | sender ephemeral public key (33)
//   | nonce (12) | ciphertext. The two public keys are authenticated as
// AES-GCM associated data and mixed into the key, so a package made for one
// request cannot be opened or replayed against another.
//
// The scanned public key is the only thing that authenticates the new device,
// so it must be read directly from the new device's screen.

const MPC_PAIR_MAGIC: &[u8; 4] = b"KPPK";
const MPC_PAIR_VERSION: u8 = 1;
const MPC_PAIR_PUBKEY_LEN: usize = 33;

/// The new device's one-time key pair for [`mpc_pairing_export_share`].
#[frb]
#[derive(Clone)]
pub struct MpcPairingRequest {
    /// Compressed public key (33 bytes). Show it to the existing device.
    pub public_key: Vec<u8>,
    /// Secret key (32 bytes). Keep it in memory or secure storage only until the
    /// package arrives, then discard it.
    pub secret_key: Vec<u8>,
}

impl std::fmt::Debug for MpcPairingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcPairingRequest").finish_non_exhaustive()
    }
}

fn mpc_pairing_key(shared: &[u8], new_public: &[u8], sender_public: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"khodpay/pairing/v1");
    hasher.update(shared);
    hasher.update(new_public);
    hasher.update(sender_public);
    hasher.finalize().into()
}

/// Encrypts `plain` so only the holder of the secret key behind `new_public`
/// can open it.
fn mpc_pairing_seal(plain: &[u8], new_public: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use rand::RngCore;
    use zeroize::Zeroize;

    let their = k256::PublicKey::from_sec1_bytes(new_public)
        .map_err(|_| "the pairing public key is not valid".to_string())?;
    let ours = k256::SecretKey::random(&mut rand::rngs::OsRng);
    let our_public = ours.public_key().to_sec1_bytes();
    let shared = k256::ecdh::diffie_hellman(ours.to_nonzero_scalar(), their.as_affine());
    let mut key = mpc_pairing_key(shared.raw_secret_bytes(), new_public, &our_public);

    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut package = Vec::new();
    package.extend_from_slice(MPC_PAIR_MAGIC);
    package.push(MPC_PAIR_VERSION);
    package.extend_from_slice(&our_public);
    package.extend_from_slice(&nonce);

    let mut aad = package[..5 + MPC_PAIR_PUBKEY_LEN].to_vec();
    aad.extend_from_slice(new_public);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: &aad })
        .map_err(|_| "could not encrypt the pairing package".to_string())?;
    package.extend_from_slice(&ciphertext);
    Ok(package)
}

/// Opens a package made by [`mpc_pairing_seal`] with the new device's secret key.
fn mpc_pairing_open(package: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use zeroize::Zeroize;

    const BAD: &str = "not a KhodPay pairing package";
    let header_len = 5 + MPC_PAIR_PUBKEY_LEN + 12;
    if package.len() <= header_len || &package[..4] != MPC_PAIR_MAGIC {
        return Err(BAD.into());
    }
    if package[4] != MPC_PAIR_VERSION {
        return Err(format!("unsupported pairing package version {}", package[4]));
    }
    let sender_public = &package[5..5 + MPC_PAIR_PUBKEY_LEN];
    let nonce = &package[5 + MPC_PAIR_PUBKEY_LEN..header_len];
    let sender = k256::PublicKey::from_sec1_bytes(sender_public).map_err(|_| BAD.to_string())?;
    let ours = k256::SecretKey::from_slice(secret_key)
        .map_err(|_| "the pairing secret key is not valid".to_string())?;
    let our_public = ours.public_key().to_sec1_bytes();

    let shared = k256::ecdh::diffie_hellman(ours.to_nonzero_scalar(), sender.as_affine());
    let mut key = mpc_pairing_key(shared.raw_secret_bytes(), &our_public, sender_public);
    let mut aad = package[..5 + MPC_PAIR_PUBKEY_LEN].to_vec();
    aad.extend_from_slice(&our_public);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &package[header_len..],
                aad: &aad,
            },
        )
        .map_err(|_| "the pairing package was not made for this request, or is damaged".to_string())
}

/// New device, step 1: make a one-time key pair. Show `public_key` (for
/// example as a QR code) to the existing device and keep `secret_key`.
#[frb]
pub fn mpc_pairing_new_request() -> MpcPairingRequest {
    let secret = k256::SecretKey::random(&mut rand::rngs::OsRng);
    MpcPairingRequest {
        public_key: secret.public_key().to_sec1_bytes().to_vec(),
        secret_key: secret.to_bytes().to_vec(),
    }
}

/// Existing device, step 2: encrypt this device's share to the new device.
/// Only a device share (party 0) can be exported; the recovery share moves
/// through its passphrase-protected backup instead.
#[frb]
pub fn mpc_pairing_export_share(
    device_share: Vec<u8>,
    new_device_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let info = mpc_share_info(device_share.clone())?;
    if info.party_index != PARTY_DEVICE {
        return Err("only the device share can be sent to another device".into());
    }
    mpc_pairing_seal(&device_share, &new_device_public_key)
}

/// New device, step 3: open the package with the secret key from step 1 and
/// return the device share. The share is checked before it is returned. Store
/// it like a share from key generation, and link the device on the server.
#[frb]
pub fn mpc_pairing_import_share(secret_key: Vec<u8>, package: Vec<u8>) -> Result<Vec<u8>, String> {
    use zeroize::Zeroize;
    let mut share = mpc_pairing_open(&package, &secret_key)?;
    match mpc_share_info(share.clone()) {
        Ok(info) if info.party_index == PARTY_DEVICE => Ok(share),
        Ok(_) => {
            share.zeroize();
            Err("the package does not hold a device share".into())
        }
        Err(e) => {
            share.zeroize();
            Err(e)
        }
    }
}

/// What a stored share says about itself.
#[frb]
#[derive(Debug, Clone)]
pub struct MpcShareInfo {
    /// EIP-55 wallet address.
    pub wallet_address: String,
    /// 0 for the device share, 2 for the recovery share.
    pub party_index: u16,
    /// Shares the wallet was split into (3).
    pub parties: u16,
    /// Shares needed to sign (2).
    pub threshold: u16,
}

/// Reads the wallet address and role from a share.
#[frb]
pub fn mpc_share_info(share: Vec<u8>) -> Result<MpcShareInfo, String> {
    let wrapped = DeviceShare::from_bytes(&share).map_err(|e| e.to_string())?;
    let full = aux_info::from_device_share(&wrapped).map_err(|e| e.to_string())?;
    Ok(MpcShareInfo {
        wallet_address: aux_info::wallet_address(&full).map_err(|e| e.to_string())?,
        party_index: aux_info::share_index(&full),
        parties: aux_info::share_parties(&full),
        threshold: aux_info::share_threshold(&full),
    })
}

/// Signs a 32-byte hash using the device share and the recovery share held
/// together on this device, with no server involved.
///
/// This is the escape hatch for when the signer server is unavailable. It
/// needs the unlocked recovery share, so the device briefly holds two shares.
/// **Slow** (several seconds): run it off the UI isolate.
#[frb]
pub fn mpc_sign_locally(
    device_share: Vec<u8>,
    recovery_share: Vec<u8>,
    tx_hash: Vec<u8>,
) -> Result<Vec<u8>, String> {
    use rand::RngCore;
    let hash: [u8; 32] = tx_hash
        .as_slice()
        .try_into()
        .map_err(|_| format!("tx_hash must be exactly 32 bytes, got {}", tx_hash.len()))?;
    let load = |bytes: &[u8]| -> Result<aux_info::FullKeyShare, String> {
        let wrapped = DeviceShare::from_bytes(bytes).map_err(|e| e.to_string())?;
        aux_info::from_device_share(&wrapped).map_err(|e| e.to_string())
    };
    let (a, c) = (load(&device_share)?, load(&recovery_share)?);
    if aux_info::wallet_address(&a).map_err(|e| e.to_string())?
        != aux_info::wallet_address(&c).map_err(|e| e.to_string())?
    {
        return Err("the two shares belong to different wallets".into());
    }
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    let session_id = hex::encode(id);
    aux_info::sign_with_local_shares(a, c, &session_id, hash)
        .map(|sig| sig.to_vec())
        .map_err(|e| e.to_string())
}

/// Flutter-facing wrapper for the device side of a 2-party key generation with
/// the KhodPay signer.
///
/// Each gRPC round trip carries one encoded batch of protocol messages in each
/// direction. Dart only moves opaque bytes between this session and the
/// network.
///
/// ## Lifecycle
///
/// ```text
/// // StartDkg → session_id, server_first_batch
/// let session = MpcDkgSession.create(session_id, primes);
/// var batch = server_first_batch;
/// loop {
///   let r = session.advance(batch);
///   if r.is_complete {
///     // store r.device_share in SecureStorageService; show r.wallet_address
///   }
///   if r.next_payload != null {
///     batch = DkgRound(session_id, r.next_payload)  // server's reply
///   } else {
///     break;
///   }
/// }
/// ```
#[frb]
pub struct MpcDkgSession {
    session_id: String,
    state: Mutex<MpcDkgState>,
}

struct MpcDkgState {
    /// `None` once the ceremony finished or failed.
    party: Option<DeviceDkg>,
    /// The device's first messages, sent together with the reply to the
    /// server's first batch.
    held: Vec<WireMessage>,
    /// Passphrase that encrypts the recovery share when it is produced.
    passphrase: String,
}

impl Drop for MpcDkgState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.passphrase.zeroize();
    }
}

impl std::fmt::Debug for MpcDkgSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcDkgSession")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

#[frb]
impl MpcDkgSession {
    /// Starts the device side of the key generation the server announced with
    /// `session_id`.
    ///
    /// The device runs two of the wallet's three parties (the device share and
    /// the recovery share), so it needs two separate sets of primes: call
    /// [`mpc_generate_primes`] twice. Pass `None` to let the session generate
    /// them itself, which can take minutes on a phone.
    ///
    /// `recovery_passphrase` encrypts the recovery share before it leaves Rust
    /// (at least [`MPC_MIN_PASSPHRASE_CHARS`] characters). It must be
    /// remembered: without it the backup cannot be opened.
    ///
    /// # Errors
    ///
    /// Returns a description if `session_id`, a primes value or the passphrase
    /// is invalid.
    #[frb]
    pub fn create(
        session_id: String,
        device_primes: Option<Vec<u8>>,
        recovery_primes: Option<Vec<u8>>,
        recovery_passphrase: String,
    ) -> Result<Self, String> {
        mpc_validate_session_id(&session_id)?;
        mpc_check_passphrase(&recovery_passphrase)?;
        let source = |primes: Option<Vec<u8>>| -> Result<PrimesSource, String> {
            Ok(match primes {
                Some(bytes) => PrimesSource::Ready(mpc_parse_primes(&bytes)?),
                None => PrimesSource::generate_in_background(),
            })
        };
        let mut party =
            DeviceDkg::new(&session_id, source(device_primes)?, source(recovery_primes)?);
        // Start key generation now so the device's first messages are ready.
        let first = party.step(Vec::new()).map_err(|e| e.to_string())?;

        Ok(Self {
            session_id,
            state: Mutex::new(MpcDkgState {
                party: Some(party),
                held: first.outgoing,
                passphrase: recovery_passphrase,
            }),
        })
    }

    /// Returns the session id the server announced.
    #[frb]
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    /// Processes the server's latest batch (empty is allowed) and returns what
    /// to send back.
    ///
    /// Blocks while the device computes (prime generation if it was not done
    /// ahead, zero-knowledge proofs), so Dart awaits it off the UI isolate.
    ///
    /// # Errors
    ///
    /// Returns a description on any protocol error. The session cannot be used
    /// afterwards; start a new ceremony.
    #[frb]
    pub fn advance(&self, server_payload: Vec<u8>) -> Result<MpcDkgAdvanceResult, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "DKG session lock poisoned".to_string())?;
        let mut party = state
            .party
            .take()
            .ok_or_else(|| "DKG session has already finished or failed".to_string())?;

        let incoming = decode_batch(&server_payload).map_err(|e| e.to_string())?;
        let step = party.step(incoming).map_err(|e| e.to_string())?;
        let next_payload = mpc_take_payload(&mut state.held, step.outgoing)?;

        match step.output {
            Some(shares) => {
                let wallet_address =
                    aux_info::wallet_address(&shares.device).map_err(|e| e.to_string())?;
                let device_share =
                    aux_info::to_device_share(&shares.device).map_err(|e| e.to_string())?;
                // The recovery share is encrypted here and its plain form is
                // dropped with `shares` (the serialised bytes are wiped; the share object is not scrubbed), so Dart never sees it.
                let recovery_plain =
                    aux_info::to_device_share(&shares.recovery).map_err(|e| e.to_string())?;
                let recovery_backup = mpc_encrypt_recovery_share(
                    recovery_plain.to_bytes(),
                    &wallet_address,
                    &state.passphrase,
                    MPC_BACKUP_KDF_PARAMS,
                )?;
                drop(shares);
                Ok(MpcDkgAdvanceResult {
                    is_complete: true,
                    next_payload,
                    device_share: Some(device_share.to_bytes().to_vec()),
                    recovery_backup: Some(recovery_backup),
                    wallet_address: Some(wallet_address),
                })
            }
            None => {
                state.party = Some(party);
                Ok(MpcDkgAdvanceResult {
                    is_complete: false,
                    next_payload,
                    device_share: None,
                    recovery_backup: None,
                    wallet_address: None,
                })
            }
        }
    }
}

// =============================================================================
// MpcSigningSession
// =============================================================================

/// Flutter-facing wrapper for the device side of a 2-party signature on a
/// 32-byte hash.
///
/// ## Lifecycle
///
/// ```text
/// // StartSigning(wallet_address, tx_hash) → session_id, server_first_batch
/// let session = MpcSigningSession.create(session_id, device_share, tx_hash);
/// var batch = server_first_batch;
/// loop {
///   let r = session.advance(batch);
///   if r.is_complete {
///     // r.signature is the 65-byte EVM signature (r || s || v)
///   }
///   if r.next_payload != null {
///     batch = SigningRound(session_id, r.next_payload)  // server's reply
///   } else {
///     break;
///   }
/// }
/// ```
#[frb]
pub struct MpcSigningSession {
    session_id: String,
    state: Mutex<MpcSigningState>,
}

struct MpcSigningState {
    /// `None` once the ceremony finished or failed.
    runner: Option<ProtocolRunner<[u8; 65]>>,
    /// The device's first messages, sent together with the reply to the
    /// server's first batch.
    held: Vec<WireMessage>,
}

impl std::fmt::Debug for MpcSigningSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcSigningSession")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

#[frb]
impl MpcSigningSession {
    /// Starts the device side of the signature the server announced with
    /// `session_id`.
    ///
    /// - `device_share`: the bytes stored after key generation.
    /// - `tx_hash`: the 32-byte hash to sign. It is signed as given, not hashed
    ///   again, and must be the same hash sent in `StartSigning`.
    ///
    /// # Errors
    ///
    /// Returns a description if `session_id`, `tx_hash` or `device_share` is
    /// invalid. A share created before aux-info generation existed is rejected.
    #[frb]
    pub fn create(
        session_id: String,
        device_share: Vec<u8>,
        tx_hash: Vec<u8>,
    ) -> Result<Self, String> {
        mpc_validate_session_id(&session_id)?;
        let hash: [u8; 32] = tx_hash
            .as_slice()
            .try_into()
            .map_err(|_| format!("tx_hash must be exactly 32 bytes, got {}", tx_hash.len()))?;
        let share = DeviceShare::from_bytes(&device_share).map_err(|e| e.to_string())?;
        let full = aux_info::from_device_share(&share).map_err(|e| e.to_string())?;
        // The share says which party it is. The server always signs as party
        // 1; the signer list is in ascending order, and a party's id in the
        // ceremony is its place in that list.
        let own_index = aux_info::share_index(&full);
        if own_index != PARTY_DEVICE && own_index != PARTY_RECOVERY {
            return Err(format!("share belongs to party {own_index}, which cannot sign here"));
        }
        let mut group = vec![own_index, PARTY_SERVER];
        group.sort_unstable();
        let position = aux_info::signing_position(&group, own_index)
            .ok_or_else(|| "share is not part of the signer group".to_string())?;
        let mut runner = aux_info::spawn_signing_subset(
            position,
            group,
            aux_info::execution_id(&session_id, "sign"),
            full,
            hash,
        );
        let first = runner.step(Vec::new()).map_err(|e| e.to_string())?;

        Ok(Self {
            session_id,
            state: Mutex::new(MpcSigningState {
                runner: Some(runner),
                held: first.outgoing,
            }),
        })
    }

    /// Returns the session id the server announced.
    #[frb]
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    /// Processes the server's latest batch (empty is allowed) and returns what
    /// to send back. When `is_complete`, `signature` is the final signature.
    ///
    /// # Errors
    ///
    /// Returns a description on any protocol error. The session cannot be used
    /// afterwards; start a new signing session.
    #[frb]
    pub fn advance(&self, server_payload: Vec<u8>) -> Result<MpcSigningAdvanceResult, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "signing session lock poisoned".to_string())?;
        let mut runner = state
            .runner
            .take()
            .ok_or_else(|| "signing session has already finished or failed".to_string())?;

        let incoming = decode_batch(&server_payload).map_err(|e| e.to_string())?;
        let step = runner.step(incoming).map_err(|e| e.to_string())?;
        let next_payload = mpc_take_payload(&mut state.held, step.outgoing)?;

        match step.output {
            Some(signature) => Ok(MpcSigningAdvanceResult {
                is_complete: true,
                next_payload,
                signature: Some(signature.to_vec()),
            }),
            None => {
                state.runner = Some(runner);
                Ok(MpcSigningAdvanceResult {
                    is_complete: false,
                    next_payload,
                    signature: None,
                })
            }
        }
    }
}

// =============================================================================
// PART 6: COMPLETE LIBRARY COVERAGE
//
// Every public, non-generic function of the khodpay-wallet crates that is
// meaningful on a device is reachable from Dart through this file. Items that
// cannot cross the FFI boundary (generic functions, traits, borrowed
// returns, simulation helpers behind the `test-utils` feature) are covered by
// an equivalent value-based function or listed in the header table.
// =============================================================================

fn parse_language(name: &str) -> Result<Language, String> {
    let wanted = name.trim().to_lowercase();
    Language::all_variants()
        .iter()
        .copied()
        .find(|l| l.name().to_lowercase() == wanted)
        .ok_or_else(|| {
            let known: Vec<&str> = Language::all_variants().iter().map(|l| l.name()).collect();
            format!("Unsupported language '{}'. Use one of: {}", name, known.join(", "))
        })
}

fn hex_to_bytes(label: &str, value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|e| format!("Invalid {} hex: {}", label, e))
}

fn evm_address_of_key(key: &RustExtendedPrivateKey) -> Result<String, String> {
    let uncompressed = key.private_key().public_key().serialize_uncompressed();
    RustAddress::from_public_key_bytes(&uncompressed[1..])
        .map(|a| a.to_checksum_string())
        .map_err(|e| format!("Failed to derive EVM address: {}", e))
}

// ── BIP-39 ───────────────────────────────────────────────────────────────────

/// Sizes belonging to one BIP-39 word count.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip39WordCountInfo {
    pub words: u32,
    pub entropy_bytes: u32,
    pub checksum_bits: u32,
}

/// Names of every supported mnemonic language.
#[frb]
pub fn bip39_languages() -> Vec<String> {
    Language::all_variants().iter().map(|l| l.name().to_string()).collect()
}

/// Name of the default mnemonic language.
#[frb]
pub fn bip39_default_language() -> String {
    Language::default().name().to_string()
}

/// Every supported word count (12, 15, 18, 21, 24).
#[frb]
pub fn bip39_word_counts() -> Vec<u32> {
    WordCount::all_variants().iter().map(|w| w.word_count() as u32).collect()
}

/// Entropy length and checksum size for a word count.
#[frb]
pub fn bip39_word_count_info(word_count: u32) -> Result<Bip39WordCountInfo, String> {
    let wc = WordCount::from_word_count(word_count as usize).map_err(|e| e.to_string())?;
    Ok(Bip39WordCountInfo {
        words: wc.word_count() as u32,
        entropy_bytes: wc.entropy_length() as u32,
        checksum_bits: wc.checksum_bits() as u32,
    })
}

/// Word count that matches an entropy length in bytes.
#[frb]
pub fn bip39_word_count_for_entropy_length(entropy_bytes: u32) -> Result<u32, String> {
    WordCount::from_entropy_length(entropy_bytes as usize)
        .map(|w| w.word_count() as u32)
        .map_err(|e| e.to_string())
}

/// Generate a mnemonic in the given language.
#[frb]
pub fn generate_mnemonic_in_language(word_count: u32, language: String) -> Result<String, String> {
    let wc = WordCount::from_word_count(word_count as usize).map_err(|e| e.to_string())?;
    let lang = parse_language(&language)?;
    RustMnemonic::generate(wc, lang)
        .map(|m| m.phrase().to_string())
        .map_err(|e| format!("Failed to generate mnemonic: {}", e))
}

/// Create a mnemonic from entropy in the given language.
#[frb]
pub fn generate_mnemonic_from_entropy_in_language(
    entropy: Vec<u8>,
    language: String,
) -> Result<String, String> {
    let lang = parse_language(&language)?;
    RustMnemonic::new(&entropy, lang)
        .map(|m| m.phrase().to_string())
        .map_err(|e| format!("Failed to create mnemonic from entropy: {}", e))
}

/// Validate a mnemonic and return the reason it is invalid, if any.
#[frb]
pub fn validate_mnemonic_detailed(phrase: String, language: Option<String>) -> Result<(), String> {
    let lang = match language {
        Some(name) => parse_language(&name)?,
        None => Language::default(),
    };
    khodpay_bip39::validate_phrase_in_language(&phrase, lang).map_err(|e| e.to_string())
}

/// Entropy bytes encoded in a mnemonic.
#[frb]
pub fn mnemonic_to_entropy(phrase: String, language: Option<String>) -> Result<Vec<u8>, String> {
    let lang = match language {
        Some(name) => parse_language(&name)?,
        None => Language::default(),
    };
    RustMnemonic::from_phrase(&phrase, lang)
        .map(|m| m.entropy().to_vec())
        .map_err(|e| format!("Invalid mnemonic: {}", e))
}

/// Convert a mnemonic in the given language to a 64-byte seed (hex).
#[frb]
pub fn mnemonic_phrase_to_seed_hex_in_language(
    phrase: String,
    passphrase: Option<String>,
    language: String,
) -> Result<String, String> {
    let lang = parse_language(&language)?;
    khodpay_bip39::phrase_to_seed_in_language(&phrase, &passphrase.unwrap_or_default(), lang)
        .map(hex::encode)
        .map_err(|e| format!("Failed to generate seed: {}", e))
}

// ── BIP-32 ───────────────────────────────────────────────────────────────────

/// Breakdown of a BIP-32 derivation path.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip32PathInfo {
    pub normalized: String,
    pub depth: u32,
    pub is_master: bool,
    pub is_valid: bool,
    pub contains_hardened: bool,
    pub is_public_derivable: bool,
    pub hardened_prefix_length: u32,
    pub normal_suffix_length: u32,
    /// Raw child indexes (hardened ones have bit 31 set).
    pub components: Vec<u32>,
}

/// Details about one child number.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip32ChildNumberInfo {
    pub raw_index: u32,
    pub value: u32,
    pub is_hardened: bool,
}

/// Version bytes and name of a BIP-32 network.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip32NetworkInfo {
    pub name: String,
    pub xprv_version: u32,
    pub xpub_version: u32,
}

/// A master or derived key pair in extended-string form.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip32KeyPair {
    pub private_key: String,
    pub public_key: String,
}

fn parse_derivation_path(path: &str) -> Result<DerivationPath, String> {
    DerivationPath::from_str(path).map_err(|e| format!("Invalid derivation path: {}", e))
}

fn bip32_path_info(path: &DerivationPath) -> Bip32PathInfo {
    Bip32PathInfo {
        normalized: path.to_string(),
        depth: path.depth() as u32,
        is_master: path.is_master(),
        is_valid: path.is_valid(),
        contains_hardened: path.contains_hardened(),
        is_public_derivable: path.is_public_derivable(),
        hardened_prefix_length: path.hardened_prefix_length() as u32,
        normal_suffix_length: path.normal_suffix_length() as u32,
        components: path.iter().map(|c| c.to_index()).collect(),
    }
}

/// Parse a derivation path and describe it.
#[frb]
pub fn bip32_derivation_path_info(path: String) -> Result<Bip32PathInfo, String> {
    Ok(bip32_path_info(&parse_derivation_path(&path)?))
}

/// Parent of a derivation path (`None` for the master path).
#[frb]
pub fn bip32_derivation_path_parent(path: String) -> Result<Option<String>, String> {
    Ok(parse_derivation_path(&path)?.parent().map(|p| p.to_string()))
}

/// Append raw child indexes (bit 31 = hardened) to a derivation path.
#[frb]
pub fn bip32_derivation_path_extend(path: String, children: Vec<u32>) -> Result<String, String> {
    let parsed = parse_derivation_path(&path)?;
    let kids: Vec<ChildNumber> = children.into_iter().map(ChildNumber::from_index).collect();
    Ok(parsed.extend(&kids).to_string())
}

/// Whether `path` begins with `prefix`.
#[frb]
pub fn bip32_derivation_path_starts_with(path: String, prefix: String) -> Result<bool, String> {
    Ok(parse_derivation_path(&path)?.starts_with(&parse_derivation_path(&prefix)?))
}

/// Child number at a position of a derivation path.
#[frb]
pub fn bip32_derivation_path_child_at(
    path: String,
    position: u32,
) -> Result<Option<Bip32ChildNumberInfo>, String> {
    let parsed = parse_derivation_path(&path)?;
    Ok(parsed
        .child_number_at(position as usize)
        .map(|c| bip32_child_number_info(c.to_index())))
}

/// Whether the child at a position is hardened.
#[frb]
pub fn bip32_derivation_path_is_hardened_at(path: String, position: u32) -> Result<bool, String> {
    Ok(parse_derivation_path(&path)?.is_hardened_at(position as usize))
}

/// Describe a raw child index (bit 31 = hardened).
#[frb]
pub fn bip32_child_number_info(raw_index: u32) -> Bip32ChildNumberInfo {
    let c = ChildNumber::from_index(raw_index);
    Bip32ChildNumberInfo {
        raw_index: c.to_index(),
        value: c.value(),
        is_hardened: c.is_hardened(),
    }
}

/// Raw index of a hardened child with the given value.
#[frb]
pub fn bip32_child_number_hardened(value: u32) -> u32 {
    ChildNumber::Hardened(value).to_index()
}

/// Raw index of a normal child with the given value.
#[frb]
pub fn bip32_child_number_normal(value: u32) -> u32 {
    ChildNumber::Normal(value).to_index()
}

/// Name and version bytes of a network.
#[frb]
pub fn bip32_network_info(network: Network) -> Bip32NetworkInfo {
    let n: khodpay_bip32::Network = network.into();
    Bip32NetworkInfo {
        name: n.name().to_string(),
        xprv_version: n.xprv_version(),
        xpub_version: n.xpub_version(),
    }
}

/// Network that uses the given `xprv` version bytes.
#[frb]
pub fn bip32_network_from_xprv_version(version: u32) -> Option<Network> {
    khodpay_bip32::Network::from_xprv_version(version).map(Into::into)
}

/// Network that uses the given `xpub` version bytes.
#[frb]
pub fn bip32_network_from_xpub_version(version: u32) -> Option<Network> {
    khodpay_bip32::Network::from_xpub_version(version).map(Into::into)
}

/// Version bytes for a network and key kind.
#[frb]
pub fn bip32_network_version_bytes(network: Network, is_private: bool) -> u32 {
    let n: khodpay_bip32::Network = network.into();
    let kind = if is_private {
        khodpay_bip32::KeyType::Private
    } else {
        khodpay_bip32::KeyType::Public
    };
    n.version_bytes(kind)
}

/// Master private and public keys from a seed.
#[frb]
pub fn bip32_generate_master_keypair(seed: Vec<u8>, network: Network) -> Result<Bip32KeyPair, String> {
    let (private_key, public_key) = khodpay_bip32::utils::generate_master_keypair(&seed, network.into())
        .map_err(|e| format!("Failed to generate master key pair: {}", e))?;
    Ok(Bip32KeyPair {
        private_key: private_key.to_string(),
        public_key: public_key.to_string(),
    })
}

/// Private and public keys at `path` below a master key.
#[frb]
pub fn bip32_derive_keypair_from_path(
    master_extended_private_key: String,
    path: String,
) -> Result<Bip32KeyPair, String> {
    let master = RustExtendedPrivateKey::from_str(&master_extended_private_key)
        .map_err(|e| format!("Invalid extended private key: {}", e))?;
    let (private_key, public_key) =
        khodpay_bip32::utils::derive_keypair_from_path(&master, &parse_derivation_path(&path)?)
            .map_err(|e| format!("Failed to derive key pair: {}", e))?;
    Ok(Bip32KeyPair {
        private_key: private_key.to_string(),
        public_key: public_key.to_string(),
    })
}

/// Compressed public key (33 bytes, hex) of a raw private key.
#[frb]
pub fn bip32_private_key_to_public_key(private_key_hex: String) -> Result<String, String> {
    let key = khodpay_bip32::PrivateKey::from_bytes(&hex_to_bytes("private key", &private_key_hex)?)
        .map_err(|e| format!("Invalid private key: {}", e))?;
    Ok(hex::encode(khodpay_bip32::PublicKey::from_private_key(&key).to_bytes()))
}

/// Add a 32-byte tweak to a private key (hex in, hex out).
#[frb]
pub fn bip32_private_key_tweak_add(private_key_hex: String, tweak_hex: String) -> Result<String, String> {
    let key = khodpay_bip32::PrivateKey::from_bytes(&hex_to_bytes("private key", &private_key_hex)?)
        .map_err(|e| format!("Invalid private key: {}", e))?;
    key.tweak_add(&hex_to_bytes("tweak", &tweak_hex)?)
        .map(|k| hex::encode(k.to_bytes()))
        .map_err(|e| format!("Tweak failed: {}", e))
}

/// Add a 32-byte tweak to a compressed public key (hex in, hex out).
#[frb]
pub fn bip32_public_key_tweak_add(public_key_hex: String, tweak_hex: String) -> Result<String, String> {
    let key = khodpay_bip32::PublicKey::from_bytes(&hex_to_bytes("public key", &public_key_hex)?)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    key.tweak_add(&hex_to_bytes("tweak", &tweak_hex)?)
        .map(|k| hex::encode(k.to_bytes()))
        .map_err(|e| format!("Tweak failed: {}", e))
}

/// Uncompressed form (65 bytes, hex) of a compressed public key.
#[frb]
pub fn bip32_public_key_to_uncompressed(public_key_hex: String) -> Result<String, String> {
    let key = khodpay_bip32::PublicKey::from_bytes(&hex_to_bytes("public key", &public_key_hex)?)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    Ok(hex::encode(key.to_uncompressed()))
}

/// Validate a 32-byte chain code and return it as bytes.
#[frb]
pub fn bip32_chain_code_from_bytes(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    khodpay_bip32::ChainCode::from_bytes(&bytes)
        .map(|c| c.to_vec())
        .map_err(|e| format!("Invalid chain code: {}", e))
}

#[frb]
impl ExtendedPrivateKey {
    /// The 32-byte chain code.
    #[frb]
    pub fn chain_code(&self) -> Vec<u8> {
        self.inner.chain_code().to_vec()
    }

    /// The raw 32-byte private key. Handle with care.
    #[frb]
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.inner.private_key().to_bytes().to_vec()
    }

    /// The compressed public key (33 bytes).
    #[frb]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        khodpay_bip32::PublicKey::from_private_key(self.inner.private_key())
            .to_bytes()
            .to_vec()
    }

    /// The uncompressed public key (65 bytes).
    #[frb]
    pub fn public_key_uncompressed(&self) -> Vec<u8> {
        khodpay_bip32::PublicKey::from_private_key(self.inner.private_key())
            .to_uncompressed()
            .to_vec()
    }

    /// Raw child index of this key (bit 31 = hardened).
    #[frb]
    pub fn child_number_raw(&self) -> u32 {
        self.inner.child_number().to_index()
    }
}

#[frb]
impl ExtendedPublicKey {
    /// The 32-byte chain code.
    #[frb]
    pub fn chain_code(&self) -> Vec<u8> {
        self.inner.chain_code().to_vec()
    }

    /// The compressed public key (33 bytes).
    #[frb]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().to_bytes().to_vec()
    }

    /// The uncompressed public key (65 bytes).
    #[frb]
    pub fn public_key_uncompressed(&self) -> Vec<u8> {
        self.inner.public_key().to_uncompressed().to_vec()
    }

    /// Raw child index of this key (bit 31 = hardened).
    #[frb]
    pub fn child_number_raw(&self) -> u32 {
        self.inner.child_number().to_index()
    }
}

// ── BIP-44 ───────────────────────────────────────────────────────────────────

/// Components of a BIP-44 path.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip44PathInfo {
    pub path: String,
    pub purpose: Purpose,
    pub coin_type: CoinType,
    pub account: u32,
    pub chain: Chain,
    pub address_index: u32,
    pub is_valid: bool,
    pub depth: u8,
}

/// A derived BIP-44 address with its path.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip44DerivedAddressInfo {
    pub path: String,
    pub chain: Chain,
    pub index: u32,
    pub purpose: Purpose,
    pub coin_type: CoinType,
    pub account_index: u32,
    pub is_external: bool,
    pub is_internal: bool,
    /// Checksummed address for EVM coins, otherwise the extended key string.
    pub address: String,
}

/// Structured details of a coin type.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip44CoinDetails {
    pub name: String,
    pub symbol: String,
    pub index: u32,
    pub is_testnet: bool,
    pub is_evm_compatible: bool,
    pub default_purpose: Purpose,
}

/// Structured details of a purpose.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip44PurposeDetails {
    pub name: String,
    pub value: u32,
    pub description: String,
}

/// Structured details of a chain (external or internal).
#[frb]
#[derive(Debug, Clone)]
pub struct Bip44ChainDetails {
    pub name: String,
    pub value: u32,
    pub is_external: bool,
    pub is_internal: bool,
}

/// Result of scanning one chain for used addresses.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip44ChainScan {
    pub chain: Chain,
    pub used_indices: Vec<u32>,
    pub last_used_index: Option<u32>,
}

/// Result of scanning one account.
#[frb]
#[derive(Debug, Clone)]
pub struct Bip44AccountScan {
    pub account_index: u32,
    pub external: Bip44ChainScan,
    pub internal: Bip44ChainScan,
    pub is_used: bool,
    pub total_used_count: u32,
}

fn bip44_path_details(path: &RustBip44Path) -> Bip44PathInfo {
    Bip44PathInfo {
        path: path.to_string(),
        purpose: path.purpose().into(),
        coin_type: path.coin_type().into(),
        account: path.account(),
        chain: path.chain().into(),
        address_index: path.address_index(),
        is_valid: path.is_valid(),
        depth: path.depth(),
    }
}

fn parse_bip44_path_str(path: &str) -> Result<RustBip44Path, String> {
    RustBip44Path::from_str(path).map_err(|e| format!("Invalid BIP-44 path: {}", e))
}

fn bip44_chain_scan(r: khodpay_bip44::ChainScanResult) -> Bip44ChainScan {
    Bip44ChainScan {
        chain: r.chain.into(),
        used_indices: r.used_indices,
        last_used_index: r.last_used_index,
    }
}

/// Build a BIP-44 path from its components.
#[frb]
pub fn bip44_path_build(
    purpose: Purpose,
    coin_type: CoinType,
    account: u32,
    chain: Chain,
    address_index: u32,
) -> Result<Bip44PathInfo, String> {
    let path = RustBip44Path::builder()
        .purpose(purpose.into())
        .coin_type(coin_type.into())
        .account(account)
        .chain(chain.into())
        .address_index(address_index)
        .build()
        .map_err(|e| format!("Failed to build path: {}", e))?;
    Ok(bip44_path_details(&path))
}

/// Parse a BIP-44 path into its components.
#[frb]
pub fn bip44_path_parse(path: String) -> Result<Bip44PathInfo, String> {
    Ok(bip44_path_details(&parse_bip44_path_str(&path)?))
}

/// The same path with the next address index.
#[frb]
pub fn bip44_path_next_address(path: String) -> Result<Bip44PathInfo, String> {
    Ok(bip44_path_details(&parse_bip44_path_str(&path)?.next_address()))
}

/// The same path with a different address index.
#[frb]
pub fn bip44_path_with_address_index(path: String, address_index: u32) -> Result<Bip44PathInfo, String> {
    Ok(bip44_path_details(&parse_bip44_path_str(&path)?.with_address_index(address_index)))
}

/// The same path on a different chain.
#[frb]
pub fn bip44_path_with_chain(path: String, chain: Chain) -> Result<Bip44PathInfo, String> {
    Ok(bip44_path_details(&parse_bip44_path_str(&path)?.with_chain(chain.into())))
}

/// The same path on the external chain.
#[frb]
pub fn bip44_path_to_external(path: String) -> Result<Bip44PathInfo, String> {
    Ok(bip44_path_details(&parse_bip44_path_str(&path)?.to_external()))
}

/// The same path on the internal (change) chain.
#[frb]
pub fn bip44_path_to_internal(path: String) -> Result<Bip44PathInfo, String> {
    Ok(bip44_path_details(&parse_bip44_path_str(&path)?.to_internal()))
}

/// The same path under a different account.
#[frb]
pub fn bip44_path_with_account(path: String, account: u32) -> Result<Bip44PathInfo, String> {
    let p = parse_bip44_path_str(&path)?
        .with_account(account)
        .map_err(|e| format!("Invalid account: {}", e))?;
    Ok(bip44_path_details(&p))
}

/// The same path under the next account.
#[frb]
pub fn bip44_path_next_account(path: String) -> Result<Bip44PathInfo, String> {
    let p = parse_bip44_path_str(&path)?
        .next_account()
        .map_err(|e| format!("Invalid account: {}", e))?;
    Ok(bip44_path_details(&p))
}

/// The same path with a different purpose.
#[frb]
pub fn bip44_path_with_purpose(path: String, purpose: Purpose) -> Result<Bip44PathInfo, String> {
    Ok(bip44_path_details(&parse_bip44_path_str(&path)?.with_purpose(purpose.into())))
}

/// The same path with a different coin type.
#[frb]
pub fn bip44_path_with_coin_type(path: String, coin_type: CoinType) -> Result<Bip44PathInfo, String> {
    Ok(bip44_path_details(&parse_bip44_path_str(&path)?.with_coin_type(coin_type.into())))
}

/// A BIP-44 path as a generic BIP-32 derivation path string.
#[frb]
pub fn bip44_path_to_derivation_path(path: String) -> Result<String, String> {
    Ok(parse_bip44_path_str(&path)?.to_derivation_path().to_string())
}

/// Structured details of a coin type.
#[frb]
pub fn bip44_coin_details(coin_type: CoinType) -> Bip44CoinDetails {
    let c: RustCoinType = coin_type.into();
    Bip44CoinDetails {
        name: c.name().to_string(),
        symbol: c.symbol().to_string(),
        index: c.index(),
        is_testnet: c.is_testnet(),
        is_evm_compatible: c.is_evm_compatible(),
        default_purpose: c.default_purpose().into(),
    }
}

/// Structured details of a purpose.
#[frb]
pub fn bip44_purpose_details(purpose: Purpose) -> Bip44PurposeDetails {
    let p: RustPurpose = purpose.into();
    Bip44PurposeDetails {
        name: p.name().to_string(),
        value: p.value(),
        description: p.description().to_string(),
    }
}

/// Structured details of a chain.
#[frb]
pub fn bip44_chain_details(chain: Chain) -> Bip44ChainDetails {
    let c: RustChain = chain.into();
    Bip44ChainDetails {
        name: c.name().to_string(),
        value: c.value(),
        is_external: c.is_external(),
        is_internal: c.is_internal(),
    }
}

/// The default gap limit (20).
#[frb]
pub fn bip44_default_gap_limit() -> u32 {
    khodpay_bip44::DEFAULT_GAP_LIMIT
}

/// Last used address index, given the set of used indexes.
///
/// Dart looks up which addresses have activity and passes them in; the gap
/// limit rule is applied here.
#[frb]
pub fn bip44_find_last_used_index(
    used_indices: Vec<u32>,
    gap_limit: u32,
    start_index: u32,
) -> Result<Option<u32>, String> {
    let chain = khodpay_bip44::MockBlockchain::with_used_addresses(&used_indices);
    khodpay_bip44::GapLimitChecker::new(gap_limit)
        .find_last_used_index(&chain, start_index)
        .map_err(|e| e.to_string())
}

/// All used indexes found by the gap limit rule.
#[frb]
pub fn bip44_find_used_indices(
    used_indices: Vec<u32>,
    gap_limit: u32,
    start_index: u32,
) -> Result<Vec<u32>, String> {
    let chain = khodpay_bip44::MockBlockchain::with_used_addresses(&used_indices);
    khodpay_bip44::GapLimitChecker::new(gap_limit)
        .find_used_indices(&chain, start_index)
        .map_err(|e| e.to_string())
}

/// Scan one chain with the gap limit rule.
#[frb]
pub fn bip44_scan_chain(
    used_indices: Vec<u32>,
    gap_limit: u32,
    chain: Chain,
) -> Result<Bip44ChainScan, String> {
    let discovery = khodpay_bip44::MockBlockchain::with_used_addresses(&used_indices);
    let scanner = khodpay_bip44::AccountScanner::new(khodpay_bip44::GapLimitChecker::new(gap_limit));
    scanner
        .scan_chain(&discovery, chain.into())
        .map(bip44_chain_scan)
        .map_err(|e| e.to_string())
}

/// Scan accounts `0..max_accounts` using one set of used indexes per chain.
#[frb]
pub fn bip44_discover_accounts(
    external_used_indices: Vec<u32>,
    internal_used_indices: Vec<u32>,
    gap_limit: u32,
    max_accounts: u32,
) -> Result<Vec<Bip44AccountScan>, String> {
    let external = khodpay_bip44::MockBlockchain::with_used_addresses(&external_used_indices);
    let internal = khodpay_bip44::MockBlockchain::with_used_addresses(&internal_used_indices);
    let scanner = khodpay_bip44::AccountScanner::new(khodpay_bip44::GapLimitChecker::new(gap_limit));
    let results = scanner
        .discover_accounts(&external, &internal, max_accounts)
        .map_err(|e| e.to_string())?;
    Ok(results
        .into_iter()
        .map(|r| Bip44AccountScan {
            account_index: r.account_index,
            is_used: r.is_used(),
            total_used_count: r.total_used_count() as u32,
            external: bip44_chain_scan(r.external),
            internal: bip44_chain_scan(r.internal),
        })
        .collect())
}

#[frb]
impl Bip44Wallet {
    /// Create a wallet from a mnemonic written in the given language.
    #[frb]
    pub fn from_mnemonic_in_language(
        mnemonic: String,
        passphrase: Option<String>,
        language: String,
        network: Network,
    ) -> Result<Self, String> {
        let wallet = khodpay_bip44::WalletBuilder::new()
            .mnemonic(&mnemonic)
            .password(passphrase.as_deref().unwrap_or(""))
            .language(parse_language(&language)?)
            .network(network.into())
            .build()
            .map_err(|e| format!("Failed to create wallet: {}", e))?;
        Ok(Self { inner: wallet })
    }

    /// The master key as an extended private key string.
    #[frb]
    pub fn master_key_string(&self) -> String {
        self.inner.master_key().to_string()
    }

    /// Forget cached accounts.
    #[frb]
    pub fn clear_cache(&mut self) {
        self.inner.clear_cache();
    }

    /// Number of accounts currently cached.
    #[frb]
    pub fn cached_account_count(&self) -> u32 {
        self.inner.cached_account_count() as u32
    }
}

#[frb]
impl Bip44Account {
    /// Build an account from an account-level extended private key string.
    #[frb]
    pub fn from_extended_key(
        extended_key: String,
        purpose: Purpose,
        coin_type: CoinType,
        account_index: u32,
    ) -> Result<Self, String> {
        let key = RustExtendedPrivateKey::from_str(&extended_key)
            .map_err(|e| format!("Invalid extended private key: {}", e))?;
        Ok(Self {
            inner: RustAccount::from_extended_key(
                key,
                purpose.into(),
                coin_type.into(),
                account_index,
            ),
        })
    }

    /// A derived address together with its path.
    #[frb]
    pub fn derived_address_info(
        &self,
        chain: Chain,
        index: u32,
    ) -> Result<Bip44DerivedAddressInfo, String> {
        let derived = khodpay_bip44::DerivedAddress::new(&self.inner, chain.into(), index)
            .map_err(|e| format!("Failed to derive address: {}", e))?;
        let address = if self.inner.coin_type().is_evm_compatible() {
            evm_address_of_key(derived.key())?
        } else {
            derived.key().to_string()
        };
        Ok(Bip44DerivedAddressInfo {
            path: derived.path().to_string(),
            chain: derived.chain().into(),
            index: derived.index(),
            purpose: derived.purpose().into(),
            coin_type: derived.coin_type().into(),
            account_index: derived.account_index(),
            is_external: derived.is_external(),
            is_internal: derived.is_internal(),
            address,
        })
    }

    /// Walk addresses from `start_index`, returning at most `count`.
    ///
    /// `max_index` stops the walk early when set.
    #[frb]
    pub fn iterate_addresses(
        &self,
        chain: Chain,
        start_index: u32,
        max_index: Option<u32>,
        count: u32,
    ) -> Result<Vec<String>, String> {
        let mut iter = khodpay_bip44::AddressIterator::new(&self.inner, chain.into())
            .start_at(start_index);
        if let Some(max) = max_index {
            iter = iter.max_index(max);
        }
        let evm = self.inner.coin_type().is_evm_compatible();
        iter.take(count as usize)
            .map(|item| {
                let key = item.map_err(|e| format!("Failed to derive address: {}", e))?;
                if evm {
                    evm_address_of_key(&key)
                } else {
                    Ok(key.to_string())
                }
            })
            .collect()
    }
}

// ── khodpay-signing ──────────────────────────────────────────────────────────

fn parse_u128(label: &str, value: &str) -> Result<u128, String> {
    value
        .trim()
        .parse::<u128>()
        .map_err(|e| format!("Invalid {}: {}", label, e))
}

fn bytes32(label: &str, value: &[u8]) -> Result<[u8; 32], String> {
    value
        .try_into()
        .map_err(|_| format!("{} must be 32 bytes, got {}", label, value.len()))
}

/// keccak-256 of arbitrary bytes.
#[frb]
pub fn keccak256_bytes(data: Vec<u8>) -> Vec<u8> {
    khodpay_signing::eip712::keccak256(&data).to_vec()
}

/// EIP-712 domain type string, e.g. `EIP712Domain(string name,...)`.
#[frb]
pub fn eip712_domain_type_string(
    name: String,
    version: String,
    chain_id: u64,
    verifying_contract: Option<String>,
) -> Result<String, String> {
    Ok(parse_eip712_domain(&name, &version, chain_id, verifying_contract.as_deref())?.type_string())
}

/// EIP-712 domain type hash.
#[frb]
pub fn eip712_domain_type_hash(
    name: String,
    version: String,
    chain_id: u64,
    verifying_contract: Option<String>,
) -> Result<Vec<u8>, String> {
    Ok(parse_eip712_domain(&name, &version, chain_id, verifying_contract.as_deref())?
        .type_hash()
        .to_vec())
}

/// EIP-712 domain separator.
#[frb]
pub fn eip712_domain_separator(
    name: String,
    version: String,
    chain_id: u64,
    verifying_contract: Option<String>,
) -> Result<Vec<u8>, String> {
    Ok(parse_eip712_domain(&name, &version, chain_id, verifying_contract.as_deref())?
        .domain_separator()
        .to_vec())
}

/// ABI-encode an address as a 32-byte EIP-712 word.
#[frb]
pub fn eip712_encode_address(address: String) -> Result<Vec<u8>, String> {
    let a = RustAddress::from_str(&address).map_err(|e| format!("Invalid address: {}", e))?;
    Ok(encode_address(&a).to_vec())
}

/// Encode a decimal `u128` as a 32-byte word.
#[frb]
pub fn eip712_encode_uint256(value: String) -> Result<Vec<u8>, String> {
    Ok(khodpay_signing::eip712::encode_uint256(parse_u128("uint256", &value)?).to_vec())
}

/// Encode 32 big-endian bytes as a 32-byte word.
#[frb]
pub fn eip712_encode_u256_bytes(value: Vec<u8>) -> Result<Vec<u8>, String> {
    Ok(khodpay_signing::eip712::encode_u256_bytes(bytes32("value", &value)?).to_vec())
}

/// Encode a `u64` as a 32-byte word.
#[frb]
pub fn eip712_encode_uint64(value: u64) -> Vec<u8> {
    khodpay_signing::eip712::encode_uint64(value).to_vec()
}

/// Encode a bool as a 32-byte word.
#[frb]
pub fn eip712_encode_bool(value: bool) -> Vec<u8> {
    khodpay_signing::eip712::encode_bool(value).to_vec()
}

/// Encode a `bytes32` value as a 32-byte word.
#[frb]
pub fn eip712_encode_bytes32(value: Vec<u8>) -> Result<Vec<u8>, String> {
    Ok(encode_bytes32(bytes32("value", &value)?).to_vec())
}

/// Hash a dynamic `bytes` or `string` value as EIP-712 requires.
#[frb]
pub fn eip712_encode_bytes_dynamic(value: Vec<u8>) -> Vec<u8> {
    khodpay_signing::eip712::encode_bytes_dynamic(&value).to_vec()
}

/// Pack verification and call gas limits into one 32-byte word.
#[frb]
pub fn erc4337_pack_gas_limits(verification_gas_limit: String, call_gas_limit: String) -> Result<Vec<u8>, String> {
    Ok(PackedUserOperation::pack_gas_limits(
        parse_u128("verification_gas_limit", &verification_gas_limit)?,
        parse_u128("call_gas_limit", &call_gas_limit)?,
    )
    .to_vec())
}

/// Pack priority and max fee per gas into one 32-byte word.
#[frb]
pub fn erc4337_pack_gas_fees(
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
) -> Result<Vec<u8>, String> {
    Ok(PackedUserOperation::pack_gas_fees(
        parse_u128("max_priority_fee_per_gas", &max_priority_fee_per_gas)?,
        parse_u128("max_fee_per_gas", &max_fee_per_gas)?,
    )
    .to_vec())
}

/// Decoded view of a built user operation.
#[frb]
#[derive(Debug, Clone)]
pub struct WpgpUserOperationDetails {
    pub verification_gas_limit: String,
    pub call_gas_limit: String,
    pub max_priority_fee_per_gas: String,
    pub max_fee_per_gas: String,
    pub has_paymaster: bool,
    pub paymaster_address: Option<String>,
    pub paymaster_data: Vec<u8>,
}

/// Build a user operation and read back its packed fields.
#[frb]
pub fn wpgp_user_operation_details(user_op: WpgpUserOperation) -> Result<WpgpUserOperationDetails, String> {
    let built = build_packed_user_op(&user_op)?;
    Ok(WpgpUserOperationDetails {
        verification_gas_limit: built.verification_gas_limit().to_string(),
        call_gas_limit: built.call_gas_limit().to_string(),
        max_priority_fee_per_gas: built.max_priority_fee_per_gas().to_string(),
        max_fee_per_gas: built.max_fee_per_gas().to_string(),
        has_paymaster: built.has_paymaster(),
        paymaster_address: built.paymaster_address().map(|a| a.to_checksum_string()),
        paymaster_data: built.paymaster_data().to_vec(),
    })
}

#[frb]
impl EvmWei {
    /// Big-endian 32-byte form of this value.
    #[frb]
    pub fn to_be_bytes(&self) -> Result<Vec<u8>, String> {
        let w: RustWei = self.value_hex.parse().map_err(|e| format!("Invalid wei: {}", e))?;
        Ok(w.to_be_bytes().to_vec())
    }

    /// Build a value from big-endian bytes.
    #[frb]
    pub fn from_be_bytes(bytes: Vec<u8>) -> Self {
        Self {
            value_hex: RustWei::from_be_bytes(&bytes).to_string(),
        }
    }

    /// The value as a decimal `u128` string, or `None` if it does not fit.
    #[frb]
    pub fn to_u128_string(&self) -> Result<Option<String>, String> {
        let w: RustWei = self.value_hex.parse().map_err(|e| format!("Invalid wei: {}", e))?;
        Ok(w.as_u128().map(|v| v.to_string()))
    }
}

#[frb]
impl Eip1559Transaction {
    /// `0x02 || rlp([...])` without a signature.
    #[frb]
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, String> {
        Ok(self.to_rust_transaction()?.encode_unsigned())
    }
}

// ── khodpay-mpc-tss ──────────────────────────────────────────────────────────

/// One protocol message exchanged with the signer server.
#[frb]
#[derive(Debug, Clone)]
pub struct MpcWireMessage {
    pub sender: u16,
    pub is_broadcast: bool,
    pub phase: u8,
    pub recipient: Option<u16>,
    pub payload: Vec<u8>,
}

/// Encode messages into one batch, the unit sent per gRPC round trip.
#[frb]
pub fn mpc_encode_wire_batch(messages: Vec<MpcWireMessage>) -> Result<Vec<u8>, String> {
    let wire: Vec<WireMessage> = messages
        .into_iter()
        .map(|m| WireMessage {
            sender: m.sender,
            is_broadcast: m.is_broadcast,
            phase: m.phase,
            recipient: m.recipient,
            payload: m.payload,
        })
        .collect();
    encode_batch(&wire).map_err(|e| e.to_string())
}

/// Decode a batch received from the signer server.
#[frb]
pub fn mpc_decode_wire_batch(bytes: Vec<u8>) -> Result<Vec<MpcWireMessage>, String> {
    Ok(decode_batch(&bytes)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|m| MpcWireMessage {
            sender: m.sender,
            is_broadcast: m.is_broadcast,
            phase: m.phase,
            recipient: m.recipient,
            payload: m.payload,
        })
        .collect())
}

/// 32-byte execution id both parties derive for a ceremony.
#[frb]
pub fn mpc_execution_id(session_id: String, purpose: String) -> Vec<u8> {
    aux_info::execution_id(&session_id, &purpose).to_vec()
}

/// Whether the bytes are a complete, usable device share.
#[frb]
pub fn mpc_is_valid_device_share(device_share: Vec<u8>) -> bool {
    DeviceShare::from_bytes(&device_share)
        .ok()
        .and_then(|s| aux_info::from_device_share(&s).ok())
        .is_some()
}

/// Wallet address (EIP-55) a device share belongs to.
#[frb]
pub fn mpc_wallet_address_from_device_share(device_share: Vec<u8>) -> Result<String, String> {
    let share = DeviceShare::from_bytes(&device_share).map_err(|e| e.to_string())?;
    let full = aux_info::from_device_share(&share).map_err(|e| e.to_string())?;
    aux_info::wallet_address(&full).map_err(|e| e.to_string())
}

/// Check that a 65-byte signature over `tx_hash` recovers to `expected_address`.
#[frb]
pub fn mpc_verify_signature_recovers_address(
    signature: Vec<u8>,
    tx_hash: Vec<u8>,
    expected_address: String,
) -> Result<bool, String> {
    let sig: [u8; 65] = signature
        .as_slice()
        .try_into()
        .map_err(|_| format!("signature must be 65 bytes, got {}", signature.len()))?;
    Ok(khodpay_mpc_tss::verify_signature_recovers_address(
        &sig,
        bytes32("tx_hash", &tx_hash)?,
        &expected_address,
    ))
}

// =============================================================================
// PART 7: WPGP GATEWAY — BUSINESS REGISTRATION (US-009.1)
//
// ABI encoding and decoding for the gateway calls the registration wizard
// makes, so the app holds no hand-written ABI code.
// =============================================================================

const REGISTER_BUSINESS_SIGNATURE: &str =
    "registerBusiness(bytes32,address,string,string,uint256,bytes)";

fn abi_selector(signature: &str) -> [u8; 4] {
    let h = khodpay_signing::eip712::keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn abi_word_u64(value: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&value.to_be_bytes());
    w
}

fn abi_push_dynamic(tail: &mut Vec<u8>, data: &[u8]) {
    tail.extend_from_slice(&abi_word_u64(data.len() as u64));
    tail.extend_from_slice(data);
    let pad = (32 - data.len() % 32) % 32;
    tail.extend(std::iter::repeat(0u8).take(pad));
}

fn parse_address_20(label: &str, value: &str) -> Result<[u8; 20], String> {
    let raw = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(raw).map_err(|e| format!("Invalid {}: {}", label, e))?;
    bytes
        .try_into()
        .map_err(|_| format!("{} must be 20 bytes", label))
}

fn decimal_from_be_word(word: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    let mut number = word.to_vec();
    while number.iter().any(|b| *b != 0) {
        let mut rem = 0u32;
        for b in number.iter_mut() {
            let cur = (rem << 8) | *b as u32;
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        return "0".to_string();
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

/// The 4-byte selector of the gateway `registerBusiness` call, as `0x` hex.
#[frb]
pub fn wpgp_register_business_selector() -> String {
    format!("0x{}", hex::encode(abi_selector(REGISTER_BUSINESS_SIGNATURE)))
}

/// A random 32-byte business id from the operating system's CSPRNG.
#[frb]
pub fn wpgp_generate_business_id() -> Result<Vec<u8>, String> {
    let mut id = [0u8; 32];
    getrandom::getrandom(&mut id).map_err(|e| format!("Random source failed: {}", e))?;
    Ok(id.to_vec())
}

/// Call data (`0x` hex) for
/// `registerBusiness(bytes32,address,string,string,uint256,bytes)`.
#[frb]
pub fn wpgp_encode_register_business(
    business_id: Vec<u8>,
    owner_address: String,
    name: String,
    metadata_uri: String,
    permit_expires_at: u64,
    platform_signature: Vec<u8>,
) -> Result<String, String> {
    let id = bytes32("business_id", &business_id)?;
    let owner = parse_address_20("owner_address", &owner_address)?;

    let mut tail = Vec::new();
    let name_offset = 6 * 32;
    abi_push_dynamic(&mut tail, name.as_bytes());
    let metadata_offset = name_offset + tail.len();
    abi_push_dynamic(&mut tail, metadata_uri.as_bytes());
    let signature_offset = name_offset + tail.len();
    abi_push_dynamic(&mut tail, &platform_signature);

    let mut out = Vec::with_capacity(4 + name_offset + tail.len());
    out.extend_from_slice(&abi_selector(REGISTER_BUSINESS_SIGNATURE));
    out.extend_from_slice(&id);
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&owner);
    out.extend_from_slice(&abi_word_u64(name_offset as u64));
    out.extend_from_slice(&abi_word_u64(metadata_offset as u64));
    out.extend_from_slice(&abi_word_u64(permit_expires_at));
    out.extend_from_slice(&abi_word_u64(signature_offset as u64));
    out.extend_from_slice(&tail);
    Ok(format!("0x{}", hex::encode(out)))
}

/// Gateway custom errors that `registerBusiness` can fail with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayRevertKind {
    MetadataTooLarge,
    PermitExpired,
    PermitWrongAction,
    PermitNonceStale,
    InvalidPermitSignature,
    BusinessIdAlreadyExists,
    ActivationDepositTooSmall,
    ActivationTargetsNotConfigured,
    /// No revert data, or an error the gateway does not define.
    Unknown,
}

/// A decoded gateway revert. `args` are the error's `uint256` arguments as
/// decimal strings, in order (empty for `BusinessIdAlreadyExists`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRevert {
    pub kind: GatewayRevertKind,
    pub args: Vec<String>,
}

const GATEWAY_ERRORS: [(&str, GatewayRevertKind); 8] = [
    ("MetadataTooLarge(uint256,uint256)", GatewayRevertKind::MetadataTooLarge),
    ("PermitExpired(uint256,uint256)", GatewayRevertKind::PermitExpired),
    ("PermitWrongAction()", GatewayRevertKind::PermitWrongAction),
    ("PermitNonceStale(uint256,uint256)", GatewayRevertKind::PermitNonceStale),
    ("InvalidPermitSignature()", GatewayRevertKind::InvalidPermitSignature),
    ("BusinessIdAlreadyExists(bytes32)", GatewayRevertKind::BusinessIdAlreadyExists),
    (
        "ActivationDepositTooSmall(uint256,uint256)",
        GatewayRevertKind::ActivationDepositTooSmall,
    ),
    (
        "ActivationTargetsNotConfigured()",
        GatewayRevertKind::ActivationTargetsNotConfigured,
    ),
];

/// Decode revert data (`0x` hex, or `None`) into a [`GatewayRevert`].
/// Never fails: anything unrecognised yields `Unknown`.
#[frb]
pub fn wpgp_decode_gateway_revert(revert_data: Option<String>) -> GatewayRevert {
    let unknown = GatewayRevert {
        kind: GatewayRevertKind::Unknown,
        args: Vec::new(),
    };
    let Some(text) = revert_data else {
        return unknown;
    };
    let Ok(bytes) = hex::decode(text.trim().trim_start_matches("0x")) else {
        return unknown;
    };
    if bytes.len() < 4 {
        return unknown;
    }
    let Some((_, kind)) = GATEWAY_ERRORS
        .iter()
        .find(|(sig, _)| abi_selector(sig) == bytes[..4])
    else {
        return unknown;
    };
    let args = if *kind == GatewayRevertKind::BusinessIdAlreadyExists {
        Vec::new()
    } else {
        bytes[4..]
            .chunks_exact(32)
            .map(decimal_from_be_word)
            .collect()
    };
    GatewayRevert { kind: *kind, args }
}

/// The gateway's on-chain record of a business.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WpgpBusinessInfo {
    pub status: u8,
    pub owner: String,
    pub trust_level: u8,
    pub name: String,
    pub metadata_uri: String,
    pub registered_at: u64,
    pub updated_at: u64,
}

fn info_word<'a>(data: &'a [u8], offset: usize, field: &str) -> Result<&'a [u8], String> {
    data.get(offset..offset + 32)
        .ok_or_else(|| format!("Field {} is out of bounds", field))
}

fn info_u64(data: &[u8], offset: usize, field: &str) -> Result<u64, String> {
    let w = info_word(data, offset, field)?;
    if w[..24].iter().any(|b| *b != 0) {
        return Err(format!("Field {} is out of range", field));
    }
    Ok(u64::from_be_bytes(w[24..].try_into().expect("8 bytes")))
}

fn info_small(data: &[u8], offset: usize, field: &str) -> Result<u8, String> {
    let v = info_u64(data, offset, field)?;
    u8::try_from(v).map_err(|_| format!("Field {} is out of range", field))
}

fn info_string(data: &[u8], base: usize, rel: usize, field: &str) -> Result<String, String> {
    let len = info_u64(data, base + rel, field)? as usize;
    let start = base + rel + 32;
    let bytes = data
        .get(start..start.checked_add(len).ok_or("length overflow")?)
        .ok_or_else(|| format!("Field {} data is out of bounds", field))?;
    String::from_utf8(bytes.to_vec()).map_err(|_| format!("Field {} is not valid UTF-8", field))
}

/// Decode the `eth_call` result of `getBusinessInfo(bytes32)`: the 7-field
/// struct `status, owner, trustLevel, name, metadataURI, registeredAt,
/// updatedAt`. Rejects malformed data and any other layout.
#[frb]
pub fn wpgp_decode_business_info(result_hex: String) -> Result<WpgpBusinessInfo, String> {
    let data = hex::decode(result_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("Result is not hex: {}", e))?;
    if data.len() % 32 != 0 {
        return Err("Result is not word-aligned".to_string());
    }
    const BASE: usize = 32;
    const HEAD: usize = 7 * 32;
    if data.len() < BASE + HEAD {
        return Err(format!("Result too short for 7-field layout: {} bytes", data.len()));
    }
    if info_u64(&data, 0, "outer offset")? != BASE as u64 {
        return Err("Unexpected outer offset".to_string());
    }

    let status = info_small(&data, BASE, "status")?;
    let owner_word = info_word(&data, BASE + 32, "owner")?;
    if owner_word[..12].iter().any(|b| *b != 0) {
        return Err("Field owner out of range".to_string());
    }
    let owner = format!("0x{}", hex::encode(&owner_word[12..]));
    let trust_level = info_small(&data, BASE + 64, "trustLevel")?;
    let name_offset = info_u64(&data, BASE + 96, "nameOffset")? as usize;
    let metadata_offset = info_u64(&data, BASE + 128, "metadataURIOffset")? as usize;
    let registered_at = info_u64(&data, BASE + 160, "registeredAt")?;
    let updated_at = info_u64(&data, BASE + 192, "updatedAt")?;

    if name_offset != HEAD {
        return Err(format!(
            "Unexpected name offset {} (expected {}); response is not the 7-field layout",
            name_offset, HEAD
        ));
    }
    let padded = |len: usize| len.div_ceil(32) * 32;
    let name_len = info_u64(&data, BASE + name_offset, "name length")? as usize;
    let expected_metadata = name_offset + 32 + padded(name_len);
    if metadata_offset != expected_metadata {
        return Err(format!(
            "Unexpected metadataURI offset {} (expected {})",
            metadata_offset, expected_metadata
        ));
    }
    let metadata_len = info_u64(&data, BASE + metadata_offset, "metadataURI length")? as usize;
    let expected_total = BASE + metadata_offset + 32 + padded(metadata_len);
    if data.len() != expected_total {
        return Err(format!(
            "Unexpected result length {} (expected {})",
            data.len(),
            expected_total
        ));
    }

    Ok(WpgpBusinessInfo {
        status,
        owner,
        trust_level,
        name: info_string(&data, BASE, name_offset, "name")?,
        metadata_uri: info_string(&data, BASE, metadata_offset, "metadataURI")?,
        registered_at,
        updated_at,
    })
}

// =============================================================================
// Integration tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── MPC helpers ───────────────────────────────────────────────────────────

    #[test]
    fn test_mpc_session_id_bounds() {
        assert!(mpc_validate_session_id("a").is_ok());
        assert!(mpc_validate_session_id(&"a".repeat(MPC_MAX_SESSION_ID_LEN)).is_ok());
        assert!(mpc_validate_session_id("").is_err());
        assert!(mpc_validate_session_id(&"a".repeat(MPC_MAX_SESSION_ID_LEN + 1)).is_err());
    }

    #[test]
    fn test_mpc_take_payload_is_none_when_nothing_to_send() {
        let mut held = Vec::new();
        assert_eq!(mpc_take_payload(&mut held, Vec::new()).unwrap(), None);
    }

    #[test]
    fn test_mpc_take_payload_sends_held_messages_once() {
        let message = |n: u8| WireMessage {
            sender: 0,
            is_broadcast: true,
            phase: 0,
            recipient: None,
            payload: vec![n],
        };
        let mut held = vec![message(1)];
        let first = mpc_take_payload(&mut held, vec![message(2)]).unwrap().unwrap();
        assert_eq!(decode_batch(&first).unwrap(), vec![message(1), message(2)]);
        assert!(held.is_empty());
        assert_eq!(mpc_take_payload(&mut held, Vec::new()).unwrap(), None);
    }

    // ── MpcDkgSession ─────────────────────────────────────────────────────────
    const TEST_PASSPHRASE: &str = "correct horse battery";
    #[test]
    fn test_dkg_create_rejects_empty_session_id() {
        let err = MpcDkgSession::create(String::new(), None, None, TEST_PASSPHRASE.into()).unwrap_err();
        assert!(err.contains("session_id"), "unexpected error: {err}");
    }
    #[test]
    fn test_dkg_create_rejects_invalid_primes() {
        let err = MpcDkgSession::create(
            "session".into(),
            Some(vec![1, 2, 3]),
            None,
            TEST_PASSPHRASE.into(),
        )
        .unwrap_err();
        assert!(err.contains("primes"), "unexpected error: {err}");
    }
    #[test]
    fn test_dkg_create_rejects_a_short_passphrase() {
        let err = MpcDkgSession::create("session".into(), None, None, "short".into()).unwrap_err();
        assert!(err.contains("passphrase"), "unexpected error: {err}");
    }
    // ── Recovery backup ───────────────────────────────────────────────────────
    const FAST_KDF: MpcKdfParams = MpcKdfParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };
    const ADDRESS: &str = "0x1111111111111111111111111111111111111111";
    #[test]
    fn test_passphrase_rules() {
        assert!(mpc_validate_passphrase("short".into()).is_err());
        assert!(mpc_validate_passphrase("ten chars!!".into()).is_ok());
        assert!(mpc_validate_passphrase("é".repeat(10)).is_ok(), "length counts characters");
        assert!(mpc_validate_passphrase("a".repeat(MPC_MAX_PASSPHRASE_BYTES + 1)).is_err());
        assert_eq!(mpc_min_passphrase_chars(), 10);
    }
    #[test]
    fn test_backup_header_is_readable_without_the_passphrase() {
        let backup =
            mpc_encrypt_recovery_share(b"payload", ADDRESS, TEST_PASSPHRASE, FAST_KDF).unwrap();
        assert_eq!(mpc_recovery_backup_wallet_address(backup.clone()).unwrap(), ADDRESS);
        assert!(!backup.windows(7).any(|w| w == b"payload"), "share must not appear in clear");
    }
    #[test]
    fn test_backup_is_randomised() {
        let a = mpc_encrypt_recovery_share(b"x", ADDRESS, TEST_PASSPHRASE, FAST_KDF).unwrap();
        let b = mpc_encrypt_recovery_share(b"x", ADDRESS, TEST_PASSPHRASE, FAST_KDF).unwrap();
        assert_ne!(a, b, "salt and nonce must differ per backup");
    }
    #[test]
    fn test_backup_with_wrong_passphrase_or_tampering_is_refused() {
        let backup =
            mpc_encrypt_recovery_share(b"payload", ADDRESS, TEST_PASSPHRASE, FAST_KDF).unwrap();
        let err = mpc_unlock_recovery_backup(backup.clone(), "another passphrase".into()).unwrap_err();
        assert!(err.contains("wrong passphrase"), "unexpected error: {err}");
        // Flipping any byte, in the ciphertext or in the authenticated header
        // (including the wallet address), is detected.
        for at in [backup.len() - 1, 20, 40, 60] {
            let mut tampered = backup.clone();
            tampered[at] ^= 0x01;
            assert!(
                mpc_unlock_recovery_backup(tampered, TEST_PASSPHRASE.into()).is_err(),
                "tampering at byte {at} must be detected"
            );
        }
    }
    #[test]
    fn test_backup_opens_with_the_right_passphrase_then_checks_the_share() {
        // The encryption layer accepts the right passphrase; the content here
        // is not a recovery share, so the share check refuses it.
        let backup =
            mpc_encrypt_recovery_share(b"payload", ADDRESS, TEST_PASSPHRASE, FAST_KDF).unwrap();
        let err = mpc_unlock_recovery_backup(backup, TEST_PASSPHRASE.into()).unwrap_err();
        assert!(!err.contains("wrong passphrase"), "unexpected error: {err}");
    }
    #[test]
    fn test_backup_rejects_garbage_and_unsafe_settings() {
        assert!(mpc_recovery_backup_wallet_address(vec![1, 2, 3]).is_err());
        assert!(mpc_unlock_recovery_backup(vec![0u8; 100], TEST_PASSPHRASE.into()).is_err());
        let mut backup =
            mpc_encrypt_recovery_share(b"x", ADDRESS, TEST_PASSPHRASE, FAST_KDF).unwrap();
        // A header asking for 4 GiB of memory must be refused, not attempted.
        backup[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = mpc_unlock_recovery_backup(backup, TEST_PASSPHRASE.into()).unwrap_err();
        assert!(err.contains("unsupported"), "unexpected error: {err}");
    }
    #[test]
    fn test_backup_rejects_a_short_passphrase() {
        assert!(mpc_encrypt_recovery_share(b"x", ADDRESS, "short", FAST_KDF).is_err());
    }
    /// Device (bridge sessions) against a server-side party, over encoded
    /// batches: the complete 2-of-3 DKG, then a signature with the device
    /// share, one with the unlocked recovery share, and one with both shares
    /// and no server. Slow because of prime generation:
    /// `cargo test -p khodpay-flutter-bridge --release -- --ignored device_sessions`.
    #[test]
    #[ignore = "generates Paillier primes; slow, run explicitly with --ignored"]
    fn test_device_sessions_complete_dkg_and_sign_against_a_server_party() {
        use khodpay_mpc_tss::dkg_flow::{DkgParty, PARTIES, THRESHOLD};
        let dkg_id = "bridge-e2e-dkg";
        // The server generates its primes in the background while the device
        // generates its own here, as the app would ahead of time.
        let mut server = DkgParty::new_threshold(
            PARTY_SERVER,
            PARTIES,
            THRESHOLD,
            dkg_id,
            PrimesSource::generate_in_background(),
        );
        let device_primes = mpc_generate_primes().expect("primes");
        let recovery_primes = mpc_generate_primes().expect("primes");
        let server_first = server.step(Vec::new()).unwrap();
        let device = MpcDkgSession::create(
            dkg_id.into(),
            Some(device_primes),
            Some(recovery_primes),
            TEST_PASSPHRASE.into(),
        )
        .unwrap();
        let mut for_device = server_first.outgoing;
        let mut for_server: Vec<WireMessage> = Vec::new();
        let (mut device_done, mut server_share): (Option<MpcDkgAdvanceResult>, _) = (None, None);
        for _ in 0..300 {
            let mut progressed = false;
            if device_done.is_none() {
                let batch = encode_batch(&std::mem::take(&mut for_device)).unwrap();
                let result = device.advance(batch).unwrap();
                if let Some(payload) = &result.next_payload {
                    for_server.extend(decode_batch(payload).unwrap());
                    progressed = true;
                }
                if result.is_complete {
                    progressed = true;
                    device_done = Some(result);
                }
            }
            if server_share.is_none() {
                let step = server.step(std::mem::take(&mut for_server)).unwrap();
                progressed |= !step.outgoing.is_empty() || step.output.is_some();
                for_device.extend(step.outgoing);
                server_share = step.output;
            }
            if device_done.is_some() && server_share.is_some() {
                break;
            }
            assert!(progressed, "DKG stalled");
        }
        let device_done = device_done.expect("device finished");
        let server_share = server_share.expect("server finished");
        let address = device_done.wallet_address.clone().expect("wallet address");
        assert_eq!(address, aux_info::wallet_address(&server_share).unwrap());
        let device_share = device_done.device_share.expect("device share");
        let backup = device_done.recovery_backup.expect("recovery backup");
        // The device cannot be advanced again after it finished.
        assert!(device.advance(Vec::new()).is_err());

        // What the shares say about themselves.
        let info = mpc_share_info(device_share.clone()).unwrap();
        assert_eq!((info.party_index, info.parties, info.threshold), (0, 3, 2));
        assert_eq!(info.wallet_address, address);
        assert_eq!(mpc_recovery_backup_wallet_address(backup.clone()).unwrap(), address);

        // The backup needs the passphrase, and opens with it.
        assert!(mpc_unlock_recovery_backup(backup.clone(), "not the passphrase".into()).is_err());
        let recovery_share = mpc_unlock_recovery_backup(backup.clone(), TEST_PASSPHRASE.into()).unwrap();
        let rinfo = mpc_share_info(recovery_share.clone()).unwrap();
        assert_eq!((rinfo.party_index, rinfo.wallet_address.as_str()), (2, address.as_str()));

        // Changing the passphrase re-encrypts the same share.
        let renewed = mpc_change_recovery_passphrase(
            backup,
            TEST_PASSPHRASE.into(),
            "a brand new passphrase".into(),
        )
        .unwrap();
        assert!(mpc_unlock_recovery_backup(renewed.clone(), TEST_PASSPHRASE.into()).is_err());
        assert_eq!(
            mpc_unlock_recovery_backup(renewed, "a brand new passphrase".into()).unwrap().len(),
            recovery_share.len()
        );

        let hash = [0x42u8; 32];
        // Device share with the server, then recovery share with the server.
        for (name, share) in [("device", device_share.clone()), ("recovery", recovery_share.clone())] {
            let sign_id = format!("bridge-e2e-sign-{name}");
            let own = mpc_share_info(share.clone()).unwrap().party_index;
            let mut group = vec![own, PARTY_SERVER];
            group.sort_unstable();
            let server_pos = aux_info::signing_position(&group, PARTY_SERVER).unwrap();
            let mut server_sign = aux_info::spawn_signing_subset(
                server_pos,
                group,
                aux_info::execution_id(&sign_id, "sign"),
                server_share.clone(),
                hash,
            );
            let server_first = server_sign.step(Vec::new()).unwrap();
            let device_sign =
                MpcSigningSession::create(sign_id, share, hash.to_vec()).unwrap();
            let mut for_device = server_first.outgoing;
            let mut for_server: Vec<WireMessage> = Vec::new();
            let (mut device_sig, mut server_sig): (Option<Vec<u8>>, Option<[u8; 65]>) = (None, None);
            for _ in 0..100 {
                let mut progressed = false;
                if device_sig.is_none() {
                    let batch = encode_batch(&std::mem::take(&mut for_device)).unwrap();
                    let result = device_sign.advance(batch).unwrap();
                    if let Some(payload) = &result.next_payload {
                        for_server.extend(decode_batch(payload).unwrap());
                        progressed = true;
                    }
                    if result.is_complete {
                        progressed = true;
                        device_sig = result.signature;
                    }
                }
                if server_sig.is_none() {
                    let step = server_sign.step(std::mem::take(&mut for_server)).unwrap();
                    progressed |= !step.outgoing.is_empty() || step.output.is_some();
                    for_device.extend(step.outgoing);
                    server_sig = step.output;
                }
                if device_sig.is_some() && server_sig.is_some() {
                    break;
                }
                assert!(progressed, "signing stalled ({name})");
            }
            let device_sig = device_sig.expect("device signature");
            let server_sig = server_sig.expect("server signature");
            assert_eq!(device_sig, server_sig.to_vec(), "{name}");
            assert!(
                khodpay_mpc_tss::verify_signature_recovers_address(&server_sig, hash, &address),
                "{name}"
            );
        }

        // A second device receives a copy of the device share, and it is
        // the same share; the recovery share cannot be exported this way.
        let request = mpc_pairing_new_request();
        let package = mpc_pairing_export_share(device_share.clone(), request.public_key.clone()).unwrap();
        let imported = mpc_pairing_import_share(request.secret_key, package).unwrap();
        assert_eq!(imported, device_share);
        assert!(mpc_pairing_export_share(recovery_share.clone(), request.public_key).is_err());

        // Both user shares together, no server.
        let local = mpc_sign_locally(device_share, recovery_share, hash.to_vec()).unwrap();
        let local: [u8; 65] = local.try_into().expect("65 bytes");
        assert!(khodpay_mpc_tss::verify_signature_recovers_address(&local, hash, &address));
    }
    // ── Pairing ───────────────────────────────────────────────────────────────
    #[test]
    fn test_pairing_package_opens_only_with_the_matching_secret_key() {
        let request = mpc_pairing_new_request();
        assert_eq!(request.public_key.len(), 33);
        assert_eq!(request.secret_key.len(), 32);
        let package = mpc_pairing_seal(b"a device share", &request.public_key).unwrap();
        assert!(!package.windows(14).any(|w| w == b"a device share"));
        assert_eq!(
            mpc_pairing_open(&package, &request.secret_key).unwrap(),
            b"a device share"
        );
        let other = mpc_pairing_new_request();
        assert!(mpc_pairing_open(&package, &other.secret_key).is_err());
    }
    #[test]
    fn test_pairing_packages_are_randomised() {
        let request = mpc_pairing_new_request();
        let a = mpc_pairing_seal(b"x", &request.public_key).unwrap();
        let b = mpc_pairing_seal(b"x", &request.public_key).unwrap();
        assert_ne!(a, b);
    }
    #[test]
    fn test_pairing_detects_tampering_everywhere() {
        let request = mpc_pairing_new_request();
        let package = mpc_pairing_seal(b"payload", &request.public_key).unwrap();
        for at in [4, 10, 40, 50, package.len() - 1] {
            let mut tampered = package.clone();
            tampered[at] ^= 0x01;
            assert!(
                mpc_pairing_open(&tampered, &request.secret_key).is_err(),
                "tampering at byte {at} must be detected"
            );
        }
    }
    #[test]
    fn test_pairing_rejects_garbage() {
        let request = mpc_pairing_new_request();
        assert!(mpc_pairing_seal(b"x", &[1, 2, 3]).is_err());
        assert!(mpc_pairing_open(&[0u8; 10], &request.secret_key).is_err());
        let package = mpc_pairing_seal(b"x", &request.public_key).unwrap();
        assert!(mpc_pairing_open(&package, &[1, 2, 3]).is_err());
    }
    #[test]
    fn test_pairing_import_refuses_something_that_is_not_a_device_share() {
        let request = mpc_pairing_new_request();
        let package = mpc_pairing_seal(b"not a share", &request.public_key).unwrap();
        assert!(mpc_pairing_import_share(request.secret_key, package).is_err());
    }
    #[test]
    fn test_pairing_export_refuses_something_that_is_not_a_device_share() {
        let request = mpc_pairing_new_request();
        assert!(mpc_pairing_export_share(vec![1, 2, 3], request.public_key).is_err());
    }
    #[test]
    fn test_sign_locally_rejects_bad_input() {
        assert!(mpc_sign_locally(vec![1], vec![2], vec![0u8; 31]).is_err());
        assert!(mpc_sign_locally(vec![1], vec![2], vec![0u8; 32]).is_err());
    }
    // ── MpcSigningSession ─────────────────────────────────────────────────────

    #[test]
    fn test_signing_create_rejects_empty_session_id() {
        let err = MpcSigningSession::create(String::new(), vec![1], vec![0u8; 32]).unwrap_err();
        assert!(err.contains("session_id"), "unexpected error: {err}");
    }

    #[test]
    fn test_signing_create_rejects_empty_share() {
        let err = MpcSigningSession::create("s".into(), vec![], vec![0u8; 32]).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn test_signing_create_rejects_wrong_hash_len() {
        let err = MpcSigningSession::create("s".into(), vec![1, 2, 3], vec![0u8; 31]).unwrap_err();
        assert!(err.contains("32"), "error should mention 32 bytes: {err}");
    }

    #[test]
    fn test_signing_create_rejects_a_share_without_aux_info() {
        // Bytes that are not a complete key share, such as one from the old
        // simulated DKG, must be refused before any ceremony starts.
        let err = MpcSigningSession::create("s".into(), vec![0x01; 64], vec![0u8; 32]).unwrap_err();
        assert!(err.contains("complete key share"), "unexpected error: {err}");
    }

}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn bip39_helpers() {
        assert!(bip39_languages().contains(&bip39_default_language()));
        let info = bip39_word_count_info(12).unwrap();
        assert_eq!((info.words, info.entropy_bytes, info.checksum_bits), (12, 16, 4));
        assert_eq!(bip39_word_counts(), vec![12, 15, 18, 21, 24]);
        assert_eq!(bip39_word_count_for_entropy_length(32).unwrap(), 24);
        assert!(bip39_word_count_info(13).is_err());
        let lang = bip39_default_language();
        assert!(validate_mnemonic_detailed(PHRASE.to_string(), Some(lang.clone())).is_ok());
        assert!(validate_mnemonic_detailed("abandon".to_string(), None).is_err());
        let entropy = mnemonic_to_entropy(PHRASE.to_string(), None).unwrap();
        assert_eq!(entropy, vec![0u8; 16]);
        assert_eq!(
            generate_mnemonic_from_entropy_in_language(entropy, lang.clone()).unwrap(),
            PHRASE
        );
        assert_eq!(
            mnemonic_phrase_to_seed_hex_in_language(PHRASE.to_string(), None, lang).unwrap(),
            mnemonic_phrase_to_seed_hex(PHRASE.to_string(), None).unwrap()
        );
        assert!(parse_language("klingon").is_err());
    }

    #[test]
    fn bip32_helpers() {
        let info = bip32_derivation_path_info("m/44'/60'/0'/0/1".to_string()).unwrap();
        assert_eq!(info.depth, 5);
        assert!(info.contains_hardened);
        assert_eq!(info.hardened_prefix_length, 3);
        assert_eq!(info.components[4], 1);
        assert_eq!(
            bip32_derivation_path_parent("m/44'/60'".to_string()).unwrap().as_deref(),
            Some("m/44'")
        );
        assert_eq!(
            bip32_derivation_path_extend("m/44'".to_string(), vec![bip32_child_number_hardened(60)])
                .unwrap(),
            "m/44'/60'"
        );
        assert!(bip32_derivation_path_starts_with("m/44'/60'".to_string(), "m/44'".to_string()).unwrap());
        let child = bip32_child_number_info(bip32_child_number_hardened(7));
        assert!(child.is_hardened);
        assert_eq!(child.value, 7);
        assert_eq!(bip32_network_info(Network::BitcoinMainnet).xprv_version, 0x0488ADE4);
        assert_eq!(
            bip32_network_version_bytes(Network::BitcoinMainnet, false),
            0x0488B21E
        );
    }

    #[test]
    fn bip32_keys_and_pairs() {
        let seed = hex::decode(mnemonic_phrase_to_seed_hex(PHRASE.to_string(), None).unwrap()).unwrap();
        let pair = bip32_generate_master_keypair(seed.clone(), Network::BitcoinMainnet).unwrap();
        let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet).unwrap();
        assert_eq!(pair.private_key, master.to_extended_string());
        assert_eq!(master.private_key_bytes().len(), 32);
        assert_eq!(master.public_key_bytes().len(), 33);
        assert_eq!(master.public_key_uncompressed().len(), 65);
        assert_eq!(master.chain_code().len(), 32);
        let derived =
            bip32_derive_keypair_from_path(pair.private_key, "m/44'/60'/0'/0/0".to_string()).unwrap();
        let direct = master.derive_path("m/44'/60'/0'/0/0".to_string()).unwrap();
        assert_eq!(derived.private_key, direct.to_extended_string());
        let public = master.to_extended_public_key();
        assert_eq!(public.public_key_bytes(), master.public_key_bytes());
        let priv_hex = hex::encode(master.private_key_bytes());
        assert_eq!(
            bip32_private_key_to_public_key(priv_hex.clone()).unwrap(),
            hex::encode(master.public_key_bytes())
        );
        let tweak = hex::encode([1u8; 32]);
        let tweaked_pub = bip32_public_key_tweak_add(hex::encode(master.public_key_bytes()), tweak.clone()).unwrap();
        let tweaked_priv = bip32_private_key_tweak_add(priv_hex, tweak).unwrap();
        assert_eq!(bip32_private_key_to_public_key(tweaked_priv).unwrap(), tweaked_pub);
        assert_eq!(
            bip32_public_key_to_uncompressed(tweaked_pub).unwrap().len(),
            130
        );
        assert!(bip32_chain_code_from_bytes(vec![0; 31]).is_err());
    }

    #[test]
    fn bip44_paths_and_discovery() {
        let p = bip44_path_parse("m/44'/60'/0'/0/0".to_string()).unwrap();
        assert!(p.is_valid);
        assert_eq!(p.address_index, 0);
        assert_eq!(bip44_path_next_address(p.path.clone()).unwrap().address_index, 1);
        assert_eq!(bip44_path_to_internal(p.path.clone()).unwrap().path, "m/44'/60'/0'/1/0");
        assert_eq!(bip44_path_next_account(p.path.clone()).unwrap().account, 1);
        assert_eq!(bip44_path_to_derivation_path(p.path.clone()).unwrap(), "m/44'/60'/0'/0/0");
        let built = bip44_path_build(Purpose::Bip44, CoinType::Ethereum, 0, Chain::External, 0).unwrap();
        assert_eq!(built.path, p.path);
        assert!(bip44_coin_details(CoinType::Ethereum).is_evm_compatible);
        assert_eq!(bip44_chain_details(Chain::Internal).value, 1);
        assert_eq!(bip44_purpose_details(Purpose::Bip44).value, 44);

        assert_eq!(bip44_find_last_used_index(vec![0, 1, 5], 20, 0).unwrap(), Some(5));
        assert_eq!(bip44_find_last_used_index(vec![], 20, 0).unwrap(), None);
        assert_eq!(bip44_find_used_indices(vec![0, 3], 5, 0).unwrap(), vec![0, 3]);
        let scan = bip44_scan_chain(vec![2], 5, Chain::External).unwrap();
        assert_eq!(scan.last_used_index, Some(2));
        let accounts = bip44_discover_accounts(vec![0], vec![], 5, 2).unwrap();
        assert!(!accounts.is_empty());
    }

    #[test]
    fn bip44_wallet_and_account_extras() {
        let mut wallet =
            Bip44Wallet::from_mnemonic(PHRASE.to_string(), None, Network::BitcoinMainnet).unwrap();
        let account = wallet.get_account(Purpose::Bip44, CoinType::Ethereum, 0).unwrap();
        assert_eq!(wallet.cached_account_count(), 1);
        wallet.clear_cache();
        assert_eq!(wallet.cached_account_count(), 0);
        assert!(!wallet.master_key_string().is_empty());

        let lang = bip39_default_language();
        let w2 = Bip44Wallet::from_mnemonic_in_language(
            PHRASE.to_string(),
            None,
            lang,
            Network::BitcoinMainnet,
        )
        .unwrap();
        assert_eq!(w2.master_key_string(), wallet.master_key_string());

        let info = account.derived_address_info(Chain::External, 0).unwrap();
        assert_eq!(info.address, account.derive_address(Chain::External, 0).unwrap());
        assert_eq!(info.path, "m/44'/60'/0'/0/0");
        let walked = account.iterate_addresses(Chain::External, 0, None, 3).unwrap();
        assert_eq!(walked.len(), 3);
        assert_eq!(walked[0], info.address);
        let capped = account.iterate_addresses(Chain::External, 0, Some(1), 10).unwrap();
        assert_eq!(capped.len(), 2);

        let restored = Bip44Account::from_extended_key(
            account.extended_key_string(),
            Purpose::Bip44,
            CoinType::Ethereum,
            0,
        )
        .unwrap();
        assert_eq!(
            restored.derive_address(Chain::External, 2).unwrap(),
            account.derive_address(Chain::External, 2).unwrap()
        );
    }

    #[test]
    fn signing_helpers() {
        assert_eq!(
            hex::encode(keccak256_bytes(vec![])),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        let addr = "0x00000000000000000000000000000000000000aa".to_string();
        let sep = eip712_domain_separator("WPGP".into(), "1".into(), 97, Some(addr.clone())).unwrap();
        assert_eq!(sep.len(), 32);
        assert_eq!(
            eip712_domain_separator("WPGP".into(), "1".into(), 97, Some(addr.clone())).unwrap(),
            sep
        );
        assert_ne!(
            eip712_domain_separator("WPGP".into(), "1".into(), 56, Some(addr.clone())).unwrap(),
            sep
        );
        assert!(eip712_domain_type_string("WPGP".into(), "1".into(), 97, Some(addr.clone()))
            .unwrap()
            .starts_with("EIP712Domain("));
        assert_eq!(eip712_domain_type_hash("WPGP".into(), "1".into(), 97, None).unwrap().len(), 32);
        assert_eq!(eip712_encode_address(addr).unwrap()[31], 0xaa);
        assert_eq!(eip712_encode_uint256("258".into()).unwrap()[30..], [1, 2]);
        assert_eq!(eip712_encode_uint64(1)[31], 1);
        assert_eq!(eip712_encode_bool(true)[31], 1);
        assert!(eip712_encode_bytes32(vec![0; 31]).is_err());
        assert_eq!(eip712_encode_bytes32(vec![7; 32]).unwrap(), vec![7; 32]);
        assert_eq!(eip712_encode_u256_bytes(vec![0; 32]).unwrap(), vec![0; 32]);
        assert_eq!(eip712_encode_bytes_dynamic(vec![]).len(), 32);

        let limits = erc4337_pack_gas_limits("1".into(), "2".into()).unwrap();
        assert_eq!((limits[15], limits[31]), (1, 2));
        let fees = erc4337_pack_gas_fees("3".into(), "4".into()).unwrap();
        assert_eq!((fees[15], fees[31]), (3, 4));
    }

    #[test]
    fn wei_and_tx_extras() {
        let wei = EvmWei::from_wei_u64(258);
        let bytes = wei.to_be_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(EvmWei::from_be_bytes(bytes).to_decimal_string(), "258");
        assert_eq!(wei.to_u128_string().unwrap().as_deref(), Some("258"));
    }

    #[test]
    fn mpc_helpers() {
        let a = mpc_execution_id("s".into(), "dkg".into());
        assert_eq!(a.len(), 32);
        assert_eq!(a, mpc_execution_id("s".into(), "dkg".into()));
        assert_ne!(a, mpc_execution_id("s".into(), "signing".into()));

        let messages = vec![MpcWireMessage {
            sender: 1,
            is_broadcast: true,
            phase: 2,
            recipient: None,
            payload: vec![9, 8, 7],
        }];
        let decoded = mpc_decode_wire_batch(mpc_encode_wire_batch(messages).unwrap()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!((decoded[0].sender, decoded[0].phase), (1, 2));
        assert_eq!(decoded[0].payload, vec![9, 8, 7]);
        assert!(mpc_decode_wire_batch(vec![0xff, 0xff]).is_err());

        assert!(!mpc_is_valid_device_share(vec![1, 2, 3]));
        assert!(mpc_wallet_address_from_device_share(vec![1, 2, 3]).is_err());
        assert!(mpc_verify_signature_recovers_address(vec![0; 64], vec![0; 32], String::new()).is_err());
        assert!(!mpc_verify_signature_recovers_address(
            vec![0; 65],
            vec![0; 32],
            "0x0000000000000000000000000000000000000000".into()
        )
        .unwrap());
    }
}

#[cfg(test)]
mod gateway_tests {
    use super::*;

    const CAST_REGISTER: &str = "0xf1581a6a1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000006553f10000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000004436166650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000077b2261223a317d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004deadbeef00000000000000000000000000000000000000000000000000000000";

    const CAST_INFO: &str = "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000004436166650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000037572690000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_register_business_matches_cast() {
        let out = wpgp_encode_register_business(
            vec![0x11; 32],
            "0x2222222222222222222222222222222222222222".into(),
            "Cafe".into(),
            "{\"a\":1}".into(),
            1_700_000_000,
            vec![0xde, 0xad, 0xbe, 0xef],
        )
        .unwrap();
        assert_eq!(out, CAST_REGISTER);
        assert_eq!(wpgp_register_business_selector(), "0xf1581a6a");
    }

    #[test]
    fn test_register_business_rejects_bad_inputs() {
        assert!(wpgp_encode_register_business(
            vec![0; 31],
            "0x2222222222222222222222222222222222222222".into(),
            "a".into(),
            "b".into(),
            1,
            vec![]
        )
        .is_err());
        assert!(wpgp_encode_register_business(vec![0; 32], "0x12".into(), "a".into(), "b".into(), 1, vec![]).is_err());
    }

    #[test]
    fn test_business_id_is_random_32_bytes() {
        let a = wpgp_generate_business_id().unwrap();
        let b = wpgp_generate_business_id().unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn test_decode_revert() {
        let selector = hex::encode(abi_selector("ActivationDepositTooSmall(uint256,uint256)"));
        assert_eq!(selector, "a82ee855");
        let data = format!("0x{}{:064x}{:064x}", selector, 5u64, 1_000_000_000_000_000u64);
        let r = wpgp_decode_gateway_revert(Some(data));
        assert_eq!(r.kind, GatewayRevertKind::ActivationDepositTooSmall);
        assert_eq!(r.args, vec!["5".to_string(), "1000000000000000".to_string()]);

        let big = format!("0x{}{}{:064x}", selector, "f".repeat(64), 0u64);
        let r = wpgp_decode_gateway_revert(Some(big));
        assert_eq!(
            r.args[0],
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        assert_eq!(r.args[1], "0");
    }

    #[test]
    fn test_decode_revert_unknown_and_no_arg_errors() {
        assert_eq!(wpgp_decode_gateway_revert(None).kind, GatewayRevertKind::Unknown);
        assert_eq!(wpgp_decode_gateway_revert(Some("0x12".into())).kind, GatewayRevertKind::Unknown);
        assert_eq!(wpgp_decode_gateway_revert(Some("zz".into())).kind, GatewayRevertKind::Unknown);
        assert_eq!(wpgp_decode_gateway_revert(Some("0xdeadbeef".into())).kind, GatewayRevertKind::Unknown);
        let sel = hex::encode(abi_selector("InvalidPermitSignature()"));
        let r = wpgp_decode_gateway_revert(Some(format!("0x{}", sel)));
        assert_eq!(r.kind, GatewayRevertKind::InvalidPermitSignature);
        assert!(r.args.is_empty());
        let sel = hex::encode(abi_selector("BusinessIdAlreadyExists(bytes32)"));
        let r = wpgp_decode_gateway_revert(Some(format!("0x{}{}", sel, "11".repeat(32))));
        assert_eq!(r.kind, GatewayRevertKind::BusinessIdAlreadyExists);
        assert!(r.args.is_empty());
    }

    #[test]
    fn test_decode_business_info_matches_cast() {
        let info = wpgp_decode_business_info(CAST_INFO.into()).unwrap();
        assert_eq!(info.status, 1);
        assert_eq!(info.owner, "0x2222222222222222222222222222222222222222");
        assert_eq!(info.trust_level, 2);
        assert_eq!(info.name, "Cafe");
        assert_eq!(info.metadata_uri, "uri");
        assert_eq!(info.registered_at, 10);
        assert_eq!(info.updated_at, 20);
    }

    #[test]
    fn test_decode_business_info_rejects_malformed() {
        assert!(wpgp_decode_business_info("0x".into()).is_err());
        assert!(wpgp_decode_business_info("0xzz".into()).is_err());
        assert!(wpgp_decode_business_info(CAST_INFO[..CAST_INFO.len() - 64].into()).is_err());
        let extra = format!("{}{}", CAST_INFO, "00".repeat(32));
        assert!(wpgp_decode_business_info(extra).is_err());
    }
}
