//! Flutter Rust Bridge definitions for KhodPay Wallet
//!
//! This module provides both Object-Oriented (struct wrappers) and 
//! Procedural (utility functions) APIs for Flutter integration.

use flutter_rust_bridge::frb;
use khodpay_bip32::{
    ExtendedPrivateKey as RustExtendedPrivateKey,
    ExtendedPublicKey as RustExtendedPublicKey,
    DerivationPath, ChildNumber,
};
use khodpay_bip39::{Mnemonic as RustMnemonic, WordCount, Language};
use khodpay_bip44::{
    Wallet as RustWallet,
    Purpose as RustPurpose,
    CoinType as RustCoinType,
    Chain as RustChain,
    Bip44Path as RustBip44Path,
    Account as RustAccount,
};
use khodpay_signing::{
    Address as RustAddress,
    ChainId as RustChainId,
    Wei as RustWei,
    Signature as RustSignature,
    Eip1559Transaction as RustEip1559Transaction,
    SignedTransaction as RustSignedTransaction,
    Bip44Signer as RustBip44Signer,
    recover_signer as rust_recover_signer,
    TRANSFER_GAS, TOKEN_TRANSFER_GAS, GWEI, ETHER,
};
use std::str::FromStr;

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

        let child = self.inner.derive_child(child_num)
            .map_err(|e| format!("Failed to derive child: {}", e))?;
        
        Ok(Self { inner: child })
    }

    /// Derive using a path string (e.g., "m/44'/0'/0'/0/0")
    #[frb]
    pub fn derive_path(&self, path: String) -> Result<Self, String> {
        let derivation_path = DerivationPath::from_str(&path)
            .map_err(|e| format!("Invalid derivation path: {}", e))?;
        
        let derived = self.inner.derive_path(&derivation_path)
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
        let child = self.inner.derive_child(ChildNumber::Normal(index))
            .map_err(|e| format!("Failed to derive child: {}", e))?;
        Ok(Self { inner: child })
    }

    /// Derive using a path string (only non-hardened paths allowed)
    #[frb]
    pub fn derive_path(&self, path: String) -> Result<Self, String> {
        let derivation_path = DerivationPath::from_str(&path)
            .map_err(|e| format!("Invalid derivation path: {}", e))?;
        
        let derived = self.inner.derive_path(&derivation_path)
            .map_err(|e| format!("Failed to derive path (hardened derivation not allowed): {}", e))?;
        
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
        let account = self.inner
            .get_account(purpose.into(), coin_type.into(), account_index)
            .map_err(|e| format!("Failed to get account: {}", e))?;
        
        Ok(Bip44Account { inner: account.clone() })
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
        let key = self.inner.derive_external(index)
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
        let key = self.inner.derive_internal(index)
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
        let key = self.inner.derive_address(chain.into(), index)
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
        let keys = self.inner.derive_address_range(chain.into(), start, count)
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
        Self { inner: RustAddress::ZERO }
    }

    /// Parse an address from a hex string (with or without 0x prefix)
    #[frb]
    pub fn from_hex(hex_string: String) -> Result<Self, String> {
        let addr = RustAddress::from_str(&hex_string)
            .map_err(|e| format!("Invalid address: {}", e))?;
        Ok(Self { inner: addr })
    }

    /// Create an address from 20 bytes
    #[frb]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let addr = RustAddress::from_slice(&bytes)
            .map_err(|e| format!("Invalid address bytes: {}", e))?;
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
        Self { value_hex: "0".to_string() }
    }

    /// Create Wei from a u64 value (in wei)
    #[frb]
    pub fn from_wei_u64(wei: u64) -> Self {
        let rust_wei = RustWei::from_wei(wei);
        Self { value_hex: rust_wei.to_string() }
    }

    /// Create Wei from a decimal string (in wei)
    #[frb]
    pub fn from_wei_string(wei_string: String) -> Result<Self, String> {
        let rust_wei: RustWei = wei_string.parse()
            .map_err(|e| format!("Invalid wei value: {}", e))?;
        Ok(Self { value_hex: rust_wei.to_string() })
    }

    /// Create Wei from gwei (1 gwei = 10^9 wei)
    #[frb]
    pub fn from_gwei(gwei: u64) -> Self {
        let rust_wei = RustWei::from_gwei(gwei);
        Self { value_hex: rust_wei.to_string() }
    }

    /// Create Wei from ether/BNB (1 ether = 10^18 wei)
    #[frb]
    pub fn from_ether(ether: u64) -> Self {
        let rust_wei = RustWei::from_ether(ether);
        Self { value_hex: rust_wei.to_string() }
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
        let a: RustWei = self.value_hex.parse()
            .map_err(|e| format!("Invalid wei value: {}", e))?;
        let b: RustWei = other.value_hex.parse()
            .map_err(|e| format!("Invalid wei value: {}", e))?;
        Ok(Self { value_hex: (a + b).to_string() })
    }

    /// Multiply Wei by a u64 scalar
    #[frb]
    pub fn multiply(&self, scalar: u64) -> Result<Self, String> {
        let a: RustWei = self.value_hex.parse()
            .map_err(|e| format!("Invalid wei value: {}", e))?;
        Ok(Self { value_hex: (a * scalar).to_string() })
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
        let r = hex::decode(&self.r_hex)
            .map_err(|e| format!("Invalid r hex: {}", e))?;
        let s = hex::decode(&self.s_hex)
            .map_err(|e| format!("Invalid s hex: {}", e))?;
        
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
        let r = hex::decode(&sig.r_hex)
            .map_err(|e| format!("Invalid r hex: {}", e))?;
        let s = hex::decode(&sig.s_hex)
            .map_err(|e| format!("Invalid s hex: {}", e))?;
        
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
        let max_priority_fee: RustWei = self.max_priority_fee_per_gas.parse()
            .map_err(|e| format!("Invalid max_priority_fee_per_gas: {}", e))?;
        let max_fee: RustWei = self.max_fee_per_gas.parse()
            .map_err(|e| format!("Invalid max_fee_per_gas: {}", e))?;
        let value: RustWei = self.value.parse()
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
            let addr = RustAddress::from_str(to_addr)
                .map_err(|e| format!("Invalid to address: {}", e))?;
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
            chain_id: self.chain_id.clone()
                .ok_or_else(|| "chain_id is required".to_string())?,
            nonce: self.nonce
                .ok_or_else(|| "nonce is required".to_string())?,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas.clone()
                .ok_or_else(|| "max_priority_fee_per_gas is required".to_string())?,
            max_fee_per_gas: self.max_fee_per_gas.clone()
                .ok_or_else(|| "max_fee_per_gas is required".to_string())?,
            gas_limit: self.gas_limit
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
        Self { transaction, signature }
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
        let hex_str = private_key_hex.strip_prefix("0x").unwrap_or(&private_key_hex);
        let bytes = hex::decode(hex_str)
            .map_err(|e| format!("Invalid private key hex: {}", e))?;
        
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
        EvmAddress { inner: self.inner.address() }
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
        
        let sig = self.inner.sign_hash(&hash_arr)
            .map_err(|e| format!("Signing failed: {}", e))?;
        
        Ok(sig.into())
    }

    /// Sign an EIP-1559 transaction
    #[frb]
    pub fn sign_transaction(&self, tx: &Eip1559Transaction) -> Result<EvmSignature, String> {
        let rust_tx = tx.to_rust_transaction()?;
        let sig = self.inner.sign_transaction(&rust_tx)
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
        Self { address, storage_keys }
    }

    /// Create an access list item with only an address (no storage keys)
    #[frb]
    pub fn address_only(address: String) -> Self {
        Self { address, storage_keys: Vec::new() }
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
pub fn mnemonic_phrase_to_seed_hex(phrase: String, passphrase: Option<String>) -> Result<String, String> {
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

    let master_key = RustExtendedPrivateKey::from_mnemonic(
        &mnemonic,
        passphrase.as_deref(),
        network.into(),
    )
    .map_err(|e| format!("Failed to create master key: {}", e))?;

    Ok(master_key.to_string())
}

/// Derive a child key from an extended private key using a derivation path
#[frb]
pub fn derive_key(
    extended_key: String,
    derivation_path: String,
) -> Result<String, String> {
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
pub fn get_address(
    extended_private_key: String,
    address_index: u32,
) -> Result<String, String> {
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

    let master_key = RustExtendedPrivateKey::from_mnemonic(
        &mnemonic,
        passphrase.as_deref(),
        network.into(),
    )
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
    let bip44_path = RustBip44Path::from_str(&path)
        .map_err(|e| format!("Invalid BIP44 path: {}", e))?;

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
    let addr = RustAddress::from_str(&address)
        .map_err(|e| format!("Invalid address: {}", e))?;
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
    let hex_str = private_key_hex.strip_prefix("0x").unwrap_or(&private_key_hex);
    let key_bytes = hex::decode(hex_str)
        .map_err(|e| format!("Invalid private key hex: {}", e))?;
    
    if key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }
    
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    
    let signer = RustBip44Signer::from_private_key(&key_arr)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    // Parse recipient address
    let to_addr = RustAddress::from_str(&to)
        .map_err(|e| format!("Invalid to address: {}", e))?;

    // Parse value
    let value: RustWei = value_wei.parse()
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
    let signature = signer.sign_transaction(&tx)
        .map_err(|e| format!("Failed to sign transaction: {}", e))?;

    // Create signed transaction
    let signed = RustSignedTransaction::new(tx, signature);

    Ok(signed.to_raw_transaction())
}

/// Recover signer address from a signature and message hash
#[frb]
pub fn recover_signer_address(
    hash_hex: String,
    signature_hex: String,
) -> Result<String, String> {
    // Parse hash
    let hash_str = hash_hex.strip_prefix("0x").unwrap_or(&hash_hex);
    let hash_bytes = hex::decode(hash_str)
        .map_err(|e| format!("Invalid hash hex: {}", e))?;
    
    if hash_bytes.len() != 32 {
        return Err("Hash must be 32 bytes".to_string());
    }
    
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash_bytes);

    // Parse signature (65 bytes: r || s || v)
    let sig_str = signature_hex.strip_prefix("0x").unwrap_or(&signature_hex);
    let sig_bytes = hex::decode(sig_str)
        .map_err(|e| format!("Invalid signature hex: {}", e))?;
    
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
    let hex_str = private_key_hex.strip_prefix("0x").unwrap_or(&private_key_hex);
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("Invalid private key hex: {}", e))?;
    
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
