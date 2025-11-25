//! Flutter Rust Bridge definitions for KhodPay Wallet
//!
//! This module provides both Object-Oriented (struct wrappers) and 
//! Procedural (utility functions) APIs for Flutter integration.

use flutter_rust_bridge::frb;
use khodpay_bip32::{
    ExtendedPrivateKey as RustExtendedPrivateKey,
    ExtendedPublicKey as RustExtendedPublicKey,
    Network, DerivationPath, ChildNumber,
};
use khodpay_bip39::{Mnemonic as RustMnemonic, WordCount, Language};
use khodpay_bip44::{
    Wallet as RustWallet,
    Purpose as RustPurpose,
    CoinType as RustCoinType,
    Chain as RustChain,
    Bip44Path as RustBip44Path,
};
use std::str::FromStr;

// =============================================================================
// PART 1: ENUMS AND DATA TYPES
// =============================================================================

/// Network type for the wallet
#[frb]
#[derive(Debug, Clone, Copy)]
pub enum NetworkType {
    BitcoinMainnet,
    BitcoinTestnet,
}

impl From<NetworkType> for Network {
    fn from(nt: NetworkType) -> Self {
        match nt {
            NetworkType::BitcoinMainnet => Network::BitcoinMainnet,
            NetworkType::BitcoinTestnet => Network::BitcoinTestnet,
        }
    }
}

impl From<Network> for NetworkType {
    fn from(n: Network) -> Self {
        match n {
            Network::BitcoinMainnet => NetworkType::BitcoinMainnet,
            Network::BitcoinTestnet => NetworkType::BitcoinTestnet,
        }
    }
}

/// BIP44 Purpose types (derivation standards)
#[frb]
#[derive(Debug, Clone, Copy)]
pub enum PurposeType {
    BIP44,
    BIP49,
    BIP84,
    BIP86,
}

impl From<PurposeType> for RustPurpose {
    fn from(pt: PurposeType) -> Self {
        match pt {
            PurposeType::BIP44 => RustPurpose::BIP44,
            PurposeType::BIP49 => RustPurpose::BIP49,
            PurposeType::BIP84 => RustPurpose::BIP84,
            PurposeType::BIP86 => RustPurpose::BIP86,
        }
    }
}

impl From<RustPurpose> for PurposeType {
    fn from(p: RustPurpose) -> Self {
        match p {
            RustPurpose::BIP44 => PurposeType::BIP44,
            RustPurpose::BIP49 => PurposeType::BIP49,
            RustPurpose::BIP84 => PurposeType::BIP84,
            RustPurpose::BIP86 => PurposeType::BIP86,
        }
    }
}

/// BIP44 Coin types (cryptocurrencies)
#[frb]
#[derive(Debug, Clone, Copy)]
pub enum CoinType {
    Bitcoin,
    BitcoinTestnet,
    Litecoin,
    Dogecoin,
    Ethereum,
    Custom(u32),
}

impl From<CoinType> for RustCoinType {
    fn from(ct: CoinType) -> Self {
        match ct {
            CoinType::Bitcoin => RustCoinType::Bitcoin,
            CoinType::BitcoinTestnet => RustCoinType::BitcoinTestnet,
            CoinType::Litecoin => RustCoinType::Litecoin,
            CoinType::Dogecoin => RustCoinType::Dogecoin,
            CoinType::Ethereum => RustCoinType::Ethereum,
            CoinType::Custom(index) => RustCoinType::Custom(index),
        }
    }
}

impl From<RustCoinType> for CoinType {
    fn from(ct: RustCoinType) -> Self {
        match ct {
            RustCoinType::Bitcoin => CoinType::Bitcoin,
            RustCoinType::BitcoinTestnet => CoinType::BitcoinTestnet,
            RustCoinType::Litecoin => CoinType::Litecoin,
            RustCoinType::Dogecoin => CoinType::Dogecoin,
            RustCoinType::Ethereum => CoinType::Ethereum,
            RustCoinType::Custom(index) => CoinType::Custom(index),
            _ => CoinType::Custom(ct.index()),
        }
    }
}

/// BIP44 Chain type (external/internal)
#[frb]
#[derive(Debug, Clone, Copy)]
pub enum ChainType {
    External,
    Internal,
}

impl From<ChainType> for RustChain {
    fn from(ct: ChainType) -> Self {
        match ct {
            ChainType::External => RustChain::External,
            ChainType::Internal => RustChain::Internal,
        }
    }
}

impl From<RustChain> for ChainType {
    fn from(c: RustChain) -> Self {
        match c {
            RustChain::External => ChainType::External,
            RustChain::Internal => ChainType::Internal,
        }
    }
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
    pub fn from_seed(seed: Vec<u8>, network: NetworkType) -> Result<Self, String> {
        let key = RustExtendedPrivateKey::from_seed(&seed, network.into())
            .map_err(|e| format!("Failed to create key from seed: {}", e))?;
        Ok(Self { inner: key })
    }

    /// Create master key from mnemonic
    #[frb]
    pub fn from_mnemonic(
        mnemonic: &Mnemonic,
        passphrase: Option<String>,
        network: NetworkType,
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
    pub fn network(&self) -> NetworkType {
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
    pub fn network(&self) -> NetworkType {
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
        network: NetworkType,
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
    pub fn from_seed(seed: Vec<u8>, network: NetworkType) -> Result<Self, String> {
        let wallet = RustWallet::from_seed(&seed, network.into())
            .map_err(|e| format!("Failed to create wallet: {}", e))?;
        
        Ok(Self { inner: wallet })
    }

    /// Get the network this wallet operates on
    #[frb]
    pub fn network(&self) -> NetworkType {
        self.inner.network().into()
    }

    /// Get an account for a specific coin type
    #[frb]
    pub fn get_account(
        &mut self,
        purpose: PurposeType,
        coin_type: CoinType,
        account_index: u32,
    ) -> Result<Bip44Account, String> {
        let network = self.inner.network();
        let account = self.inner
            .get_account(purpose.into(), coin_type.into(), account_index)
            .map_err(|e| format!("Failed to get account: {}", e))?;
        
        Ok(Bip44Account {
            purpose: purpose,
            coin_type: coin_type,
            account_index,
            network: network.into(),
            account_key: account.extended_key().to_string(),
        })
    }
}

/// Flutter wrapper for BIP44 Account
#[frb]
#[derive(Debug, Clone)]
pub struct Bip44Account {
    pub purpose: PurposeType,
    pub coin_type: CoinType,
    pub account_index: u32,
    pub network: NetworkType,
    pub account_key: String,
}

#[frb]
impl Bip44Account {
    /// Derive an external (receiving) address at the given index
    #[frb]
    pub fn derive_external(&self, index: u32) -> Result<String, String> {
        let account_key = RustExtendedPrivateKey::from_str(&self.account_key)
            .map_err(|e| format!("Invalid account key: {}", e))?;
        
        // Derive m/0/index (external chain)
        let chain_key = account_key
            .derive_child(ChildNumber::Normal(0))
            .map_err(|e| format!("Failed to derive chain: {}", e))?;
        
        let address_key = chain_key
            .derive_child(ChildNumber::Normal(index))
            .map_err(|e| format!("Failed to derive address: {}", e))?;
        
        Ok(address_key.to_string())
    }

    /// Derive an internal (change) address at the given index
    #[frb]
    pub fn derive_internal(&self, index: u32) -> Result<String, String> {
        let account_key = RustExtendedPrivateKey::from_str(&self.account_key)
            .map_err(|e| format!("Invalid account key: {}", e))?;
        
        // Derive m/1/index (internal chain)
        let chain_key = account_key
            .derive_child(ChildNumber::Normal(1))
            .map_err(|e| format!("Failed to derive chain: {}", e))?;
        
        let address_key = chain_key
            .derive_child(ChildNumber::Normal(index))
            .map_err(|e| format!("Failed to derive address: {}", e))?;
        
        Ok(address_key.to_string())
    }

    /// Derive a range of addresses
    #[frb]
    pub fn derive_address_range(
        &self,
        chain: ChainType,
        start: u32,
        count: u32,
    ) -> Result<Vec<String>, String> {
        let mut addresses = Vec::new();
        
        for i in start..(start + count) {
            let address = match chain {
                ChainType::External => self.derive_external(i)?,
                ChainType::Internal => self.derive_internal(i)?,
            };
            addresses.push(address);
        }
        
        Ok(addresses)
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

/// Create a master extended private key from a mnemonic string
#[frb]
pub fn create_master_key(
    mnemonic: String,
    passphrase: Option<String>,
    network: NetworkType,
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
    network: NetworkType,
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
        NetworkType::BitcoinMainnet => 0,
        NetworkType::BitcoinTestnet => 1,
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
    purpose: PurposeType,
    coin_type: CoinType,
    account_index: u32,
    network: NetworkType,
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
    chain: ChainType,
    address_index: u32,
) -> Result<String, String> {
    let account = RustExtendedPrivateKey::from_str(&account_key)
        .map_err(|e| format!("Invalid account key: {}", e))?;

    let chain_value = match chain {
        ChainType::External => 0,
        ChainType::Internal => 1,
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

    let purpose: PurposeType = bip44_path.purpose().into();
    let coin_type: CoinType = bip44_path.coin_type().into();
    let chain: ChainType = bip44_path.chain().into();

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
pub fn get_purpose_info(purpose: PurposeType) -> WalletResult {
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
// PART 4: SIMPLE UTILITY FUNCTIONS
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
