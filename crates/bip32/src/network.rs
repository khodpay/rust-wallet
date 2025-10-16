//! Network types and key type identifiers for BIP32 extended key serialization.
//!
//! This module defines network identifiers and key types used for extended key
//! version bytes. Different networks use different version byte prefixes when
//! serializing extended keys to Base58Check format.
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip32::{Network, KeyType};
//!
//! let mainnet = Network::BitcoinMainnet;
//! assert_eq!(mainnet.version_bytes(KeyType::Private), 0x0488ADE4);
//! assert_eq!(mainnet.version_bytes(KeyType::Public), 0x0488B21E);
//! ```

/// Key type identifier for extended keys.
///
/// BIP32 defines two types of extended keys:
/// - Private extended keys (xprv/tprv) - contain private key material
/// - Public extended keys (xpub/tpub) - contain only public key material
///
/// # Examples
///
/// ```rust
/// use khodpay_bip32::KeyType;
///
/// let private = KeyType::Private;
/// let public = KeyType::Public;
///
/// assert!(private.is_private());
/// assert!(public.is_public());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// Private extended key (xprv/tprv).
    ///
    /// Contains private key material and can be used to:
    /// - Derive child private keys
    /// - Derive child public keys
    /// - Sign transactions
    Private,

    /// Public extended key (xpub/tpub).
    ///
    /// Contains only public key material and can be used to:
    /// - Derive child public keys (normal derivation only)
    /// - Verify signatures
    /// - Generate addresses for watching
    ///
    /// Cannot:
    /// - Derive hardened child keys
    /// - Sign transactions
    Public,
}

impl KeyType {
    /// Returns `true` if this is a private key type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::KeyType;
    ///
    /// assert!(KeyType::Private.is_private());
    /// assert!(!KeyType::Public.is_private());
    /// ```
    pub fn is_private(&self) -> bool {
        matches!(self, KeyType::Private)
    }

    /// Returns `true` if this is a public key type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::KeyType;
    ///
    /// assert!(KeyType::Public.is_public());
    /// assert!(!KeyType::Private.is_public());
    /// ```
    pub fn is_public(&self) -> bool {
        matches!(self, KeyType::Public)
    }

    /// Returns the human-readable name of the key type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::KeyType;
    ///
    /// assert_eq!(KeyType::Private.name(), "Private");
    /// assert_eq!(KeyType::Public.name(), "Public");
    /// ```
    pub fn name(&self) -> &'static str {
        match self {
            KeyType::Private => "Private",
            KeyType::Public => "Public",
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Network identifier for BIP32 extended key serialization.
///
/// Each network uses different version bytes when serializing extended keys.
/// These version bytes appear as prefixes in the Base58Check encoded strings:
///
/// - `xprv`/`xpub` - Bitcoin Mainnet
/// - `tprv`/`tpub` - Bitcoin Testnet
///
/// # Examples
///
/// ```rust
/// use khodpay_bip32::Network;
///
/// // Create network instances
/// let mainnet = Network::BitcoinMainnet;
/// let testnet = Network::BitcoinTestnet;
///
/// // Get version bytes
/// println!("Mainnet xprv: {:#x}", mainnet.xprv_version());
/// println!("Testnet tprv: {:#x}", testnet.xprv_version());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Bitcoin mainnet.
    ///
    /// Extended keys serialize with `xprv` (private) and `xpub` (public) prefixes.
    ///
    /// - Private version: `0x0488ADE4`
    /// - Public version: `0x0488B21E`
    BitcoinMainnet,

    /// Bitcoin testnet.
    ///
    /// Extended keys serialize with `tprv` (private) and `tpub` (public) prefixes.
    ///
    /// - Private version: `0x04358394`
    /// - Public version: `0x043587CF`
    BitcoinTestnet,
}

impl Network {
    /// Returns the version bytes for the specified key type.
    ///
    /// This is the primary method for getting version bytes, combining network
    /// and key type information.
    ///
    /// # Arguments
    ///
    /// * `key_type` - The type of extended key (Private or Public)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{Network, KeyType};
    ///
    /// let mainnet = Network::BitcoinMainnet;
    /// assert_eq!(mainnet.version_bytes(KeyType::Private), 0x0488ADE4);
    /// assert_eq!(mainnet.version_bytes(KeyType::Public), 0x0488B21E);
    /// ```
    pub fn version_bytes(&self, key_type: KeyType) -> u32 {
        match key_type {
            KeyType::Private => self.xprv_version(),
            KeyType::Public => self.xpub_version(),
        }
    }

    /// Returns the version bytes for extended private keys (xprv/tprv).
    ///
    /// These 4-byte values are used as the version prefix when serializing
    /// extended private keys to Base58Check format.
    ///
    /// # Returns
    ///
    /// - `0x0488ADE4` for Bitcoin Mainnet (xprv)
    /// - `0x04358394` for Bitcoin Testnet (tprv)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::Network;
    ///
    /// assert_eq!(Network::BitcoinMainnet.xprv_version(), 0x0488ADE4);
    /// assert_eq!(Network::BitcoinTestnet.xprv_version(), 0x04358394);
    /// ```
    pub fn xprv_version(&self) -> u32 {
        match self {
            Network::BitcoinMainnet => 0x0488ADE4,
            Network::BitcoinTestnet => 0x04358394,
        }
    }

    /// Returns the version bytes for extended public keys (xpub/tpub).
    ///
    /// These 4-byte values are used as the version prefix when serializing
    /// extended public keys to Base58Check format.
    ///
    /// # Returns
    ///
    /// - `0x0488B21E` for Bitcoin Mainnet (xpub)
    /// - `0x043587CF` for Bitcoin Testnet (tpub)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::Network;
    ///
    /// assert_eq!(Network::BitcoinMainnet.xpub_version(), 0x0488B21E);
    /// assert_eq!(Network::BitcoinTestnet.xpub_version(), 0x043587CF);
    /// ```
    pub fn xpub_version(&self) -> u32 {
        match self {
            Network::BitcoinMainnet => 0x0488B21E,
            Network::BitcoinTestnet => 0x043587CF,
        }
    }

    /// Returns the human-readable name of the network.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::Network;
    ///
    /// assert_eq!(Network::BitcoinMainnet.name(), "Bitcoin Mainnet");
    /// assert_eq!(Network::BitcoinTestnet.name(), "Bitcoin Testnet");
    /// ```
    pub fn name(&self) -> &'static str {
        match self {
            Network::BitcoinMainnet => "Bitcoin Mainnet",
            Network::BitcoinTestnet => "Bitcoin Testnet",
        }
    }

    /// Attempts to identify the network from extended private key version bytes.
    ///
    /// This method iterates through all known networks and checks if the provided
    /// version matches any of their xprv version bytes. This avoids hardcoding
    /// version bytes in multiple places.
    ///
    /// # Arguments
    ///
    /// * `version` - The 4-byte version prefix from an extended private key
    ///
    /// # Returns
    ///
    /// - `Some(Network)` if the version matches a known network
    /// - `None` if the version is not recognized
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::Network;
    ///
    /// assert_eq!(Network::from_xprv_version(0x0488ADE4), Some(Network::BitcoinMainnet));
    /// assert_eq!(Network::from_xprv_version(0x04358394), Some(Network::BitcoinTestnet));
    /// assert_eq!(Network::from_xprv_version(0xFFFFFFFF), None);
    /// ```
    pub fn from_xprv_version(version: u32) -> Option<Network> {
        // Iterate through all network variants
        const NETWORKS: [Network; 2] = [Network::BitcoinMainnet, Network::BitcoinTestnet];

        NETWORKS
            .into_iter()
            .find(|&network| network.xprv_version() == version)
    }

    /// Attempts to identify the network from extended public key version bytes.
    ///
    /// This method iterates through all known networks and checks if the provided
    /// version matches any of their xpub version bytes. This avoids hardcoding
    /// version bytes in multiple places.
    ///
    /// # Arguments
    ///
    /// * `version` - The 4-byte version prefix from an extended public key
    ///
    /// # Returns
    ///
    /// - `Some(Network)` if the version matches a known network
    /// - `None` if the version is not recognized
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::Network;
    ///
    /// assert_eq!(Network::from_xpub_version(0x0488B21E), Some(Network::BitcoinMainnet));
    /// assert_eq!(Network::from_xpub_version(0x043587CF), Some(Network::BitcoinTestnet));
    /// assert_eq!(Network::from_xpub_version(0xFFFFFFFF), None);
    /// ```
    pub fn from_xpub_version(version: u32) -> Option<Network> {
        // Iterate through all network variants
        const NETWORKS: [Network; 2] = [Network::BitcoinMainnet, Network::BitcoinTestnet];

        NETWORKS
            .into_iter()
            .find(|&network| network.xpub_version() == version)
    }
}

impl Default for Network {
    /// Returns the default network (Bitcoin Mainnet).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::Network;
    ///
    /// let network = Network::default();
    /// assert_eq!(network, Network::BitcoinMainnet);
    /// ```
    fn default() -> Self {
        Network::BitcoinMainnet
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KeyType tests
    #[test]
    fn test_key_type_is_private() {
        assert!(KeyType::Private.is_private());
        assert!(!KeyType::Public.is_private());
    }

    #[test]
    fn test_key_type_is_public() {
        assert!(KeyType::Public.is_public());
        assert!(!KeyType::Private.is_public());
    }

    #[test]
    fn test_key_type_name() {
        assert_eq!(KeyType::Private.name(), "Private");
        assert_eq!(KeyType::Public.name(), "Public");
    }

    #[test]
    fn test_key_type_display() {
        assert_eq!(KeyType::Private.to_string(), "Private");
        assert_eq!(KeyType::Public.to_string(), "Public");
    }

    #[test]
    fn test_key_type_equality() {
        assert_eq!(KeyType::Private, KeyType::Private);
        assert_eq!(KeyType::Public, KeyType::Public);
        assert_ne!(KeyType::Private, KeyType::Public);
    }

    #[test]
    fn test_key_type_clone_and_copy() {
        let key_type1 = KeyType::Private;
        let key_type2 = key_type1; // Copy
        let key_type3 = key_type1; // Clone

        assert_eq!(key_type1, key_type2);
        assert_eq!(key_type1, key_type3);
    }

    // Network tests
    #[test]
    fn test_version_bytes_with_key_type() {
        assert_eq!(
            Network::BitcoinMainnet.version_bytes(KeyType::Private),
            0x0488ADE4
        );
        assert_eq!(
            Network::BitcoinMainnet.version_bytes(KeyType::Public),
            0x0488B21E
        );
        assert_eq!(
            Network::BitcoinTestnet.version_bytes(KeyType::Private),
            0x04358394
        );
        assert_eq!(
            Network::BitcoinTestnet.version_bytes(KeyType::Public),
            0x043587CF
        );
    }

    #[test]
    fn test_xprv_version_bytes() {
        assert_eq!(Network::BitcoinMainnet.xprv_version(), 0x0488ADE4);
        assert_eq!(Network::BitcoinTestnet.xprv_version(), 0x04358394);
    }

    #[test]
    fn test_xpub_version_bytes() {
        assert_eq!(Network::BitcoinMainnet.xpub_version(), 0x0488B21E);
        assert_eq!(Network::BitcoinTestnet.xpub_version(), 0x043587CF);
    }

    #[test]
    fn test_network_names() {
        assert_eq!(Network::BitcoinMainnet.name(), "Bitcoin Mainnet");
        assert_eq!(Network::BitcoinTestnet.name(), "Bitcoin Testnet");
    }

    #[test]
    fn test_from_xprv_version() {
        assert_eq!(
            Network::from_xprv_version(0x0488ADE4),
            Some(Network::BitcoinMainnet)
        );
        assert_eq!(
            Network::from_xprv_version(0x04358394),
            Some(Network::BitcoinTestnet)
        );
        assert_eq!(Network::from_xprv_version(0xFFFFFFFF), None);
        assert_eq!(Network::from_xprv_version(0x0488B21E), None); // xpub version, not xprv
    }

    #[test]
    fn test_from_xpub_version() {
        assert_eq!(
            Network::from_xpub_version(0x0488B21E),
            Some(Network::BitcoinMainnet)
        );
        assert_eq!(
            Network::from_xpub_version(0x043587CF),
            Some(Network::BitcoinTestnet)
        );
        assert_eq!(Network::from_xpub_version(0xFFFFFFFF), None);
        assert_eq!(Network::from_xpub_version(0x0488ADE4), None); // xprv version, not xpub
    }

    #[test]
    fn test_default_network() {
        assert_eq!(Network::default(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_display() {
        assert_eq!(Network::BitcoinMainnet.to_string(), "Bitcoin Mainnet");
        assert_eq!(Network::BitcoinTestnet.to_string(), "Bitcoin Testnet");
    }

    #[test]
    fn test_equality() {
        assert_eq!(Network::BitcoinMainnet, Network::BitcoinMainnet);
        assert_eq!(Network::BitcoinTestnet, Network::BitcoinTestnet);
        assert_ne!(Network::BitcoinMainnet, Network::BitcoinTestnet);
    }

    #[test]
    fn test_clone_and_copy() {
        let network1 = Network::BitcoinMainnet;
        let network2 = network1; // Copy
        let network3 = network1; // Clone

        assert_eq!(network1, network2);
        assert_eq!(network1, network3);
    }
}
