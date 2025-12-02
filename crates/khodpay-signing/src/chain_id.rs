//! EVM chain identifiers for transaction signing.
//!
//! Chain IDs are used in EIP-155 and EIP-1559 transactions for replay protection.
//! Each EVM network has a unique chain ID that must be included in signed transactions.

use std::fmt;

/// EVM chain identifier for transaction replay protection.
///
/// Chain IDs are embedded in transactions to prevent replay attacks across
/// different EVM networks. For example, a transaction signed for BSC (chain ID 56)
/// cannot be replayed on Ethereum (chain ID 1).
///
/// # Note
///
/// `ChainId` is different from `khodpay_bip44::CoinType`:
/// - `CoinType::Ethereum` (60) → Used in BIP-44 derivation path
/// - `ChainId::BscMainnet` (56) → Used in transaction for replay protection
///
/// BSC uses Ethereum's coin type (60) for key derivation because it's EVM-compatible,
/// but uses its own chain ID (56) in transactions.
///
/// # Examples
///
/// ```rust
/// use khodpay_signing::ChainId;
///
/// let bsc = ChainId::BscMainnet;
/// assert_eq!(u64::from(bsc), 56);
///
/// let custom = ChainId::Custom(137); // Polygon
/// assert_eq!(u64::from(custom), 137);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ChainId {
    /// BSC Mainnet (chain ID 56).
    BscMainnet,

    /// BSC Testnet (chain ID 97).
    BscTestnet,

    /// Custom chain ID for other EVM networks.
    ///
    /// Use this for networks not explicitly defined, such as:
    /// - Ethereum Mainnet: `Custom(1)`
    /// - Polygon: `Custom(137)`
    /// - Arbitrum: `Custom(42161)`
    Custom(u64),
}

impl ChainId {
    /// BSC Mainnet chain ID value.
    pub const BSC_MAINNET: u64 = 56;

    /// BSC Testnet chain ID value.
    pub const BSC_TESTNET: u64 = 97;

    /// Returns the numeric chain ID value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::ChainId;
    ///
    /// assert_eq!(ChainId::BscMainnet.value(), 56);
    /// assert_eq!(ChainId::BscTestnet.value(), 97);
    /// assert_eq!(ChainId::Custom(1).value(), 1);
    /// ```
    pub const fn value(&self) -> u64 {
        match self {
            ChainId::BscMainnet => Self::BSC_MAINNET,
            ChainId::BscTestnet => Self::BSC_TESTNET,
            ChainId::Custom(id) => *id,
        }
    }

    /// Returns the network name for this chain ID.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::ChainId;
    ///
    /// assert_eq!(ChainId::BscMainnet.name(), "BSC Mainnet");
    /// assert_eq!(ChainId::BscTestnet.name(), "BSC Testnet");
    /// assert_eq!(ChainId::Custom(1).name(), "Custom");
    /// ```
    pub const fn name(&self) -> &'static str {
        match self {
            ChainId::BscMainnet => "BSC Mainnet",
            ChainId::BscTestnet => "BSC Testnet",
            ChainId::Custom(_) => "Custom",
        }
    }

    /// Returns `true` if this is a testnet chain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::ChainId;
    ///
    /// assert!(!ChainId::BscMainnet.is_testnet());
    /// assert!(ChainId::BscTestnet.is_testnet());
    /// ```
    pub const fn is_testnet(&self) -> bool {
        matches!(self, ChainId::BscTestnet)
    }
}

impl From<ChainId> for u64 {
    fn from(chain_id: ChainId) -> Self {
        chain_id.value()
    }
}

impl From<u64> for ChainId {
    fn from(value: u64) -> Self {
        match value {
            Self::BSC_MAINNET => ChainId::BscMainnet,
            Self::BSC_TESTNET => ChainId::BscTestnet,
            _ => ChainId::Custom(value),
        }
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainId::BscMainnet => write!(f, "BSC Mainnet (56)"),
            ChainId::BscTestnet => write!(f, "BSC Testnet (97)"),
            ChainId::Custom(id) => write!(f, "Chain {}", id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Value Tests ====================

    #[test]
    fn test_bsc_mainnet_value() {
        assert_eq!(ChainId::BscMainnet.value(), 56);
    }

    #[test]
    fn test_bsc_testnet_value() {
        assert_eq!(ChainId::BscTestnet.value(), 97);
    }

    #[test]
    fn test_custom_value() {
        assert_eq!(ChainId::Custom(1).value(), 1);
        assert_eq!(ChainId::Custom(137).value(), 137);
        assert_eq!(ChainId::Custom(42161).value(), 42161);
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_constants() {
        assert_eq!(ChainId::BSC_MAINNET, 56);
        assert_eq!(ChainId::BSC_TESTNET, 97);
    }

    // ==================== From<u64> Tests ====================

    #[test]
    fn test_from_u64_bsc_mainnet() {
        let chain_id = ChainId::from(56u64);
        assert_eq!(chain_id, ChainId::BscMainnet);
    }

    #[test]
    fn test_from_u64_bsc_testnet() {
        let chain_id = ChainId::from(97u64);
        assert_eq!(chain_id, ChainId::BscTestnet);
    }

    #[test]
    fn test_from_u64_custom() {
        let chain_id = ChainId::from(1u64);
        assert_eq!(chain_id, ChainId::Custom(1));

        let chain_id = ChainId::from(137u64);
        assert_eq!(chain_id, ChainId::Custom(137));
    }

    // ==================== Into<u64> Tests ====================

    #[test]
    fn test_into_u64() {
        let value: u64 = ChainId::BscMainnet.into();
        assert_eq!(value, 56);

        let value: u64 = ChainId::BscTestnet.into();
        assert_eq!(value, 97);

        let value: u64 = ChainId::Custom(137).into();
        assert_eq!(value, 137);
    }

    // ==================== Round-trip Tests ====================

    #[test]
    fn test_round_trip_bsc_mainnet() {
        let original = ChainId::BscMainnet;
        let value: u64 = original.into();
        let recovered = ChainId::from(value);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_round_trip_bsc_testnet() {
        let original = ChainId::BscTestnet;
        let value: u64 = original.into();
        let recovered = ChainId::from(value);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_round_trip_custom() {
        let original = ChainId::Custom(42161);
        let value: u64 = original.into();
        let recovered = ChainId::from(value);
        assert_eq!(original, recovered);
    }

    // ==================== Name Tests ====================

    #[test]
    fn test_name() {
        assert_eq!(ChainId::BscMainnet.name(), "BSC Mainnet");
        assert_eq!(ChainId::BscTestnet.name(), "BSC Testnet");
        assert_eq!(ChainId::Custom(1).name(), "Custom");
    }

    // ==================== is_testnet Tests ====================

    #[test]
    fn test_is_testnet() {
        assert!(!ChainId::BscMainnet.is_testnet());
        assert!(ChainId::BscTestnet.is_testnet());
        assert!(!ChainId::Custom(1).is_testnet());
        assert!(!ChainId::Custom(5).is_testnet()); // Goerli is testnet but Custom doesn't know
    }

    // ==================== Display Tests ====================

    #[test]
    fn test_display() {
        assert_eq!(ChainId::BscMainnet.to_string(), "BSC Mainnet (56)");
        assert_eq!(ChainId::BscTestnet.to_string(), "BSC Testnet (97)");
        assert_eq!(ChainId::Custom(1).to_string(), "Chain 1");
        assert_eq!(ChainId::Custom(137).to_string(), "Chain 137");
    }

    // ==================== Debug Tests ====================

    #[test]
    fn test_debug() {
        assert_eq!(format!("{:?}", ChainId::BscMainnet), "BscMainnet");
        assert_eq!(format!("{:?}", ChainId::BscTestnet), "BscTestnet");
        assert_eq!(format!("{:?}", ChainId::Custom(1)), "Custom(1)");
    }

    // ==================== Equality Tests ====================

    #[test]
    fn test_equality() {
        assert_eq!(ChainId::BscMainnet, ChainId::BscMainnet);
        assert_eq!(ChainId::BscTestnet, ChainId::BscTestnet);
        assert_eq!(ChainId::Custom(1), ChainId::Custom(1));

        assert_ne!(ChainId::BscMainnet, ChainId::BscTestnet);
        assert_ne!(ChainId::BscMainnet, ChainId::Custom(56)); // Different variants!
        assert_ne!(ChainId::Custom(1), ChainId::Custom(2));
    }

    // ==================== Clone/Copy Tests ====================

    #[test]
    fn test_clone_copy() {
        let original = ChainId::BscMainnet;
        let copied = original; // Copy trait

        assert_eq!(original, copied);
    }

    // ==================== Hash Tests ====================

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(ChainId::BscMainnet);
        set.insert(ChainId::BscTestnet);
        set.insert(ChainId::Custom(1));

        assert!(set.contains(&ChainId::BscMainnet));
        assert!(set.contains(&ChainId::BscTestnet));
        assert!(set.contains(&ChainId::Custom(1)));
        assert!(!set.contains(&ChainId::Custom(2)));
    }
}
