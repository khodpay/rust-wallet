//! EIP-1559 (Type 2) transaction types.
//!
//! This module provides the transaction structure and builder for creating
//! EIP-1559 transactions used on BSC and other EVM chains.

use crate::{AccessList, AccessListItem, Address, ChainId, Error, Result, Wei};

/// Gas limit for a standard ETH/BNB transfer.
pub const TRANSFER_GAS: u64 = 21_000;

/// Typical gas limit for a BEP-20/ERC-20 token transfer.
pub const TOKEN_TRANSFER_GAS: u64 = 65_000;

/// EIP-1559 (Type 2) transaction.
///
/// This is the modern transaction format with separate base fee and priority fee,
/// providing more predictable gas pricing.
///
/// # Fields
///
/// - `chain_id`: Network identifier (56 for BSC mainnet)
/// - `nonce`: Transaction count from sender
/// - `max_priority_fee_per_gas`: Tip to the validator (in wei)
/// - `max_fee_per_gas`: Maximum total fee per gas (in wei)
/// - `gas_limit`: Maximum gas units for execution
/// - `to`: Recipient address (None for contract creation)
/// - `value`: Amount to transfer (in wei)
/// - `data`: Contract call data or empty for simple transfers
/// - `access_list`: EIP-2930 access list for gas optimization
///
/// # Examples
///
/// ```rust
/// use khodpay_signing::{Eip1559Transaction, ChainId, Wei, Address};
///
/// let tx = Eip1559Transaction::builder()
///     .chain_id(ChainId::BscMainnet)
///     .nonce(0)
///     .max_priority_fee_per_gas(Wei::from_gwei(1))
///     .max_fee_per_gas(Wei::from_gwei(5))
///     .gas_limit(21000)
///     .to("0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap())
///     .value(Wei::from_ether(1))
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip1559Transaction {
    /// The chain ID for replay protection.
    pub chain_id: ChainId,
    /// The transaction nonce (sender's transaction count).
    pub nonce: u64,
    /// The maximum priority fee per gas (tip to validator).
    pub max_priority_fee_per_gas: Wei,
    /// The maximum total fee per gas.
    pub max_fee_per_gas: Wei,
    /// The gas limit for the transaction.
    pub gas_limit: u64,
    /// The recipient address (None for contract creation).
    pub to: Option<Address>,
    /// The value to transfer in wei.
    pub value: Wei,
    /// The transaction data (contract call data).
    pub data: Vec<u8>,
    /// The access list for gas optimization.
    pub access_list: AccessList,
}

impl Eip1559Transaction {
    /// Transaction type identifier for EIP-1559.
    pub const TYPE: u8 = 0x02;

    /// Creates a new transaction builder.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::{Eip1559Transaction, ChainId, Wei};
    ///
    /// let tx = Eip1559Transaction::builder()
    ///     .chain_id(ChainId::BscMainnet)
    ///     .nonce(0)
    ///     .max_priority_fee_per_gas(Wei::from_gwei(1))
    ///     .max_fee_per_gas(Wei::from_gwei(5))
    ///     .gas_limit(21000)
    ///     .value(Wei::ZERO)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> Eip1559TransactionBuilder {
        Eip1559TransactionBuilder::new()
    }

    /// Validates the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `max_fee_per_gas` < `max_priority_fee_per_gas`
    /// - `gas_limit` < 21000 (minimum for any transaction)
    pub fn validate(&self) -> Result<()> {
        // max_fee must be >= max_priority_fee
        if self.max_fee_per_gas < self.max_priority_fee_per_gas {
            return Err(Error::ValidationError(
                "max_fee_per_gas must be >= max_priority_fee_per_gas".to_string(),
            ));
        }

        // Gas limit must be at least 21000 (intrinsic gas)
        if self.gas_limit < TRANSFER_GAS {
            return Err(Error::InvalidGas(format!(
                "gas_limit must be at least {}, got {}",
                TRANSFER_GAS, self.gas_limit
            )));
        }

        Ok(())
    }

    /// Returns `true` if this is a contract creation transaction.
    pub fn is_contract_creation(&self) -> bool {
        self.to.is_none()
    }

    /// Returns `true` if this is a simple value transfer (no data).
    pub fn is_transfer(&self) -> bool {
        self.to.is_some() && self.data.is_empty()
    }
}

/// Builder for constructing EIP-1559 transactions.
///
/// Provides a fluent API for building transactions with validation.
#[derive(Debug, Clone, Default)]
pub struct Eip1559TransactionBuilder {
    chain_id: Option<ChainId>,
    nonce: Option<u64>,
    max_priority_fee_per_gas: Option<Wei>,
    max_fee_per_gas: Option<Wei>,
    gas_limit: Option<u64>,
    to: Option<Address>,
    value: Option<Wei>,
    data: Vec<u8>,
    access_list: AccessList,
}

impl Eip1559TransactionBuilder {
    /// Creates a new transaction builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the chain ID.
    pub fn chain_id(mut self, chain_id: ChainId) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Sets the nonce.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sets the maximum priority fee per gas (tip).
    pub fn max_priority_fee_per_gas(mut self, fee: Wei) -> Self {
        self.max_priority_fee_per_gas = Some(fee);
        self
    }

    /// Sets the maximum fee per gas.
    pub fn max_fee_per_gas(mut self, fee: Wei) -> Self {
        self.max_fee_per_gas = Some(fee);
        self
    }

    /// Sets the gas limit.
    pub fn gas_limit(mut self, limit: u64) -> Self {
        self.gas_limit = Some(limit);
        self
    }

    /// Sets the recipient address.
    pub fn to(mut self, address: Address) -> Self {
        self.to = Some(address);
        self
    }

    /// Sets the value to transfer.
    pub fn value(mut self, value: Wei) -> Self {
        self.value = Some(value);
        self
    }

    /// Sets the transaction data.
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Sets the access list.
    pub fn access_list(mut self, access_list: AccessList) -> Self {
        self.access_list = access_list;
        self
    }

    /// Adds an access list item.
    pub fn add_access_list_item(mut self, item: AccessListItem) -> Self {
        self.access_list.push(item);
        self
    }

    /// Builds the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or validation fails.
    pub fn build(self) -> Result<Eip1559Transaction> {
        let tx = Eip1559Transaction {
            chain_id: self
                .chain_id
                .ok_or_else(|| Error::ValidationError("chain_id is required".to_string()))?,
            nonce: self
                .nonce
                .ok_or_else(|| Error::ValidationError("nonce is required".to_string()))?,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas.ok_or_else(|| {
                Error::ValidationError("max_priority_fee_per_gas is required".to_string())
            })?,
            max_fee_per_gas: self
                .max_fee_per_gas
                .ok_or_else(|| Error::ValidationError("max_fee_per_gas is required".to_string()))?,
            gas_limit: self
                .gas_limit
                .ok_or_else(|| Error::ValidationError("gas_limit is required".to_string()))?,
            to: self.to,
            value: self.value.unwrap_or(Wei::ZERO),
            data: self.data,
            access_list: self.access_list,
        };

        tx.validate()?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap()
    }

    // ==================== Builder Tests ====================

    #[test]
    fn test_builder_minimal() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        assert_eq!(tx.chain_id, ChainId::BscMainnet);
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.max_priority_fee_per_gas, Wei::from_gwei(1));
        assert_eq!(tx.max_fee_per_gas, Wei::from_gwei(5));
        assert_eq!(tx.gas_limit, 21000);
        assert_eq!(tx.to, None);
        assert_eq!(tx.value, Wei::ZERO);
        assert!(tx.data.is_empty());
        assert!(tx.access_list.is_empty());
    }

    #[test]
    fn test_builder_full() {
        let recipient = test_address();
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(5)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .to(recipient)
            .value(Wei::from_ether(1))
            .data(vec![0x01, 0x02, 0x03])
            .build()
            .unwrap();

        assert_eq!(tx.to, Some(recipient));
        assert_eq!(tx.value, Wei::from_ether(1));
        assert_eq!(tx.data, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_builder_with_access_list() {
        let addr = test_address();
        let item = AccessListItem::new(addr, vec![[1u8; 32]]);

        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .access_list(vec![item.clone()])
            .build()
            .unwrap();

        assert_eq!(tx.access_list.len(), 1);
        assert_eq!(tx.access_list[0], item);
    }

    #[test]
    fn test_builder_add_access_list_item() {
        let addr = test_address();
        let item = AccessListItem::address_only(addr);

        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .add_access_list_item(item)
            .build()
            .unwrap();

        assert_eq!(tx.access_list.len(), 1);
    }

    // ==================== Missing Field Tests ====================

    #[test]
    fn test_builder_missing_chain_id() {
        let result = Eip1559Transaction::builder()
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("chain_id"));
    }

    #[test]
    fn test_builder_missing_nonce() {
        let result = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce"));
    }

    #[test]
    fn test_builder_missing_max_priority_fee() {
        let result = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build();

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("max_priority_fee_per_gas"));
    }

    #[test]
    fn test_builder_missing_max_fee() {
        let result = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .gas_limit(21000)
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_fee_per_gas"));
    }

    #[test]
    fn test_builder_missing_gas_limit() {
        let result = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("gas_limit"));
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_validation_max_fee_less_than_priority_fee() {
        let result = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(10))
            .max_fee_per_gas(Wei::from_gwei(5)) // Less than priority fee!
            .gas_limit(21000)
            .build();

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("max_fee_per_gas must be >= max_priority_fee_per_gas"));
    }

    #[test]
    fn test_validation_gas_limit_too_low() {
        let result = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(20000) // Less than 21000!
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("gas_limit"));
    }

    #[test]
    fn test_validation_equal_fees_ok() {
        let result = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(5))
            .max_fee_per_gas(Wei::from_gwei(5)) // Equal is OK
            .gas_limit(21000)
            .build();

        assert!(result.is_ok());
    }

    // ==================== Transaction Type Tests ====================

    #[test]
    fn test_is_contract_creation() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        assert!(tx.is_contract_creation());
        assert!(!tx.is_transfer());
    }

    #[test]
    fn test_is_transfer() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .to(test_address())
            .value(Wei::from_ether(1))
            .build()
            .unwrap();

        assert!(!tx.is_contract_creation());
        assert!(tx.is_transfer());
    }

    #[test]
    fn test_is_contract_call() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(65000)
            .to(test_address())
            .data(vec![0xa9, 0x05, 0x9c, 0xbb]) // transfer(address,uint256) selector
            .build()
            .unwrap();

        assert!(!tx.is_contract_creation());
        assert!(!tx.is_transfer()); // Has data, so not a simple transfer
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_transaction_type() {
        assert_eq!(Eip1559Transaction::TYPE, 0x02);
    }

    #[test]
    fn test_gas_constants() {
        assert_eq!(TRANSFER_GAS, 21_000);
        assert_eq!(TOKEN_TRANSFER_GAS, 65_000);
    }

    // ==================== Clone/Eq Tests ====================

    #[test]
    fn test_transaction_clone() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .to(test_address())
            .value(Wei::from_ether(1))
            .build()
            .unwrap();

        let cloned = tx.clone();
        assert_eq!(tx, cloned);
    }

    #[test]
    fn test_transaction_equality() {
        let tx1 = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let tx2 = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let tx3 = Eip1559Transaction::builder()
            .chain_id(ChainId::BscTestnet) // Different chain
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        assert_eq!(tx1, tx2);
        assert_ne!(tx1, tx3);
    }

    // ==================== BSC Specific Tests ====================

    #[test]
    fn test_bsc_mainnet_transaction() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .to(test_address())
            .value(Wei::from_ether(1))
            .build()
            .unwrap();

        assert_eq!(u64::from(tx.chain_id), 56);
    }

    #[test]
    fn test_bsc_testnet_transaction() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscTestnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .to(test_address())
            .value(Wei::from_ether(1))
            .build()
            .unwrap();

        assert_eq!(u64::from(tx.chain_id), 97);
    }
}
