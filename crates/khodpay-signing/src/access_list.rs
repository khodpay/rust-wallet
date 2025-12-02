//! EIP-2930 access list types.
//!
//! Access lists specify which addresses and storage keys a transaction will access,
//! allowing for gas savings on state access.

use crate::Address;

/// An access list item specifying an address and its storage keys.
///
/// Used in EIP-2930 and EIP-1559 transactions to declare which state
/// the transaction will access.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccessListItem {
    /// The address being accessed.
    pub address: Address,
    /// The storage keys being accessed at this address.
    pub storage_keys: Vec<[u8; 32]>,
}

impl AccessListItem {
    /// Creates a new access list item.
    pub fn new(address: Address, storage_keys: Vec<[u8; 32]>) -> Self {
        Self {
            address,
            storage_keys,
        }
    }

    /// Creates an access list item with only an address (no storage keys).
    pub fn address_only(address: Address) -> Self {
        Self {
            address,
            storage_keys: Vec::new(),
        }
    }
}

/// A list of access list items.
pub type AccessList = Vec<AccessListItem>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_list_item_new() {
        let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();
        let keys = vec![[1u8; 32], [2u8; 32]];
        let item = AccessListItem::new(addr, keys.clone());

        assert_eq!(item.address, addr);
        assert_eq!(item.storage_keys, keys);
    }

    #[test]
    fn test_access_list_item_address_only() {
        let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();
        let item = AccessListItem::address_only(addr);

        assert_eq!(item.address, addr);
        assert!(item.storage_keys.is_empty());
    }

    #[test]
    fn test_access_list_item_default() {
        let item = AccessListItem::default();
        assert_eq!(item.address, Address::ZERO);
        assert!(item.storage_keys.is_empty());
    }

    #[test]
    fn test_access_list_item_clone() {
        let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();
        let item = AccessListItem::new(addr, vec![[1u8; 32]]);
        let cloned = item.clone();

        assert_eq!(item, cloned);
    }
}
