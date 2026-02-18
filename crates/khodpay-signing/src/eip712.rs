//! Generic EIP-712 typed data signing.
//!
//! Implements [EIP-712](https://eips.ethereum.org/EIPS/eip-712) typed structured data hashing
//! and signing in a **protocol-agnostic** way. Callers implement the [`Eip712Type`] trait for
//! their own domain-specific structs; this library handles the cryptographic envelope.
//!
//! # Overview
//!
//! EIP-712 defines a standard for hashing and signing typed structured data, producing
//! human-readable signatures that wallets can display. The final signed hash is:
//!
//! ```text
//! keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message))
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use khodpay_signing::eip712::{
//!     Eip712Domain, Eip712Type, encode_address, encode_uint64, encode_bytes32,
//!     sign_typed_data, verify_typed_data,
//! };
//! use khodpay_signing::{Address, Bip44Signer};
//!
//! // 1. Define your struct and implement Eip712Type
//! struct PaymentIntent {
//!     business: Address,
//!     amount: u64,
//!     nonce: u64,
//! }
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
//! // 2. Build the EIP-712 domain matching your contract
//! let gateway: Address = "0x1111...".parse().unwrap();
//! let domain = Eip712Domain::new("MyApp", "1", 56, gateway);
//!
//! // 3. Sign
//! let intent = PaymentIntent { business: signer.address(), amount: 1_000_000, nonce: 0 };
//! let sig = sign_typed_data(&signer, &domain, &intent)?;
//!
//! // 4. Verify
//! let valid = verify_typed_data(&domain, &intent, &sig, signer.address())?;
//! assert!(valid);
//! ```
//!
//! # Encoding Helpers
//!
//! The module exports ABI encoding helpers for use inside [`Eip712Type::encode_data`]:
//!
//! | Helper | Solidity type |
//! |---|---|
//! | [`encode_address`] | `address` |
//! | [`encode_uint64`] | `uint64` |
//! | [`encode_u256_bytes`] | `uint256` (from 32-byte big-endian) |
//! | [`encode_bool`] | `bool` |
//! | [`encode_bytes32`] | `bytes32` |
//! | [`encode_bytes_dynamic`] | `bytes` / `string` (hashed) |

use crate::{Address, Result, Signature};
use sha3::{Digest, Keccak256};

// ─── Trait ───────────────────────────────────────────────────────────────────

/// A type that can be hashed according to EIP-712 typed structured data rules.
///
/// Implementors provide:
/// - [`type_string`](Eip712Type::type_string): the canonical EIP-712 type string, e.g.
///   `"Transfer(address to,uint256 amount)"`.
/// - [`encode_data`](Eip712Type::encode_data): the ABI-encoded field values (without the
///   type hash prefix). Each field must be a 32-byte word per EIP-712 `encodeData` rules.
///
/// # Encoding Rules (EIP-712 §encodeData)
///
/// | Solidity type        | Encoding                                              |
/// |----------------------|-------------------------------------------------------|
/// | `address`            | 12 zero bytes + 20 address bytes (32 bytes total)     |
/// | `uint<N>` / `int<N>` | big-endian, zero-padded to 32 bytes                   |
/// | `bool`               | 0 or 1, zero-padded to 32 bytes                       |
/// | `bytes32`            | raw 32 bytes                                          |
/// | `bytes` / `string`   | `keccak256(value)` → 32 bytes                         |
/// | nested struct `T`    | `hashStruct(T)` → 32 bytes                            |
/// | `T[]` / `T[N]`       | `keccak256(enc(T[0]) ‖ … ‖ enc(T[n-1]))` → 32 bytes  |
pub trait Eip712Type {
    /// Returns the canonical EIP-712 type string.
    ///
    /// For a struct with no nested types: `"StructName(type1 name1,type2 name2,…)"`.
    /// For structs with nested types, append referenced type strings alphabetically.
    fn type_string() -> &'static str;

    /// Returns the ABI-encoded field values for this instance.
    ///
    /// The returned bytes must be a concatenation of 32-byte words, one per field,
    /// following the EIP-712 `encodeData` specification.
    fn encode_data(&self) -> Vec<u8>;

    /// Returns `keccak256(type_string())`.
    fn type_hash() -> [u8; 32] {
        keccak256(Self::type_string().as_bytes())
    }

    /// Returns `keccak256(typeHash ‖ encodeData())` — the `hashStruct` value.
    fn hash_struct(&self) -> [u8; 32] {
        let type_hash = Self::type_hash();
        let encoded = self.encode_data();
        let mut buf = Vec::with_capacity(32 + encoded.len());
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&encoded);
        keccak256(&buf)
    }
}

// ─── Domain ──────────────────────────────────────────────────────────────────

/// EIP-712 domain separator parameters.
///
/// All fields are optional; include only those your contract's `DOMAIN_TYPEHASH` uses.
///
/// # Examples
///
/// ```rust
/// use khodpay_signing::eip712::Eip712Domain;
/// use khodpay_signing::Address;
///
/// let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap();
/// let domain = Eip712Domain::new("MyProtocol", "1", 56, addr);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip712Domain {
    /// Protocol / application name.
    pub name: Option<String>,
    /// Contract version string.
    pub version: Option<String>,
    /// EVM chain ID.
    pub chain_id: Option<u64>,
    /// Address of the verifying contract.
    pub verifying_contract: Option<Address>,
    /// Optional salt for additional domain separation.
    pub salt: Option<[u8; 32]>,
}

impl Eip712Domain {
    /// Creates a domain with the four most common fields populated.
    pub fn new(name: &str, version: &str, chain_id: u64, verifying_contract: Address) -> Self {
        Self {
            name: Some(name.to_string()),
            version: Some(version.to_string()),
            chain_id: Some(chain_id),
            verifying_contract: Some(verifying_contract),
            salt: None,
        }
    }

    /// Returns a builder for constructing a domain with only the desired fields.
    pub fn builder() -> Eip712DomainBuilder {
        Eip712DomainBuilder::default()
    }

    /// Returns the canonical EIP-712 type string for this domain configuration.
    ///
    /// Only includes fields that are `Some`, matching the contract's `DOMAIN_TYPEHASH`.
    pub fn type_string(&self) -> String {
        let mut fields = Vec::new();
        if self.name.is_some() {
            fields.push("string name");
        }
        if self.version.is_some() {
            fields.push("string version");
        }
        if self.chain_id.is_some() {
            fields.push("uint256 chainId");
        }
        if self.verifying_contract.is_some() {
            fields.push("address verifyingContract");
        }
        if self.salt.is_some() {
            fields.push("bytes32 salt");
        }
        format!("EIP712Domain({})", fields.join(","))
    }

    /// Computes `keccak256(type_string())`.
    pub fn type_hash(&self) -> [u8; 32] {
        keccak256(self.type_string().as_bytes())
    }

    /// Computes the EIP-712 domain separator.
    ///
    /// `domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, …fields…))`
    pub fn domain_separator(&self) -> [u8; 32] {
        let type_hash = self.type_hash();
        let mut buf = Vec::with_capacity(32 * 6);
        buf.extend_from_slice(&type_hash);

        if let Some(ref name) = self.name {
            buf.extend_from_slice(&keccak256(name.as_bytes()));
        }
        if let Some(ref version) = self.version {
            buf.extend_from_slice(&keccak256(version.as_bytes()));
        }
        if let Some(chain_id) = self.chain_id {
            buf.extend_from_slice(&encode_uint64_as_u256(chain_id));
        }
        if let Some(ref addr) = self.verifying_contract {
            buf.extend_from_slice(&encode_address(addr));
        }
        if let Some(salt) = self.salt {
            buf.extend_from_slice(&salt);
        }

        keccak256(&buf)
    }
}

// ─── Domain Builder ───────────────────────────────────────────────────────────

/// Builder for [`Eip712Domain`].
#[derive(Debug, Clone, Default)]
pub struct Eip712DomainBuilder {
    name: Option<String>,
    version: Option<String>,
    chain_id: Option<u64>,
    verifying_contract: Option<Address>,
    salt: Option<[u8; 32]>,
}

impl Eip712DomainBuilder {
    /// Sets the protocol name.
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Sets the version string.
    pub fn version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    /// Sets the chain ID.
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Sets the verifying contract address.
    pub fn verifying_contract(mut self, address: Address) -> Self {
        self.verifying_contract = Some(address);
        self
    }

    /// Sets the optional salt.
    pub fn salt(mut self, salt: [u8; 32]) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Builds the [`Eip712Domain`].
    pub fn build(self) -> Eip712Domain {
        Eip712Domain {
            name: self.name,
            version: self.version,
            chain_id: self.chain_id,
            verifying_contract: self.verifying_contract,
            salt: self.salt,
        }
    }
}

// ─── Core Functions ───────────────────────────────────────────────────────────

/// Computes the EIP-712 signing hash for any type implementing [`Eip712Type`].
///
/// `hash = keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message))`
///
/// This is the 32-byte digest that must be signed by the private key.
pub fn hash_typed_data<T: Eip712Type>(domain: &Eip712Domain, message: &T) -> [u8; 32] {
    let domain_sep = domain.domain_separator();
    let struct_hash = message.hash_struct();

    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(&domain_sep);
    buf[34..66].copy_from_slice(&struct_hash);

    keccak256(&buf)
}

/// Signs EIP-712 typed structured data with a [`Bip44Signer`](crate::Bip44Signer).
///
/// # Errors
///
/// Returns an error if the underlying ECDSA signing fails.
pub fn sign_typed_data<T: Eip712Type>(
    signer: &crate::Bip44Signer,
    domain: &Eip712Domain,
    message: &T,
) -> Result<Signature> {
    let hash = hash_typed_data(domain, message);
    signer.sign_hash(&hash)
}

/// Verifies an EIP-712 typed data signature.
///
/// Recovers the signer address from the signature and compares it against
/// `expected_signer`. Returns `Ok(true)` if they match, `Ok(false)` otherwise.
///
/// # Errors
///
/// Returns an error if signature recovery fails (e.g. invalid `v` value).
pub fn verify_typed_data<T: Eip712Type>(
    domain: &Eip712Domain,
    message: &T,
    signature: &Signature,
    expected_signer: Address,
) -> Result<bool> {
    let hash = hash_typed_data(domain, message);
    let recovered = crate::recover_signer(&hash, signature)?;
    Ok(recovered == expected_signer)
}

// ─── ABI Encoding Helpers (public for implementors) ──────────────────────────

/// Encodes an `address` as a 32-byte word (left-padded with 12 zero bytes).
///
/// Use this in [`Eip712Type::encode_data`] for `address` fields.
pub fn encode_address(address: &Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_bytes());
    word
}

/// Encodes a `uint256` value (up to `u128::MAX`) as a 32-byte big-endian word.
///
/// For values exceeding `u128::MAX`, use [`encode_u256_bytes`].
pub fn encode_uint256(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Encodes a raw 32-byte big-endian `uint256` value as a 32-byte word.
///
/// Use this when you already have the big-endian bytes (e.g. from `primitive_types::U256`).
pub fn encode_u256_bytes(value: [u8; 32]) -> [u8; 32] {
    value
}

/// Encodes a `uint64` as a 32-byte big-endian word.
///
/// Convenience for common `uint64` fields like nonces, deadlines, and timestamps.
pub fn encode_uint64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Encodes a `bool` as a 32-byte word (`0` or `1`).
pub fn encode_bool(value: bool) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = value as u8;
    word
}

/// Encodes a `bytes32` value as-is (already 32 bytes).
pub fn encode_bytes32(value: [u8; 32]) -> [u8; 32] {
    value
}

/// Encodes a dynamic `bytes` or `string` value as `keccak256(value)` (32 bytes).
///
/// Per EIP-712, dynamic types are encoded as the keccak256 hash of their content.
pub fn encode_bytes_dynamic(value: &[u8]) -> [u8; 32] {
    keccak256(value)
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

/// Encodes a `u64` chain ID as a 32-byte uint256 word (for domain separator).
fn encode_uint64_as_u256(value: u64) -> [u8; 32] {
    encode_uint64(value)
}

/// Computes `keccak256` of the given bytes.
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bip44Signer;

    fn test_address() -> Address {
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap()
    }

    fn test_domain() -> Eip712Domain {
        Eip712Domain::new("TestProtocol", "1", 56, test_address())
    }

    struct SimpleTransfer {
        to: Address,
        amount: u64,
    }

    impl Eip712Type for SimpleTransfer {
        fn type_string() -> &'static str {
            "Transfer(address to,uint64 amount)"
        }

        fn encode_data(&self) -> Vec<u8> {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&encode_address(&self.to));
            buf.extend_from_slice(&encode_uint64(self.amount));
            buf
        }
    }

    #[test]
    fn test_domain_type_string_full() {
        let domain = test_domain();
        assert_eq!(
            domain.type_string(),
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    }

    #[test]
    fn test_domain_type_string_minimal() {
        let domain = Eip712Domain::builder().name("App").build();
        assert_eq!(domain.type_string(), "EIP712Domain(string name)");
    }

    #[test]
    fn test_domain_type_string_with_salt() {
        let domain = Eip712Domain::builder()
            .name("App")
            .chain_id(1)
            .salt([0xffu8; 32])
            .build();
        assert_eq!(
            domain.type_string(),
            "EIP712Domain(string name,uint256 chainId,bytes32 salt)"
        );
    }

    #[test]
    fn test_domain_separator_deterministic() {
        assert_eq!(test_domain().domain_separator(), test_domain().domain_separator());
    }

    #[test]
    fn test_domain_separator_differs_by_chain() {
        let d1 = Eip712Domain::new("App", "1", 56, test_address());
        let d2 = Eip712Domain::new("App", "1", 97, test_address());
        assert_ne!(d1.domain_separator(), d2.domain_separator());
    }

    #[test]
    fn test_domain_separator_differs_by_name() {
        let d1 = Eip712Domain::new("App", "1", 56, test_address());
        let d2 = Eip712Domain::new("OtherApp", "1", 56, test_address());
        assert_ne!(d1.domain_separator(), d2.domain_separator());
    }

    #[test]
    fn test_domain_separator_differs_by_contract() {
        let addr2: Address = "0x1111111111111111111111111111111111111111".parse().unwrap();
        let d1 = Eip712Domain::new("App", "1", 56, test_address());
        let d2 = Eip712Domain::new("App", "1", 56, addr2);
        assert_ne!(d1.domain_separator(), d2.domain_separator());
    }

    #[test]
    fn test_type_hash_deterministic() {
        assert_eq!(SimpleTransfer::type_hash(), SimpleTransfer::type_hash());
    }

    #[test]
    fn test_hash_struct_differs_by_field() {
        let t1 = SimpleTransfer { to: test_address(), amount: 1000 };
        let t2 = SimpleTransfer { to: test_address(), amount: 2000 };
        assert_ne!(t1.hash_struct(), t2.hash_struct());
    }

    #[test]
    fn test_hash_typed_data_deterministic() {
        let domain = test_domain();
        let msg = SimpleTransfer { to: test_address(), amount: 500 };
        assert_eq!(hash_typed_data(&domain, &msg), hash_typed_data(&domain, &msg));
    }

    #[test]
    fn test_hash_typed_data_differs_by_domain() {
        let d1 = Eip712Domain::new("App", "1", 56, test_address());
        let d2 = Eip712Domain::new("App", "1", 97, test_address());
        let msg = SimpleTransfer { to: test_address(), amount: 500 };
        assert_ne!(hash_typed_data(&d1, &msg), hash_typed_data(&d2, &msg));
    }

    #[test]
    fn test_hash_typed_data_differs_by_message() {
        let domain = test_domain();
        let m1 = SimpleTransfer { to: test_address(), amount: 100 };
        let m2 = SimpleTransfer { to: test_address(), amount: 200 };
        assert_ne!(hash_typed_data(&domain, &m1), hash_typed_data(&domain, &m2));
    }

    #[test]
    fn test_sign_and_verify() {
        let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
        let domain = test_domain();
        let msg = SimpleTransfer { to: test_address(), amount: 1_000_000 };

        let sig = sign_typed_data(&signer, &domain, &msg).unwrap();
        let valid = verify_typed_data(&domain, &msg, &sig, signer.address()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_signer_returns_false() {
        let signer1 = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
        let mut key2 = [1u8; 32];
        key2[31] = 2;
        let signer2 = Bip44Signer::from_private_key(&key2).unwrap();

        let domain = test_domain();
        let msg = SimpleTransfer { to: test_address(), amount: 42 };

        let sig = sign_typed_data(&signer1, &domain, &msg).unwrap();
        let valid = verify_typed_data(&domain, &msg, &sig, signer2.address()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_sign_deterministic() {
        let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
        let domain = test_domain();
        let msg = SimpleTransfer { to: test_address(), amount: 99 };

        let sig1 = sign_typed_data(&signer, &domain, &msg).unwrap();
        let sig2 = sign_typed_data(&signer, &domain, &msg).unwrap();
        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
        assert_eq!(sig1.v, sig2.v);
    }

    #[test]
    fn test_cross_domain_signature_invalid() {
        let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
        let d1 = Eip712Domain::new("App", "1", 56, test_address());
        let d2 = Eip712Domain::new("App", "1", 97, test_address());
        let msg = SimpleTransfer { to: test_address(), amount: 1 };

        let sig = sign_typed_data(&signer, &d1, &msg).unwrap();
        let valid = verify_typed_data(&d2, &msg, &sig, signer.address()).unwrap();
        assert!(!valid, "Signature from chain 56 must not be valid on chain 97");
    }

    #[test]
    fn test_encode_address_length() {
        let encoded = encode_address(&test_address());
        assert_eq!(encoded.len(), 32);
        assert_eq!(&encoded[0..12], &[0u8; 12]);
    }

    #[test]
    fn test_encode_uint256_zero() {
        assert_eq!(encode_uint256(0), [0u8; 32]);
    }

    #[test]
    fn test_encode_uint256_max_u128() {
        let encoded = encode_uint256(u128::MAX);
        assert_eq!(&encoded[0..16], &[0u8; 16]);
        assert_eq!(&encoded[16..], &[0xffu8; 16]);
    }

    #[test]
    fn test_encode_uint64_value() {
        let encoded = encode_uint64(1u64);
        assert_eq!(encoded[31], 1u8);
        assert_eq!(&encoded[0..31], &[0u8; 31]);
    }

    #[test]
    fn test_encode_bool_true() {
        let encoded = encode_bool(true);
        assert_eq!(encoded[31], 1u8);
        assert_eq!(&encoded[0..31], &[0u8; 31]);
    }

    #[test]
    fn test_encode_bool_false() {
        assert_eq!(encode_bool(false), [0u8; 32]);
    }

    #[test]
    fn test_encode_bytes_dynamic() {
        let h1 = encode_bytes_dynamic(b"hello");
        let h2 = encode_bytes_dynamic(b"world");
        assert_ne!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_encode_bytes32_roundtrip() {
        let raw = [0xabu8; 32];
        assert_eq!(encode_bytes32(raw), raw);
    }

    #[test]
    fn test_nested_struct_hashing() {
        struct Inner {
            value: u64,
        }
        impl Eip712Type for Inner {
            fn type_string() -> &'static str {
                "Inner(uint64 value)"
            }
            fn encode_data(&self) -> Vec<u8> {
                encode_uint64(self.value).to_vec()
            }
        }

        struct Outer {
            inner: Inner,
            label: Vec<u8>,
        }
        impl Eip712Type for Outer {
            fn type_string() -> &'static str {
                "Outer(Inner inner,string label)Inner(uint64 value)"
            }
            fn encode_data(&self) -> Vec<u8> {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&self.inner.hash_struct());
                buf.extend_from_slice(&encode_bytes_dynamic(&self.label));
                buf
            }
        }

        let o1 = Outer { inner: Inner { value: 1 }, label: b"foo".to_vec() };
        let o2 = Outer { inner: Inner { value: 2 }, label: b"foo".to_vec() };
        assert_ne!(o1.hash_struct(), o2.hash_struct());
    }
}
