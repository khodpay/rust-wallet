//! Generic ERC-4337 (Account Abstraction) UserOperation support.
//!
//! Implements [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) v0.7
//! `PackedUserOperation` construction, hashing, and signing in a **protocol-agnostic** way.
//! No application-specific calldata is hardcoded; callers supply raw `call_data` bytes,
//! making this module usable with any smart account and any target contract.
//!
//! # Overview
//!
//! ERC-4337 enables gasless transactions via a bundler/EntryPoint architecture. The user
//! signs a `UserOperation` (not a raw transaction); the bundler submits it to the
//! `EntryPoint` contract, which calls `validateUserOp` on the user's smart account.
//!
//! ## v0.7 Packed Format
//!
//! v0.7 packs two gas values into each `bytes32` field to reduce calldata cost:
//! - `accountGasLimits`: `verificationGasLimit (u128) ‖ callGasLimit (u128)`
//! - `gasFees`: `maxPriorityFeePerGas (u128) ‖ maxFeePerGas (u128)`
//!
//! ## Hash Formula
//!
//! ```text
//! userOpHash = keccak256(
//!     keccak256(pack(userOp))  ‖  entry_point (32 bytes)  ‖  chain_id (32 bytes)
//! )
//! ```
//!
//! where `pack(userOp)` is:
//! ```text
//! abi.encode(
//!   sender, nonce, keccak256(initCode), keccak256(callData),
//!   accountGasLimits, preVerificationGas, gasFees,
//!   keccak256(paymasterAndData)
//! )
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use khodpay_signing::erc4337::{PackedUserOperation, sign_user_operation, ENTRY_POINT_V07};
//! use khodpay_signing::Address;
//!
//! // 1. Encode your contract call (any calldata — no hardcoding here)
//! let call_data: Vec<u8> = encode_execute_payment(intent, business_sig);
//!
//! // 2. Build the UserOperation
//! let user_op = PackedUserOperation::builder()
//!     .sender(smart_account_address)
//!     .nonce(0)
//!     .call_data(call_data)
//!     .account_gas_limits(150_000, 300_000)   // verificationGas, callGas
//!     .pre_verification_gas(50_000)
//!     .gas_fees(1_000_000_000, 5_000_000_000) // maxPriorityFee, maxFee (wei)
//!     .paymaster(paymaster_address, vec![])
//!     .build()?;
//!
//! // 3. Sign
//! let entry_point: Address = ENTRY_POINT_V07.parse().unwrap();
//! let sig = sign_user_operation(&signer, &user_op, entry_point, 56)?;
//!
//! // 4. Attach signature and submit to bundler
//! let mut signed_op = user_op;
//! signed_op.signature = sig.to_bytes().to_vec();
//! ```
//!
//! # EntryPoint
//!
//! The canonical ERC-4337 v0.7 EntryPoint address is available as [`ENTRY_POINT_V07`]:
//! `0x0000000071727De22E5E9d8BAf0edAc6f37da032`

use crate::{Address, Error, Result, Signature};
use crate::eip712::keccak256;

/// The canonical ERC-4337 v0.7 EntryPoint contract address.
pub const ENTRY_POINT_V07: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

/// ERC-4337 v0.7 `PackedUserOperation`.
///
/// Gas fields use the v0.7 packed format where two `u128` values are packed
/// into a single `bytes32` word.
///
/// # Fields
///
/// - `sender`: Smart account address that executes the operation.
/// - `nonce`: Account nonce (prevents replay).
/// - `init_code`: Factory calldata for deployment; empty if account exists.
/// - `call_data`: Encoded function call for the smart account to execute.
/// - `account_gas_limits`: `verificationGasLimit (u128) ‖ callGasLimit (u128)` as `bytes32`.
/// - `pre_verification_gas`: Fixed overhead gas for bundler compensation.
/// - `gas_fees`: `maxPriorityFeePerGas (u128) ‖ maxFeePerGas (u128)` as `bytes32`.
/// - `paymaster_and_data`: Paymaster address (20 bytes) + arbitrary paymaster data.
/// - `signature`: Account's signature over the user operation hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedUserOperation {
    /// The smart account address.
    pub sender: Address,
    /// The account nonce.
    pub nonce: u128,
    /// Factory init code (empty if account already deployed).
    pub init_code: Vec<u8>,
    /// Encoded calldata for the smart account to execute.
    pub call_data: Vec<u8>,
    /// Packed `verificationGasLimit ‖ callGasLimit` as 32 bytes.
    pub account_gas_limits: [u8; 32],
    /// Pre-verification gas (bundler overhead).
    pub pre_verification_gas: u128,
    /// Packed `maxPriorityFeePerGas ‖ maxFeePerGas` as 32 bytes.
    pub gas_fees: [u8; 32],
    /// Paymaster address + data (empty for no paymaster).
    pub paymaster_and_data: Vec<u8>,
    /// The signature (set after signing).
    pub signature: Vec<u8>,
}

impl PackedUserOperation {
    /// Returns a builder for constructing a `PackedUserOperation`.
    pub fn builder() -> PackedUserOperationBuilder {
        PackedUserOperationBuilder::default()
    }

    /// Packs `verificationGasLimit` (high 128 bits) and `callGasLimit` (low 128 bits)
    /// into a `bytes32` word.
    pub fn pack_gas_limits(verification_gas_limit: u128, call_gas_limit: u128) -> [u8; 32] {
        let mut packed = [0u8; 32];
        packed[0..16].copy_from_slice(&verification_gas_limit.to_be_bytes());
        packed[16..32].copy_from_slice(&call_gas_limit.to_be_bytes());
        packed
    }

    /// Packs `maxPriorityFeePerGas` (high 128 bits) and `maxFeePerGas` (low 128 bits)
    /// into a `bytes32` word.
    pub fn pack_gas_fees(max_priority_fee_per_gas: u128, max_fee_per_gas: u128) -> [u8; 32] {
        let mut packed = [0u8; 32];
        packed[0..16].copy_from_slice(&max_priority_fee_per_gas.to_be_bytes());
        packed[16..32].copy_from_slice(&max_fee_per_gas.to_be_bytes());
        packed
    }

    /// Unpacks `verificationGasLimit` from `account_gas_limits` (high 128 bits).
    pub fn verification_gas_limit(&self) -> u128 {
        u128::from_be_bytes(self.account_gas_limits[0..16].try_into().unwrap())
    }

    /// Unpacks `callGasLimit` from `account_gas_limits` (low 128 bits).
    pub fn call_gas_limit(&self) -> u128 {
        u128::from_be_bytes(self.account_gas_limits[16..32].try_into().unwrap())
    }

    /// Unpacks `maxPriorityFeePerGas` from `gas_fees` (high 128 bits).
    pub fn max_priority_fee_per_gas(&self) -> u128 {
        u128::from_be_bytes(self.gas_fees[0..16].try_into().unwrap())
    }

    /// Unpacks `maxFeePerGas` from `gas_fees` (low 128 bits).
    pub fn max_fee_per_gas(&self) -> u128 {
        u128::from_be_bytes(self.gas_fees[16..32].try_into().unwrap())
    }

    /// Returns `true` if this operation uses a paymaster.
    pub fn has_paymaster(&self) -> bool {
        self.paymaster_and_data.len() >= 20
    }

    /// Returns the paymaster address if present (first 20 bytes of `paymaster_and_data`).
    pub fn paymaster_address(&self) -> Option<Address> {
        if self.paymaster_and_data.len() >= 20 {
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&self.paymaster_and_data[0..20]);
            Some(Address::from_bytes(bytes))
        } else {
            None
        }
    }

    /// Returns the paymaster-specific data (bytes after the 20-byte address).
    pub fn paymaster_data(&self) -> &[u8] {
        if self.paymaster_and_data.len() > 20 {
            &self.paymaster_and_data[20..]
        } else {
            &[]
        }
    }
}

/// Builder for [`PackedUserOperation`].
#[derive(Debug, Clone, Default)]
pub struct PackedUserOperationBuilder {
    sender: Option<Address>,
    nonce: Option<u128>,
    init_code: Vec<u8>,
    call_data: Vec<u8>,
    account_gas_limits: Option<[u8; 32]>,
    pre_verification_gas: Option<u128>,
    gas_fees: Option<[u8; 32]>,
    paymaster_and_data: Vec<u8>,
}

impl PackedUserOperationBuilder {
    /// Sets the smart account address (required).
    pub fn sender(mut self, address: Address) -> Self {
        self.sender = Some(address);
        self
    }

    /// Sets the account nonce (required).
    pub fn nonce(mut self, nonce: u128) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sets the factory init code for account deployment.
    pub fn init_code(mut self, init_code: Vec<u8>) -> Self {
        self.init_code = init_code;
        self
    }

    /// Sets the encoded calldata for the smart account to execute.
    pub fn call_data(mut self, call_data: Vec<u8>) -> Self {
        self.call_data = call_data;
        self
    }

    /// Sets the packed account gas limits from separate values.
    ///
    /// - `verification_gas_limit`: Gas for `validateUserOp` (typically 100k–200k).
    /// - `call_gas_limit`: Gas for the actual execution (depends on target contract).
    pub fn account_gas_limits(mut self, verification_gas_limit: u128, call_gas_limit: u128) -> Self {
        self.account_gas_limits =
            Some(PackedUserOperation::pack_gas_limits(verification_gas_limit, call_gas_limit));
        self
    }

    /// Sets the packed account gas limits from a pre-packed `bytes32` value.
    pub fn account_gas_limits_packed(mut self, packed: [u8; 32]) -> Self {
        self.account_gas_limits = Some(packed);
        self
    }

    /// Sets the pre-verification gas (required).
    pub fn pre_verification_gas(mut self, gas: u128) -> Self {
        self.pre_verification_gas = Some(gas);
        self
    }

    /// Sets the packed gas fees from separate values.
    ///
    /// - `max_priority_fee_per_gas`: Tip to the validator (in wei).
    /// - `max_fee_per_gas`: Maximum total fee per gas (in wei).
    pub fn gas_fees(mut self, max_priority_fee_per_gas: u128, max_fee_per_gas: u128) -> Self {
        self.gas_fees = Some(PackedUserOperation::pack_gas_fees(
            max_priority_fee_per_gas,
            max_fee_per_gas,
        ));
        self
    }

    /// Sets the packed gas fees from a pre-packed `bytes32` value.
    pub fn gas_fees_packed(mut self, packed: [u8; 32]) -> Self {
        self.gas_fees = Some(packed);
        self
    }

    /// Sets the paymaster from an address and optional paymaster-specific data.
    ///
    /// Constructs `paymaster_and_data` as `address (20 bytes) ‖ data`.
    pub fn paymaster(mut self, address: Address, data: Vec<u8>) -> Self {
        let mut pad = Vec::with_capacity(20 + data.len());
        pad.extend_from_slice(address.as_bytes());
        pad.extend_from_slice(&data);
        self.paymaster_and_data = pad;
        self
    }

    /// Sets the raw `paymaster_and_data` bytes directly.
    pub fn paymaster_and_data_raw(mut self, data: Vec<u8>) -> Self {
        self.paymaster_and_data = data;
        self
    }

    /// Builds the [`PackedUserOperation`].
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing.
    pub fn build(self) -> Result<PackedUserOperation> {
        Ok(PackedUserOperation {
            sender: self
                .sender
                .ok_or_else(|| Error::ValidationError("sender is required".to_string()))?,
            nonce: self
                .nonce
                .ok_or_else(|| Error::ValidationError("nonce is required".to_string()))?,
            init_code: self.init_code,
            call_data: self.call_data,
            account_gas_limits: self.account_gas_limits.ok_or_else(|| {
                Error::ValidationError("account_gas_limits is required".to_string())
            })?,
            pre_verification_gas: self.pre_verification_gas.ok_or_else(|| {
                Error::ValidationError("pre_verification_gas is required".to_string())
            })?,
            gas_fees: self
                .gas_fees
                .ok_or_else(|| Error::ValidationError("gas_fees is required".to_string()))?,
            paymaster_and_data: self.paymaster_and_data,
            signature: Vec::new(),
        })
    }
}

/// Computes the ERC-4337 v0.7 user operation hash.
///
/// ```text
/// userOpHash = keccak256(
///     keccak256(pack(userOp))  ‖  entry_point (32 bytes)  ‖  chain_id (32 bytes)
/// )
/// ```
///
/// where `pack(userOp)` ABI-encodes all fields **except** `signature`.
pub fn hash_user_operation(
    user_op: &PackedUserOperation,
    entry_point: Address,
    chain_id: u64,
) -> [u8; 32] {
    let packed_hash = keccak256(&pack_user_operation(user_op));

    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&packed_hash);
    outer.extend_from_slice(&{
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(entry_point.as_bytes());
        word
    });
    outer.extend_from_slice(&{
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&chain_id.to_be_bytes());
        word
    });

    keccak256(&outer)
}

/// Signs a `PackedUserOperation` and returns the ECDSA signature.
///
/// The signature is computed over [`hash_user_operation`]. After signing,
/// set `user_op.signature = sig.to_bytes().to_vec()` before submitting to the bundler.
///
/// # Errors
///
/// Returns an error if the underlying ECDSA signing fails.
pub fn sign_user_operation(
    signer: &crate::Bip44Signer,
    user_op: &PackedUserOperation,
    entry_point: Address,
    chain_id: u64,
) -> Result<Signature> {
    let hash = hash_user_operation(user_op, entry_point, chain_id);
    signer.sign_hash(&hash)
}

/// Verifies a user operation signature.
///
/// Returns `Ok(true)` if the recovered signer matches `expected_signer`.
///
/// # Errors
///
/// Returns an error if signature recovery fails.
pub fn verify_user_operation(
    user_op: &PackedUserOperation,
    entry_point: Address,
    chain_id: u64,
    signature: &Signature,
    expected_signer: Address,
) -> Result<bool> {
    let hash = hash_user_operation(user_op, entry_point, chain_id);
    let recovered = crate::recover_signer(&hash, signature)?;
    Ok(recovered == expected_signer)
}

/// ABI-encodes the `PackedUserOperation` fields (excluding `signature`) for hashing.
///
/// Per ERC-4337 v0.7:
/// ```text
/// abi.encode(
///   sender, nonce, keccak256(initCode), keccak256(callData),
///   accountGasLimits, preVerificationGas, gasFees,
///   keccak256(paymasterAndData)
/// )
/// ```
fn pack_user_operation(user_op: &PackedUserOperation) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 * 32);

    // sender: address left-padded to 32 bytes
    buf.extend_from_slice(&{
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(user_op.sender.as_bytes());
        word
    });
    // nonce: uint256
    buf.extend_from_slice(&{
        let mut word = [0u8; 32];
        word[16..].copy_from_slice(&user_op.nonce.to_be_bytes());
        word
    });
    // initCode: keccak256
    buf.extend_from_slice(&keccak256(&user_op.init_code));
    // callData: keccak256
    buf.extend_from_slice(&keccak256(&user_op.call_data));
    // accountGasLimits: bytes32
    buf.extend_from_slice(&user_op.account_gas_limits);
    // preVerificationGas: uint256
    buf.extend_from_slice(&{
        let mut word = [0u8; 32];
        word[16..].copy_from_slice(&user_op.pre_verification_gas.to_be_bytes());
        word
    });
    // gasFees: bytes32
    buf.extend_from_slice(&user_op.gas_fees);
    // paymasterAndData: keccak256
    buf.extend_from_slice(&keccak256(&user_op.paymaster_and_data));

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bip44Signer;

    fn test_sender() -> Address {
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap()
    }

    fn test_entry_point() -> Address {
        ENTRY_POINT_V07.parse().unwrap()
    }

    fn test_paymaster() -> Address {
        "0x1111111111111111111111111111111111111111".parse().unwrap()
    }

    fn minimal_user_op() -> PackedUserOperation {
        PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(0)
            .call_data(vec![0xde, 0xad, 0xbe, 0xef])
            .account_gas_limits(150_000, 300_000)
            .pre_verification_gas(50_000)
            .gas_fees(1_000_000_000, 5_000_000_000)
            .build()
            .unwrap()
    }

    #[test]
    fn test_builder_minimal() {
        let op = minimal_user_op();
        assert_eq!(op.sender, test_sender());
        assert_eq!(op.nonce, 0);
        assert_eq!(op.call_data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(op.init_code.is_empty());
        assert!(op.paymaster_and_data.is_empty());
        assert!(op.signature.is_empty());
    }

    #[test]
    fn test_builder_with_paymaster() {
        let op = PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(1)
            .call_data(vec![0x01])
            .account_gas_limits(100_000, 200_000)
            .pre_verification_gas(21_000)
            .gas_fees(1_000_000_000, 3_000_000_000)
            .paymaster(test_paymaster(), vec![0xaa, 0xbb])
            .build()
            .unwrap();

        assert!(op.has_paymaster());
        assert_eq!(op.paymaster_address(), Some(test_paymaster()));
        assert_eq!(op.paymaster_data(), &[0xaa, 0xbb]);
        assert_eq!(op.paymaster_and_data.len(), 22);
    }

    #[test]
    fn test_builder_missing_sender() {
        let result = PackedUserOperation::builder()
            .nonce(0)
            .call_data(vec![])
            .account_gas_limits(100_000, 200_000)
            .pre_verification_gas(21_000)
            .gas_fees(1_000_000_000, 3_000_000_000)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sender"));
    }

    #[test]
    fn test_builder_missing_nonce() {
        let result = PackedUserOperation::builder()
            .sender(test_sender())
            .call_data(vec![])
            .account_gas_limits(100_000, 200_000)
            .pre_verification_gas(21_000)
            .gas_fees(1_000_000_000, 3_000_000_000)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce"));
    }

    #[test]
    fn test_builder_missing_gas_limits() {
        let result = PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(0)
            .call_data(vec![])
            .pre_verification_gas(21_000)
            .gas_fees(1_000_000_000, 3_000_000_000)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("account_gas_limits"));
    }

    #[test]
    fn test_pack_gas_limits_roundtrip() {
        let vgl = 150_000u128;
        let cgl = 300_000u128;
        let packed = PackedUserOperation::pack_gas_limits(vgl, cgl);
        let op = PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(0)
            .call_data(vec![])
            .account_gas_limits_packed(packed)
            .pre_verification_gas(21_000)
            .gas_fees(1_000_000_000, 3_000_000_000)
            .build()
            .unwrap();
        assert_eq!(op.verification_gas_limit(), vgl);
        assert_eq!(op.call_gas_limit(), cgl);
    }

    #[test]
    fn test_pack_gas_fees_roundtrip() {
        let mpfpg = 1_500_000_000u128;
        let mfpg = 6_000_000_000u128;
        let packed = PackedUserOperation::pack_gas_fees(mpfpg, mfpg);
        let op = PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(0)
            .call_data(vec![])
            .account_gas_limits(100_000, 200_000)
            .pre_verification_gas(21_000)
            .gas_fees_packed(packed)
            .build()
            .unwrap();
        assert_eq!(op.max_priority_fee_per_gas(), mpfpg);
        assert_eq!(op.max_fee_per_gas(), mfpg);
    }

    #[test]
    fn test_hash_deterministic() {
        let op = minimal_user_op();
        assert_eq!(
            hash_user_operation(&op, test_entry_point(), 56),
            hash_user_operation(&op, test_entry_point(), 56)
        );
    }

    #[test]
    fn test_hash_differs_by_chain() {
        let op = minimal_user_op();
        assert_ne!(
            hash_user_operation(&op, test_entry_point(), 56),
            hash_user_operation(&op, test_entry_point(), 97)
        );
    }

    #[test]
    fn test_hash_differs_by_entry_point() {
        let op = minimal_user_op();
        let ep2: Address = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789".parse().unwrap();
        assert_ne!(
            hash_user_operation(&op, test_entry_point(), 56),
            hash_user_operation(&op, ep2, 56)
        );
    }

    #[test]
    fn test_hash_differs_by_nonce() {
        let op1 = minimal_user_op();
        let op2 = PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(1)
            .call_data(vec![0xde, 0xad, 0xbe, 0xef])
            .account_gas_limits(150_000, 300_000)
            .pre_verification_gas(50_000)
            .gas_fees(1_000_000_000, 5_000_000_000)
            .build()
            .unwrap();
        assert_ne!(
            hash_user_operation(&op1, test_entry_point(), 56),
            hash_user_operation(&op2, test_entry_point(), 56)
        );
    }

    #[test]
    fn test_hash_differs_by_call_data() {
        let op1 = minimal_user_op();
        let op2 = PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(0)
            .call_data(vec![0x01, 0x02, 0x03])
            .account_gas_limits(150_000, 300_000)
            .pre_verification_gas(50_000)
            .gas_fees(1_000_000_000, 5_000_000_000)
            .build()
            .unwrap();
        assert_ne!(
            hash_user_operation(&op1, test_entry_point(), 56),
            hash_user_operation(&op2, test_entry_point(), 56)
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
        let op = minimal_user_op();
        let sig = sign_user_operation(&signer, &op, test_entry_point(), 56).unwrap();
        let valid = verify_user_operation(&op, test_entry_point(), 56, &sig, signer.address()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_signer_returns_false() {
        let signer1 = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
        let mut key2 = [1u8; 32];
        key2[31] = 2;
        let signer2 = Bip44Signer::from_private_key(&key2).unwrap();
        let op = minimal_user_op();
        let sig = sign_user_operation(&signer1, &op, test_entry_point(), 56).unwrap();
        let valid = verify_user_operation(&op, test_entry_point(), 56, &sig, signer2.address()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_sign_deterministic() {
        let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
        let op = minimal_user_op();
        let sig1 = sign_user_operation(&signer, &op, test_entry_point(), 56).unwrap();
        let sig2 = sign_user_operation(&signer, &op, test_entry_point(), 56).unwrap();
        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
        assert_eq!(sig1.v, sig2.v);
    }

    #[test]
    fn test_cross_chain_signature_invalid() {
        let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
        let op = minimal_user_op();
        let sig = sign_user_operation(&signer, &op, test_entry_point(), 56).unwrap();
        let valid = verify_user_operation(&op, test_entry_point(), 97, &sig, signer.address()).unwrap();
        assert!(!valid, "Signature from chain 56 must not be valid on chain 97");
    }

    #[test]
    fn test_signature_bytes_roundtrip() {
        let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
        let op = minimal_user_op();
        let sig = sign_user_operation(&signer, &op, test_entry_point(), 56).unwrap();
        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, recovered);
    }

    #[test]
    fn test_no_paymaster() {
        let op = minimal_user_op();
        assert!(!op.has_paymaster());
        assert_eq!(op.paymaster_address(), None);
        assert_eq!(op.paymaster_data(), &[] as &[u8]);
    }

    #[test]
    fn test_paymaster_no_extra_data() {
        let op = PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(0)
            .call_data(vec![])
            .account_gas_limits(100_000, 200_000)
            .pre_verification_gas(21_000)
            .gas_fees(1_000_000_000, 3_000_000_000)
            .paymaster(test_paymaster(), vec![])
            .build()
            .unwrap();
        assert!(op.has_paymaster());
        assert_eq!(op.paymaster_address(), Some(test_paymaster()));
        assert_eq!(op.paymaster_data(), &[] as &[u8]);
    }

    #[test]
    fn test_entry_point_v07_parses() {
        let ep: Result<Address> = ENTRY_POINT_V07.parse().map_err(|e: crate::Error| e);
        assert!(ep.is_ok());
    }

    #[test]
    fn test_with_init_code() {
        let op = PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(0)
            .init_code(vec![0xfa, 0xce])
            .call_data(vec![0x01])
            .account_gas_limits(200_000, 400_000)
            .pre_verification_gas(60_000)
            .gas_fees(2_000_000_000, 8_000_000_000)
            .build()
            .unwrap();
        assert_eq!(op.init_code, vec![0xfa, 0xce]);
        // Hash should differ from op without init_code
        let op_no_init = PackedUserOperation::builder()
            .sender(test_sender())
            .nonce(0)
            .call_data(vec![0x01])
            .account_gas_limits(200_000, 400_000)
            .pre_verification_gas(60_000)
            .gas_fees(2_000_000_000, 8_000_000_000)
            .build()
            .unwrap();
        assert_ne!(
            hash_user_operation(&op, test_entry_point(), 56),
            hash_user_operation(&op_no_init, test_entry_point(), 56)
        );
    }
}
