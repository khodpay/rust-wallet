//! Integration tests for EIP-712 and ERC-4337 modules.
//!
//! Demonstrates a realistic WPGP (Web3 Payment Gateway Protocol) scenario using
//! the generic `Eip712Type` trait and `PackedUserOperation` builder.
//!
//! Two payment paths are tested:
//! - **Smart Wallet (ERC-4337 gasless)**: Business signs `PaymentIntent` with EIP-712;
//!   user signs the resulting `PackedUserOperation`.
//! - **EOA Wallet**: Business signs `PaymentIntent`; user submits a standard EIP-1559
//!   transaction directly to the gateway contract.

use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Purpose, Wallet};
use khodpay_signing::{
    eip712::{
        encode_address, encode_bytes32, encode_uint64,
        hash_typed_data, sign_typed_data, verify_typed_data, Eip712Domain, Eip712Type,
    },
    erc4337::{
        hash_user_operation, sign_user_operation, verify_user_operation, PackedUserOperation,
        ENTRY_POINT_V07,
    },
    recover_signer, Address, Bip44Signer, ChainId, Eip1559Transaction, SignedTransaction, Wei,
};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BSC_CHAIN_ID: u64 = 56;

// ─── PaymentIntent: example Eip712Type implementation ────────────────────────

/// Example domain-specific struct implementing [`Eip712Type`].
///
/// Mirrors the Solidity struct used by the WPGP PaymentGateway contract:
/// ```solidity
/// struct PaymentIntent {
///     address business;
///     address recipient;
///     address token;       // address(0) = native BNB
///     uint64  amount;
///     uint64  deadline;
///     bytes32 invoiceId;
///     uint64  nonce;
/// }
/// ```
struct PaymentIntent {
    business: Address,
    recipient: Address,
    token: Address,
    amount: u64,
    deadline: u64,
    invoice_id: [u8; 32],
    nonce: u64,
}

impl Eip712Type for PaymentIntent {
    fn type_string() -> &'static str {
        "PaymentIntent(address business,address recipient,address token,uint64 amount,uint64 deadline,bytes32 invoiceId,uint64 nonce)"
    }

    fn encode_data(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 * 32);
        buf.extend_from_slice(&encode_address(&self.business));
        buf.extend_from_slice(&encode_address(&self.recipient));
        buf.extend_from_slice(&encode_address(&self.token));
        buf.extend_from_slice(&encode_uint64(self.amount));
        buf.extend_from_slice(&encode_uint64(self.deadline));
        buf.extend_from_slice(&encode_bytes32(self.invoice_id));
        buf.extend_from_slice(&encode_uint64(self.nonce));
        buf
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn make_signer(account_index: u32, address_index: u32) -> Bip44Signer {
    let mut wallet =
        Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, account_index)
        .unwrap();
    Bip44Signer::new(account, address_index).unwrap()
}

fn gateway_address() -> Address {
    "0x1111111111111111111111111111111111111111".parse().unwrap()
}

fn paymaster_address() -> Address {
    "0x2222222222222222222222222222222222222222".parse().unwrap()
}

fn smart_account_address() -> Address {
    "0x3333333333333333333333333333333333333333".parse().unwrap()
}

fn recipient_address() -> Address {
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap()
}

fn make_domain() -> Eip712Domain {
    Eip712Domain::new("WPGP", "1", BSC_CHAIN_ID, gateway_address())
}

fn make_invoice_id(seed: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = seed;
    id[31] = seed;
    id
}

/// Minimal calldata encoder for `executePayment(PaymentIntent, bytes)`.
/// Uses a placeholder selector; real selector depends on exact Solidity ABI.
fn encode_execute_payment_calldata(
    intent: &PaymentIntent,
    business_sig: &khodpay_signing::Signature,
) -> Vec<u8> {
    let selector: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    let mut calldata = Vec::new();
    calldata.extend_from_slice(&selector);
    calldata.extend_from_slice(&encode_address(&intent.business));
    calldata.extend_from_slice(&encode_address(&intent.recipient));
    calldata.extend_from_slice(&encode_address(&intent.token));
    calldata.extend_from_slice(&encode_uint64(intent.amount));
    calldata.extend_from_slice(&encode_uint64(intent.deadline));
    calldata.extend_from_slice(&encode_bytes32(intent.invoice_id));
    calldata.extend_from_slice(&encode_uint64(intent.nonce));
    calldata.extend_from_slice(&business_sig.to_bytes());
    calldata
}

// ─── EIP-712 PaymentIntent Tests ──────────────────────────────────────────────

#[test]
fn test_payment_intent_type_hash_is_deterministic() {
    assert_eq!(PaymentIntent::type_hash(), PaymentIntent::type_hash());
}

#[test]
fn test_payment_intent_type_hash_is_nonzero() {
    assert_ne!(PaymentIntent::type_hash(), [0u8; 32]);
}

#[test]
fn test_payment_intent_hash_struct_deterministic() {
    let intent = PaymentIntent {
        business: make_signer(0, 0).address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(1),
        nonce: 0,
    };
    assert_eq!(intent.hash_struct(), intent.hash_struct());
}

#[test]
fn test_payment_intent_hash_differs_by_amount() {
    let domain = make_domain();
    let base = PaymentIntent {
        business: make_signer(0, 0).address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(1),
        nonce: 0,
    };
    let modified = PaymentIntent {
        business: base.business,
        recipient: base.recipient,
        token: base.token,
        amount: 2_000_000_000,
        deadline: base.deadline,
        invoice_id: base.invoice_id,
        nonce: base.nonce,
    };
    assert_ne!(hash_typed_data(&domain, &base), hash_typed_data(&domain, &modified));
}

#[test]
fn test_payment_intent_hash_differs_by_nonce() {
    let domain = make_domain();
    let business = make_signer(0, 0).address();
    let intent0 = PaymentIntent {
        business,
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(1),
        nonce: 0,
    };
    let intent1 = PaymentIntent {
        business,
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(1),
        nonce: 1,
    };
    assert_ne!(hash_typed_data(&domain, &intent0), hash_typed_data(&domain, &intent1));
}

#[test]
fn test_payment_intent_hash_differs_by_invoice_id() {
    let domain = make_domain();
    let business = make_signer(0, 0).address();
    let intent_a = PaymentIntent {
        business,
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(0xAA),
        nonce: 0,
    };
    let intent_b = PaymentIntent {
        business,
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(0xBB),
        nonce: 0,
    };
    assert_ne!(hash_typed_data(&domain, &intent_a), hash_typed_data(&domain, &intent_b));
}

// ─── Business Signing Tests ───────────────────────────────────────────────────

#[test]
fn test_business_signs_payment_intent() {
    let business_signer = make_signer(0, 0);
    let domain = make_domain();
    let intent = PaymentIntent {
        business: business_signer.address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(1),
        nonce: 0,
    };

    let sig = sign_typed_data(&business_signer, &domain, &intent).unwrap();
    let valid = verify_typed_data(&domain, &intent, &sig, business_signer.address()).unwrap();
    assert!(valid, "Business signature must verify against business address");
}

#[test]
fn test_business_signature_is_deterministic() {
    let business_signer = make_signer(0, 0);
    let domain = make_domain();
    let intent = PaymentIntent {
        business: business_signer.address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 500_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(2),
        nonce: 5,
    };

    let sig1 = sign_typed_data(&business_signer, &domain, &intent).unwrap();
    let sig2 = sign_typed_data(&business_signer, &domain, &intent).unwrap();
    assert_eq!(sig1.r, sig2.r);
    assert_eq!(sig1.s, sig2.s);
    assert_eq!(sig1.v, sig2.v);
}

#[test]
fn test_attacker_cannot_forge_business_signature() {
    let business_signer = make_signer(0, 0);
    let attacker_signer = make_signer(0, 1);
    let domain = make_domain();
    let intent = PaymentIntent {
        business: business_signer.address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(3),
        nonce: 0,
    };

    let attacker_sig = sign_typed_data(&attacker_signer, &domain, &intent).unwrap();
    let valid =
        verify_typed_data(&domain, &intent, &attacker_sig, business_signer.address()).unwrap();
    assert!(!valid, "Attacker signature must not verify as business");
}

#[test]
fn test_cross_chain_payment_intent_signature_rejected() {
    let business_signer = make_signer(0, 0);
    let domain_mainnet = Eip712Domain::new("WPGP", "1", 56, gateway_address());
    let domain_testnet = Eip712Domain::new("WPGP", "1", 97, gateway_address());
    let intent = PaymentIntent {
        business: business_signer.address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(4),
        nonce: 0,
    };

    let sig = sign_typed_data(&business_signer, &domain_mainnet, &intent).unwrap();
    let valid =
        verify_typed_data(&domain_testnet, &intent, &sig, business_signer.address()).unwrap();
    assert!(!valid, "Mainnet signature must not be valid on testnet");
}

#[test]
fn test_tampered_intent_signature_rejected() {
    let business_signer = make_signer(0, 0);
    let domain = make_domain();
    let original = PaymentIntent {
        business: business_signer.address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(5),
        nonce: 0,
    };
    let sig = sign_typed_data(&business_signer, &domain, &original).unwrap();

    let tampered = PaymentIntent {
        business: original.business,
        recipient: original.recipient,
        token: original.token,
        amount: 999_999_999_999_999_999,
        deadline: original.deadline,
        invoice_id: original.invoice_id,
        nonce: original.nonce,
    };
    let valid = verify_typed_data(&domain, &tampered, &sig, business_signer.address()).unwrap();
    assert!(!valid, "Signature over original must not verify tampered intent");
}

// ─── ERC-4337 Smart Wallet Path ───────────────────────────────────────────────

#[test]
fn test_smart_wallet_full_flow() {
    let business_signer = make_signer(0, 0);
    let user_signer = make_signer(0, 1);
    let entry_point: Address = ENTRY_POINT_V07.parse().unwrap();
    let domain = make_domain();

    // Step 1: Business signs PaymentIntent
    let intent = PaymentIntent {
        business: business_signer.address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000_000_000_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(10),
        nonce: 0,
    };
    let business_sig = sign_typed_data(&business_signer, &domain, &intent).unwrap();
    assert!(verify_typed_data(&domain, &intent, &business_sig, business_signer.address()).unwrap());

    // Step 2: Encode calldata
    let call_data = encode_execute_payment_calldata(&intent, &business_sig);
    assert!(!call_data.is_empty());

    // Step 3: Build UserOperation
    let user_op = PackedUserOperation::builder()
        .sender(smart_account_address())
        .nonce(0)
        .call_data(call_data)
        .account_gas_limits(150_000, 300_000)
        .pre_verification_gas(50_000)
        .gas_fees(1_000_000_000, 5_000_000_000)
        .paymaster(paymaster_address(), vec![])
        .build()
        .unwrap();

    assert!(user_op.has_paymaster());
    assert_eq!(user_op.paymaster_address(), Some(paymaster_address()));

    // Step 4: User signs UserOperation
    let user_op_sig =
        sign_user_operation(&user_signer, &user_op, entry_point, BSC_CHAIN_ID).unwrap();

    // Step 5: Verify
    let valid = verify_user_operation(
        &user_op,
        entry_point,
        BSC_CHAIN_ID,
        &user_op_sig,
        user_signer.address(),
    )
    .unwrap();
    assert!(valid, "User's UserOperation signature must be valid");

    // Step 6: Attach signature — must be 65 bytes
    let mut signed_op = user_op;
    signed_op.signature = user_op_sig.to_bytes().to_vec();
    assert_eq!(signed_op.signature.len(), 65);
}

#[test]
fn test_user_op_hash_differs_by_call_data() {
    let entry_point: Address = ENTRY_POINT_V07.parse().unwrap();
    let op1 = PackedUserOperation::builder()
        .sender(smart_account_address())
        .nonce(0)
        .call_data(vec![0x01, 0x02, 0x03])
        .account_gas_limits(150_000, 300_000)
        .pre_verification_gas(50_000)
        .gas_fees(1_000_000_000, 5_000_000_000)
        .build()
        .unwrap();
    let op2 = PackedUserOperation::builder()
        .sender(smart_account_address())
        .nonce(0)
        .call_data(vec![0x04, 0x05, 0x06])
        .account_gas_limits(150_000, 300_000)
        .pre_verification_gas(50_000)
        .gas_fees(1_000_000_000, 5_000_000_000)
        .build()
        .unwrap();
    assert_ne!(
        hash_user_operation(&op1, entry_point, BSC_CHAIN_ID),
        hash_user_operation(&op2, entry_point, BSC_CHAIN_ID)
    );
}

#[test]
fn test_user_op_signature_is_chain_bound() {
    let user_signer = make_signer(0, 1);
    let entry_point: Address = ENTRY_POINT_V07.parse().unwrap();
    let user_op = PackedUserOperation::builder()
        .sender(smart_account_address())
        .nonce(0)
        .call_data(vec![0xca, 0xfe])
        .account_gas_limits(150_000, 300_000)
        .pre_verification_gas(50_000)
        .gas_fees(1_000_000_000, 5_000_000_000)
        .build()
        .unwrap();

    let sig = sign_user_operation(&user_signer, &user_op, entry_point, 56).unwrap();
    let valid =
        verify_user_operation(&user_op, entry_point, 97, &sig, user_signer.address()).unwrap();
    assert!(!valid, "Mainnet UserOp signature must not be valid on testnet");
}

#[test]
fn test_user_op_signature_is_entry_point_bound() {
    let user_signer = make_signer(0, 1);
    let ep_v07: Address = ENTRY_POINT_V07.parse().unwrap();
    let ep_v06: Address = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789".parse().unwrap();
    let user_op = PackedUserOperation::builder()
        .sender(smart_account_address())
        .nonce(0)
        .call_data(vec![0xbe, 0xef])
        .account_gas_limits(150_000, 300_000)
        .pre_verification_gas(50_000)
        .gas_fees(1_000_000_000, 5_000_000_000)
        .build()
        .unwrap();

    let sig = sign_user_operation(&user_signer, &user_op, ep_v07, BSC_CHAIN_ID).unwrap();
    let valid =
        verify_user_operation(&user_op, ep_v06, BSC_CHAIN_ID, &sig, user_signer.address())
            .unwrap();
    assert!(!valid, "Signature for v0.7 EntryPoint must not verify against v0.6");
}

#[test]
fn test_attacker_cannot_sign_user_op_as_real_user() {
    let real_user = make_signer(0, 1);
    let attacker = make_signer(0, 2);
    let entry_point: Address = ENTRY_POINT_V07.parse().unwrap();
    let user_op = PackedUserOperation::builder()
        .sender(smart_account_address())
        .nonce(0)
        .call_data(vec![0xde, 0xad])
        .account_gas_limits(150_000, 300_000)
        .pre_verification_gas(50_000)
        .gas_fees(1_000_000_000, 5_000_000_000)
        .build()
        .unwrap();

    let attacker_sig =
        sign_user_operation(&attacker, &user_op, entry_point, BSC_CHAIN_ID).unwrap();
    let valid = verify_user_operation(
        &user_op,
        entry_point,
        BSC_CHAIN_ID,
        &attacker_sig,
        real_user.address(),
    )
    .unwrap();
    assert!(!valid, "Attacker's signature must not verify as the real user");
}

// ─── EOA Wallet Path ──────────────────────────────────────────────────────────

#[test]
fn test_eoa_path_full_flow() {
    let business_signer = make_signer(0, 0);
    let user_signer = make_signer(0, 1);
    let domain = make_domain();

    // Step 1: Business signs PaymentIntent
    let intent = PaymentIntent {
        business: business_signer.address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 500_000_000_000_000_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(20),
        nonce: 3,
    };
    let business_sig = sign_typed_data(&business_signer, &domain, &intent).unwrap();
    assert!(verify_typed_data(&domain, &intent, &business_sig, business_signer.address()).unwrap());

    // Step 2: Encode calldata
    let call_data = encode_execute_payment_calldata(&intent, &business_sig);

    // Step 3: User builds and signs EIP-1559 transaction directly to gateway
    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(200_000)
        .to(gateway_address())
        .value(Wei::from_gwei(500_000_000))
        .data(call_data)
        .build()
        .unwrap();

    let tx_sig = user_signer.sign_transaction(&tx).unwrap();
    let signed_tx = SignedTransaction::new(tx.clone(), tx_sig);

    // Step 4: Verify raw transaction is well-formed
    let raw_tx = signed_tx.to_raw_transaction();
    assert!(raw_tx.starts_with("0x02"), "EOA tx must be EIP-1559 type 2");
    let tx_hash = signed_tx.tx_hash_hex();
    assert!(tx_hash.starts_with("0x"));
    assert_eq!(tx_hash.len(), 66);

    // Step 5: Verify signer recovery
    let recovered = recover_signer(&tx.signing_hash(), &tx_sig).unwrap();
    assert_eq!(recovered, user_signer.address());
}

// ─── Multi-Payment / Nonce Replay Protection ──────────────────────────────────

#[test]
fn test_sequential_nonces_produce_different_hashes() {
    let business_signer = make_signer(0, 0);
    let domain = make_domain();

    let hashes: Vec<[u8; 32]> = (0u64..5)
        .map(|nonce| {
            let intent = PaymentIntent {
                business: business_signer.address(),
                recipient: recipient_address(),
                token: Address::ZERO,
                amount: 1_000_000_000,
                deadline: 1_708_185_600,
                invoice_id: make_invoice_id(nonce as u8),
                nonce,
            };
            hash_typed_data(&domain, &intent)
        })
        .collect();

    // All hashes must be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Nonce {} and {} produced same hash", i, j);
        }
    }
}

#[test]
fn test_sequential_user_op_nonces_produce_different_hashes() {
    let entry_point: Address = ENTRY_POINT_V07.parse().unwrap();

    let hashes: Vec<[u8; 32]> = (0u128..5)
        .map(|nonce| {
            let op = PackedUserOperation::builder()
                .sender(smart_account_address())
                .nonce(nonce)
                .call_data(vec![0x01])
                .account_gas_limits(150_000, 300_000)
                .pre_verification_gas(50_000)
                .gas_fees(1_000_000_000, 5_000_000_000)
                .build()
                .unwrap();
            hash_user_operation(&op, entry_point, BSC_CHAIN_ID)
        })
        .collect();

    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Nonce {} and {} produced same hash", i, j);
        }
    }
}

// ─── Domain Flexibility Tests ─────────────────────────────────────────────────

#[test]
fn test_domain_without_verifying_contract() {
    let signer = make_signer(0, 0);
    let domain = Eip712Domain::builder()
        .name("MinimalApp")
        .version("2")
        .chain_id(BSC_CHAIN_ID)
        .build();

    let intent = PaymentIntent {
        business: signer.address(),
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 100,
        deadline: 9_999_999_999,
        invoice_id: make_invoice_id(0xFF),
        nonce: 0,
    };

    let sig = sign_typed_data(&signer, &domain, &intent).unwrap();
    let valid = verify_typed_data(&domain, &intent, &sig, signer.address()).unwrap();
    assert!(valid);
}

#[test]
fn test_same_intent_different_domains_produce_different_hashes() {
    let business = make_signer(0, 0).address();
    let domain_v1 = Eip712Domain::new("WPGP", "1", BSC_CHAIN_ID, gateway_address());
    let domain_v2 = Eip712Domain::new("WPGP", "2", BSC_CHAIN_ID, gateway_address());

    let intent = PaymentIntent {
        business,
        recipient: recipient_address(),
        token: Address::ZERO,
        amount: 1_000,
        deadline: 1_708_185_600,
        invoice_id: make_invoice_id(0x01),
        nonce: 0,
    };

    assert_ne!(
        hash_typed_data(&domain_v1, &intent),
        hash_typed_data(&domain_v2, &intent),
        "Different domain versions must produce different hashes"
    );
}
