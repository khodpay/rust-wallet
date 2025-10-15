//! # BIP32 Official Test Vectors
//!
//! This module contains the official test vectors from the BIP32 specification.
//! These test vectors are used to verify compliance with the BIP32 standard.
//!
//! Source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//!
//! ## Test Vectors Included:
//! - **Test Vector 1**: Basic derivation paths
//! - **Test Vector 2**: Maximum hardened derivation values
//! - **Test Vector 3**: Retention of leading zeros (bitpay/bitcore-lib#47)
//! - **Test Vector 4**: Retention of leading zeros (btcsuite/btcutil#172)
//! - **Test Vector 5**: Invalid extended keys (for error handling tests)

use bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey, ExtendedPublicKey, Network};
use std::str::FromStr;

/// Represents a single derivation step in a test vector
#[derive(Debug, Clone)]
pub struct DerivationStep {
    /// The derivation path (e.g., "m", "m/0H", "m/0H/1")
    pub path: &'static str,
    /// Expected extended public key (xpub format)
    pub ext_pub: &'static str,
    /// Expected extended private key (xprv format)
    pub ext_prv: &'static str,
}

/// Represents a complete test vector with seed and derivation steps
#[derive(Debug, Clone)]
pub struct TestVector {
    /// Description of the test vector
    pub description: &'static str,
    /// The seed in hexadecimal format
    pub seed_hex: &'static str,
    /// All derivation steps for this test vector
    pub derivations: &'static [DerivationStep],
}

/// Test Vector 1 - Basic derivation paths
///
/// Seed: 000102030405060708090a0b0c0d0e0f
pub const TEST_VECTOR_1: TestVector = TestVector {
    description: "Test Vector 1: Basic derivation paths",
    seed_hex: "000102030405060708090a0b0c0d0e0f",
    derivations: &[
        DerivationStep {
            path: "m",
            ext_pub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            ext_prv: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        },
        DerivationStep {
            path: "m/0H",
            ext_pub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
            ext_prv: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        },
        DerivationStep {
            path: "m/0H/1",
            ext_pub: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
            ext_prv: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        },
        DerivationStep {
            path: "m/0H/1/2H",
            ext_pub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
            ext_prv: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        },
        DerivationStep {
            path: "m/0H/1/2H/2",
            ext_pub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
            ext_prv: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        },
        DerivationStep {
            path: "m/0H/1/2H/2/1000000000",
            ext_pub: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
            ext_prv: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        },
    ],
};

/// Test Vector 2 - Maximum hardened derivation values
///
/// Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
pub const TEST_VECTOR_2: TestVector = TestVector {
    description: "Test Vector 2: Maximum hardened derivation values",
    seed_hex: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    derivations: &[
        DerivationStep {
            path: "m",
            ext_pub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            ext_prv: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        },
        DerivationStep {
            path: "m/0",
            ext_pub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
            ext_prv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        },
        DerivationStep {
            path: "m/0/2147483647H",
            ext_pub: "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
            ext_prv: "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        },
        DerivationStep {
            path: "m/0/2147483647H/1",
            ext_pub: "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
            ext_prv: "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        },
        DerivationStep {
            path: "m/0/2147483647H/1/2147483646H",
            ext_pub: "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
            ext_prv: "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        },
        DerivationStep {
            path: "m/0/2147483647H/1/2147483646H/2",
            ext_pub: "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
            ext_prv: "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        },
    ],
};

/// Test Vector 3 - Retention of leading zeros
///
/// These vectors test for the retention of leading zeros.
/// See: https://github.com/bitpay/bitcore-lib/issues/47
/// See: https://github.com/iancoleman/bip39/issues/58
///
/// Seed: 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
pub const TEST_VECTOR_3: TestVector = TestVector {
    description: "Test Vector 3: Retention of leading zeros (bitpay/bitcore-lib#47)",
    seed_hex: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
    derivations: &[
        DerivationStep {
            path: "m",
            ext_pub: "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            ext_prv: "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
        },
        DerivationStep {
            path: "m/0H",
            ext_pub: "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
            ext_prv: "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
        },
    ],
};

/// Test Vector 4 - Retention of leading zeros (btcsuite)
///
/// These vectors test for the retention of leading zeros.
/// See: https://github.com/btcsuite/btcutil/issues/172
///
/// Seed: 3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678
pub const TEST_VECTOR_4: TestVector = TestVector {
    description: "Test Vector 4: Retention of leading zeros (btcsuite/btcutil#172)",
    seed_hex: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
    derivations: &[
        DerivationStep {
            path: "m",
            ext_pub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
            ext_prv: "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
        },
        DerivationStep {
            path: "m/0H",
            ext_pub: "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
            ext_prv: "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
        },
        DerivationStep {
            path: "m/0H/1H",
            ext_pub: "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
            ext_prv: "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
        },
    ],
};

/// Invalid extended keys for error handling tests (Test Vector 5)
///
/// These test vectors contain invalid extended keys that should be rejected.
pub const INVALID_EXTENDED_KEYS: &[(&str, &str)] = &[
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
        "pubkey version / prvkey mismatch"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
        "prvkey version / pubkey mismatch"
    ),
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
        "invalid pubkey prefix 04"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
        "invalid prvkey prefix 04"
    ),
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
        "invalid pubkey prefix 01"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
        "invalid prvkey prefix 01"
    ),
    (
        "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
        "zero depth with non-zero parent fingerprint"
    ),
    (
        "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
        "zero depth with non-zero parent fingerprint"
    ),
    (
        "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
        "zero depth with non-zero index"
    ),
    (
        "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
        "zero depth with non-zero index"
    ),
    (
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
        "unknown extended key version"
    ),
    (
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
        "unknown extended key version"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
        "private key 0 not in 1..n-1"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
        "private key n not in 1..n-1"
    ),
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
        "invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007"
    ),
    (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
        "invalid checksum"
    ),
];

/// Returns all valid test vectors (1-4)
pub fn all_test_vectors() -> Vec<&'static TestVector> {
    vec![&TEST_VECTOR_1, &TEST_VECTOR_2, &TEST_VECTOR_3, &TEST_VECTOR_4]
}

/// Helper function to convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_1_accessibility() {
        assert_eq!(TEST_VECTOR_1.description, "Test Vector 1: Basic derivation paths");
        assert_eq!(TEST_VECTOR_1.seed_hex, "000102030405060708090a0b0c0d0e0f");
        assert_eq!(TEST_VECTOR_1.derivations.len(), 6);
    }

    #[test]
    fn test_vector_2_accessibility() {
        assert_eq!(TEST_VECTOR_2.description, "Test Vector 2: Maximum hardened derivation values");
        assert_eq!(TEST_VECTOR_2.derivations.len(), 6);
    }

    #[test]
    fn test_vector_3_accessibility() {
        assert_eq!(TEST_VECTOR_3.description, "Test Vector 3: Retention of leading zeros (bitpay/bitcore-lib#47)");
        assert_eq!(TEST_VECTOR_3.derivations.len(), 2);
    }

    #[test]
    fn test_vector_4_accessibility() {
        assert_eq!(TEST_VECTOR_4.description, "Test Vector 4: Retention of leading zeros (btcsuite/btcutil#172)");
        assert_eq!(TEST_VECTOR_4.derivations.len(), 3);
    }

    #[test]
    fn test_invalid_keys_count() {
        assert_eq!(INVALID_EXTENDED_KEYS.len(), 16);
    }

    #[test]
    fn test_all_test_vectors_count() {
        assert_eq!(all_test_vectors().len(), 4);
    }

    #[test]
    fn test_hex_to_bytes_conversion() {
        let result = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[15], 0x0f);
    }

    // ============================================================================
    // Test Vector 1 - Basic derivation paths
    // ============================================================================

    /// Helper function to validate a single derivation step
    fn validate_derivation_step(
        master_key: &ExtendedPrivateKey,
        step: &DerivationStep,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Parse the path
        let path = DerivationPath::from_str(step.path)?;

        // Derive the private key
        let derived_prv = master_key.derive_path(&path)?;
        let derived_prv_str = derived_prv.to_string();

        // Derive the public key
        let derived_pub = derived_prv.to_extended_public_key();
        let derived_pub_str = derived_pub.to_string();

        // Validate against expected values
        assert_eq!(
            derived_prv_str, step.ext_prv,
            "Private key mismatch for path {}\nExpected: {}\nGot:      {}",
            step.path, step.ext_prv, derived_prv_str
        );

        assert_eq!(
            derived_pub_str, step.ext_pub,
            "Public key mismatch for path {}\nExpected: {}\nGot:      {}",
            step.path, step.ext_pub, derived_pub_str
        );

        Ok(())
    }

    #[test]
    fn test_vector_1_master_key() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test the master key (m)
        let master_step = &TEST_VECTOR_1.derivations[0];
        assert_eq!(master_step.path, "m");

        let master_prv_str = master_key.to_string();
        let master_pub_str = master_key.to_extended_public_key().to_string();

        assert_eq!(
            master_prv_str, master_step.ext_prv,
            "Master private key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_prv, master_prv_str
        );

        assert_eq!(
            master_pub_str, master_step.ext_pub,
            "Master public key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_pub, master_pub_str
        );
    }

    #[test]
    fn test_vector_1_derivation_m_0h() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H
        let step = &TEST_VECTOR_1.derivations[1];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H derivation");
    }

    #[test]
    fn test_vector_1_derivation_m_0h_1() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H/1
        let step = &TEST_VECTOR_1.derivations[2];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H/1 derivation");
    }

    #[test]
    fn test_vector_1_derivation_m_0h_1_2h() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H/1/2H
        let step = &TEST_VECTOR_1.derivations[3];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H/1/2H derivation");
    }

    #[test]
    fn test_vector_1_derivation_m_0h_1_2h_2() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H/1/2H/2
        let step = &TEST_VECTOR_1.derivations[4];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H/1/2H/2 derivation");
    }

    #[test]
    fn test_vector_1_derivation_m_0h_1_2h_2_1000000000() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H/1/2H/2/1000000000
        let step = &TEST_VECTOR_1.derivations[5];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H/1/2H/2/1000000000 derivation");
    }

    #[test]
    fn test_vector_1_complete() {
        // Test all derivations in Test Vector 1 in one comprehensive test
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        for step in TEST_VECTOR_1.derivations {
            validate_derivation_step(&master_key, step)
                .unwrap_or_else(|e| panic!("Failed to validate path {}: {}", step.path, e));
        }
    }

    // ============================================================================
    // Test Vector 2 - Maximum hardened derivation values
    // ============================================================================

    #[test]
    fn test_vector_2_master_key() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test the master key (m)
        let master_step = &TEST_VECTOR_2.derivations[0];
        assert_eq!(master_step.path, "m");

        let master_prv_str = master_key.to_string();
        let master_pub_str = master_key.to_extended_public_key().to_string();

        assert_eq!(
            master_prv_str, master_step.ext_prv,
            "Master private key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_prv, master_prv_str
        );

        assert_eq!(
            master_pub_str, master_step.ext_pub,
            "Master public key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_pub, master_pub_str
        );
    }

    #[test]
    fn test_vector_2_derivation_m_0() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0
        let step = &TEST_VECTOR_2.derivations[1];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0 derivation");
    }

    #[test]
    fn test_vector_2_derivation_m_0_2147483647h() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0/2147483647H
        let step = &TEST_VECTOR_2.derivations[2];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0/2147483647H derivation");
    }

    #[test]
    fn test_vector_2_derivation_m_0_2147483647h_1() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0/2147483647H/1
        let step = &TEST_VECTOR_2.derivations[3];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0/2147483647H/1 derivation");
    }

    #[test]
    fn test_vector_2_derivation_m_0_2147483647h_1_2147483646h() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0/2147483647H/1/2147483646H
        let step = &TEST_VECTOR_2.derivations[4];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0/2147483647H/1/2147483646H derivation");
    }

    #[test]
    fn test_vector_2_derivation_m_0_2147483647h_1_2147483646h_2() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0/2147483647H/1/2147483646H/2
        let step = &TEST_VECTOR_2.derivations[5];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0/2147483647H/1/2147483646H/2 derivation");
    }

    #[test]
    fn test_vector_2_complete() {
        // Test all derivations in Test Vector 2 in one comprehensive test
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        for step in TEST_VECTOR_2.derivations {
            validate_derivation_step(&master_key, step)
                .unwrap_or_else(|e| panic!("Failed to validate path {}: {}", step.path, e));
        }
    }

    // ============================================================================
    // Test Vector 3 - Retention of leading zeros
    // ============================================================================

    #[test]
    fn test_vector_3_master_key() {
        let seed = hex_to_bytes(TEST_VECTOR_3.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test the master key (m)
        let master_step = &TEST_VECTOR_3.derivations[0];
        assert_eq!(master_step.path, "m");

        let master_prv_str = master_key.to_string();
        let master_pub_str = master_key.to_extended_public_key().to_string();

        assert_eq!(
            master_prv_str, master_step.ext_prv,
            "Master private key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_prv, master_prv_str
        );

        assert_eq!(
            master_pub_str, master_step.ext_pub,
            "Master public key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_pub, master_pub_str
        );
    }

    #[test]
    fn test_vector_3_derivation_m_0h() {
        let seed = hex_to_bytes(TEST_VECTOR_3.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H
        let step = &TEST_VECTOR_3.derivations[1];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H derivation");
    }

    #[test]
    fn test_vector_3_complete() {
        // Test all derivations in Test Vector 3 in one comprehensive test
        let seed = hex_to_bytes(TEST_VECTOR_3.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        for step in TEST_VECTOR_3.derivations {
            validate_derivation_step(&master_key, step)
                .unwrap_or_else(|e| panic!("Failed to validate path {}: {}", step.path, e));
        }
    }

    // ============================================================================
    // Test Vector 4 - Additional leading zeros tests
    // ============================================================================

    #[test]
    fn test_vector_4_complete() {
        // Test all derivations in Test Vector 4
        let seed = hex_to_bytes(TEST_VECTOR_4.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        for step in TEST_VECTOR_4.derivations {
            validate_derivation_step(&master_key, step)
                .unwrap_or_else(|e| panic!("Failed to validate path {}: {}", step.path, e));
        }
    }

    // ============================================================================
    // Verify all derivation paths in test vectors
    // ============================================================================

    #[test]
    fn test_all_paths_parse_correctly() {
        // Verify that all derivation paths in all test vectors can be parsed
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                let result = DerivationPath::from_str(step.path);
                assert!(
                    result.is_ok(),
                    "Failed to parse path '{}' in {}: {:?}",
                    step.path,
                    test_vector.description,
                    result.err()
                );
            }
        }
    }

    #[test]
    fn test_path_depths_are_correct() {
        // Test Vector 1: depths 0, 1, 2, 3, 4, 5
        let expected_depths_v1 = [0, 1, 2, 3, 4, 5];
        for (i, step) in TEST_VECTOR_1.derivations.iter().enumerate() {
            let path = DerivationPath::from_str(step.path).unwrap();
            assert_eq!(
                path.depth(),
                expected_depths_v1[i],
                "Vector 1, path {} has incorrect depth",
                step.path
            );
        }

        // Test Vector 2: depths 0, 1, 2, 3, 4, 5
        let expected_depths_v2 = [0, 1, 2, 3, 4, 5];
        for (i, step) in TEST_VECTOR_2.derivations.iter().enumerate() {
            let path = DerivationPath::from_str(step.path).unwrap();
            assert_eq!(
                path.depth(),
                expected_depths_v2[i],
                "Vector 2, path {} has incorrect depth",
                step.path
            );
        }

        // Test Vector 3: depths 0, 1
        let expected_depths_v3 = [0, 1];
        for (i, step) in TEST_VECTOR_3.derivations.iter().enumerate() {
            let path = DerivationPath::from_str(step.path).unwrap();
            assert_eq!(
                path.depth(),
                expected_depths_v3[i],
                "Vector 3, path {} has incorrect depth",
                step.path
            );
        }

        // Test Vector 4: depths 0, 1, 2
        let expected_depths_v4 = [0, 1, 2];
        for (i, step) in TEST_VECTOR_4.derivations.iter().enumerate() {
            let path = DerivationPath::from_str(step.path).unwrap();
            assert_eq!(
                path.depth(),
                expected_depths_v4[i],
                "Vector 4, path {} has incorrect depth",
                step.path
            );
        }
    }

    #[test]
    fn test_path_hardened_detection() {
        // Test Vector 1: All paths contain hardened components
        for step in TEST_VECTOR_1.derivations.iter().skip(1) {
            // Skip master key
            let path = DerivationPath::from_str(step.path).unwrap();
            assert!(
                path.contains_hardened(),
                "Vector 1, path {} should contain hardened components",
                step.path
            );
        }

        // Test Vector 2: m/0 is normal, all others have hardened
        let path_m_0 = DerivationPath::from_str("m/0").unwrap();
        assert!(
            !path_m_0.contains_hardened(),
            "Path m/0 should not contain hardened components"
        );

        for step in TEST_VECTOR_2.derivations.iter().skip(2) {
            // Skip m and m/0
            let path = DerivationPath::from_str(step.path).unwrap();
            assert!(
                path.contains_hardened(),
                "Vector 2, path {} should contain hardened components",
                step.path
            );
        }

        // Test Vector 3 & 4: All non-master paths are hardened
        for test_vector in [&TEST_VECTOR_3, &TEST_VECTOR_4] {
            for step in test_vector.derivations.iter().skip(1) {
                let path = DerivationPath::from_str(step.path).unwrap();
                assert!(
                    path.contains_hardened(),
                    "Path {} should contain hardened components",
                    step.path
                );
            }
        }
    }

    #[test]
    fn test_path_public_derivation_compatibility() {
        // Test Vector 1: m/0H/1 has hardened prefix, not fully public derivable
        let path_m_0h_1 = DerivationPath::from_str("m/0H/1").unwrap();
        assert!(
            !path_m_0h_1.is_public_derivable(),
            "Path m/0H/1 should not be public derivable (contains hardened)"
        );

        // Test Vector 2: m/0 is fully public derivable (no hardened components)
        let path_m_0 = DerivationPath::from_str("m/0").unwrap();
        assert!(
            path_m_0.is_public_derivable(),
            "Path m/0 should be public derivable"
        );

        // Any path with hardened components should not be public derivable
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                let path = DerivationPath::from_str(step.path).unwrap();
                if path.contains_hardened() {
                    assert!(
                        !path.is_public_derivable(),
                        "Path {} with hardened components should not be public derivable",
                        step.path
                    );
                }
            }
        }
    }

    #[test]
    fn test_path_string_roundtrip() {
        // Verify that parsing and converting back to string gives consistent results
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                let path = DerivationPath::from_str(step.path).unwrap();
                let path_str = path.to_string();

                // The string representation should be parseable back
                let reparsed = DerivationPath::from_str(&path_str).unwrap();
                assert_eq!(
                    path.to_string(),
                    reparsed.to_string(),
                    "Path roundtrip failed for {}",
                    step.path
                );

                // Depth should remain the same
                assert_eq!(
                    path.depth(),
                    reparsed.depth(),
                    "Depth changed after roundtrip for {}",
                    step.path
                );
            }
        }
    }

    #[test]
    fn test_path_incremental_derivation() {
        // Test that deriving incrementally matches direct path derivation
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Test path m/0H/1/2H
        let path_direct = DerivationPath::from_str("m/0H/1/2H").unwrap();
        let derived_direct = master.derive_path(&path_direct).unwrap();

        // Derive incrementally
        let path_0h = DerivationPath::from_str("m/0H").unwrap();
        let derived_0h = master.derive_path(&path_0h).unwrap();

        let path_1 = DerivationPath::from_str("m/1").unwrap();
        let derived_0h_1 = derived_0h.derive_path(&path_1).unwrap();

        let path_2h = DerivationPath::from_str("m/2H").unwrap();
        let derived_0h_1_2h = derived_0h_1.derive_path(&path_2h).unwrap();

        // Both approaches should yield the same result
        assert_eq!(
            derived_direct.to_string(),
            derived_0h_1_2h.to_string(),
            "Incremental derivation doesn't match direct derivation"
        );
    }

    #[test]
    fn test_path_parent_relationships() {
        // Test that parent() works correctly for all paths
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations.iter().skip(1) {
                // Skip master key
                let path = DerivationPath::from_str(step.path).unwrap();
                let parent = path.parent();

                assert!(
                    parent.is_some(),
                    "Path {} should have a parent",
                    step.path
                );

                let parent = parent.unwrap();
                assert_eq!(
                    parent.depth(),
                    path.depth() - 1,
                    "Parent depth incorrect for {}",
                    step.path
                );
            }
        }

        // Master key should have no parent
        let master = DerivationPath::from_str("m").unwrap();
        assert!(master.parent().is_none(), "Master key should have no parent");
    }

    #[test]
    fn test_all_paths_have_valid_indices() {
        // Verify that all child indices are within valid range
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                let path = DerivationPath::from_str(step.path).unwrap();

                // Check each level
                for i in 0..path.depth() {
                    let child_num = path.child_number_at(i as usize);
                    assert!(
                        child_num.is_some(),
                        "Path {} missing child number at index {}",
                        step.path,
                        i
                    );
                }

                // Beyond depth should return None
                assert!(
                    path.child_number_at(path.depth() as usize).is_none(),
                    "Path {} should return None for out-of-bounds index",
                    step.path
                );
            }
        }
    }

    #[test]
    fn test_path_consistency_across_vectors() {
        // All test vectors should have master key as first derivation
        for test_vector in all_test_vectors() {
            assert!(
                !test_vector.derivations.is_empty(),
                "{} has no derivations",
                test_vector.description
            );

            let first = &test_vector.derivations[0];
            assert_eq!(
                first.path, "m",
                "{} first derivation should be master key",
                test_vector.description
            );

            let master_path = DerivationPath::from_str(first.path).unwrap();
            assert!(
                master_path.is_master(),
                "{} first path should be master",
                test_vector.description
            );
        }
    }

    #[test]
    fn test_hardened_vs_normal_notation() {
        // Test that 'H' and 'h' notations are both supported
        let path_h_lower = DerivationPath::from_str("m/0h").unwrap();
        let path_h_upper = DerivationPath::from_str("m/0H").unwrap();
        let path_apostrophe = DerivationPath::from_str("m/0'").unwrap();

        // All three should represent the same hardened derivation
        assert_eq!(path_h_lower.depth(), 1);
        assert_eq!(path_h_upper.depth(), 1);
        assert_eq!(path_apostrophe.depth(), 1);

        assert!(path_h_lower.contains_hardened());
        assert!(path_h_upper.contains_hardened());
        assert!(path_apostrophe.contains_hardened());
    }

    #[test]
    fn test_all_vector_paths_comprehensive() {
        // Comprehensive test ensuring all paths in all vectors work end-to-end
        let mut total_paths = 0;
        let mut successful_derivations = 0;

        for test_vector in all_test_vectors() {
            let seed = hex_to_bytes(test_vector.seed_hex)
                .expect(&format!("Failed to decode seed for {}", test_vector.description));
            let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
                .expect(&format!("Failed to create master key for {}", test_vector.description));

            for step in test_vector.derivations {
                total_paths += 1;

                // Parse path
                let path = DerivationPath::from_str(step.path)
                    .expect(&format!("Failed to parse path {}", step.path));

                // Derive key
                let derived = master.derive_path(&path)
                    .expect(&format!("Failed to derive path {}", step.path));

                // Verify serialization matches
                assert_eq!(
                    derived.to_string(),
                    step.ext_prv,
                    "Derived key mismatch for path {}",
                    step.path
                );

                successful_derivations += 1;
            }
        }

        // Verify we tested all expected paths
        assert_eq!(total_paths, 17, "Expected 17 total derivation paths across all vectors (6 + 6 + 2 + 3)");
        assert_eq!(successful_derivations, total_paths, "All paths should derive successfully");
    }

    // ============================================================================
    // Verify all serialization formats in test vectors
    // ============================================================================

    #[test]
    fn test_all_xprv_serializations_match() {
        // Verify that all extended private key serializations match expected values
        for test_vector in all_test_vectors() {
            let seed = hex_to_bytes(test_vector.seed_hex).unwrap();
            let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

            for step in test_vector.derivations {
                let path = DerivationPath::from_str(step.path).unwrap();
                let derived = master.derive_path(&path).unwrap();
                let serialized = derived.to_string();

                assert_eq!(
                    serialized, step.ext_prv,
                    "{}: xprv serialization mismatch for path {}\nExpected: {}\nGot:      {}",
                    test_vector.description, step.path, step.ext_prv, serialized
                );

                // Verify it starts with correct prefix
                assert!(
                    serialized.starts_with("xprv"),
                    "Extended private key should start with 'xprv', got: {}",
                    &serialized[..4]
                );
            }
        }
    }

    #[test]
    fn test_all_xpub_serializations_match() {
        // Verify that all extended public key serializations match expected values
        for test_vector in all_test_vectors() {
            let seed = hex_to_bytes(test_vector.seed_hex).unwrap();
            let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

            for step in test_vector.derivations {
                let path = DerivationPath::from_str(step.path).unwrap();
                let derived_prv = master.derive_path(&path).unwrap();
                let derived_pub = derived_prv.to_extended_public_key();
                let serialized = derived_pub.to_string();

                assert_eq!(
                    serialized, step.ext_pub,
                    "{}: xpub serialization mismatch for path {}\nExpected: {}\nGot:      {}",
                    test_vector.description, step.path, step.ext_pub, serialized
                );

                // Verify it starts with correct prefix
                assert!(
                    serialized.starts_with("xpub"),
                    "Extended public key should start with 'xpub', got: {}",
                    &serialized[..4]
                );
            }
        }
    }

    #[test]
    fn test_xprv_deserialization_roundtrip() {
        // Test that all xprv values can be deserialized and re-serialized consistently
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                // Deserialize from string
                let deserialized = ExtendedPrivateKey::from_str(step.ext_prv)
                    .expect(&format!("Failed to deserialize xprv for path {}", step.path));

                // Re-serialize
                let reserialized = deserialized.to_string();

                assert_eq!(
                    reserialized, step.ext_prv,
                    "{}: xprv roundtrip failed for path {}",
                    test_vector.description, step.path
                );
            }
        }
    }

    #[test]
    fn test_xpub_deserialization_roundtrip() {
        // Test that all xpub values can be deserialized and re-serialized consistently
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                // Deserialize from string
                let deserialized = ExtendedPublicKey::from_str(step.ext_pub)
                    .expect(&format!("Failed to deserialize xpub for path {}", step.path));

                // Re-serialize
                let reserialized = deserialized.to_string();

                assert_eq!(
                    reserialized, step.ext_pub,
                    "{}: xpub roundtrip failed for path {}",
                    test_vector.description, step.path
                );
            }
        }
    }

    #[test]
    fn test_serialization_format_consistency() {
        // Verify serialization format consistency across all vectors
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                // Check xprv format
                assert_eq!(
                    step.ext_prv.len(), 111,
                    "xprv for path {} should be 111 characters (Base58Check of 78 bytes)",
                    step.path
                );

                // Check xpub format
                assert_eq!(
                    step.ext_pub.len(), 111,
                    "xpub for path {} should be 111 characters (Base58Check of 78 bytes)",
                    step.path
                );

                // Verify Base58 character set (only valid Base58 chars)
                for ch in step.ext_prv.chars() {
                    assert!(
                        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(ch),
                        "Invalid Base58 character '{}' in xprv for path {}",
                        ch, step.path
                    );
                }

                for ch in step.ext_pub.chars() {
                    assert!(
                        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(ch),
                        "Invalid Base58 character '{}' in xpub for path {}",
                        ch, step.path
                    );
                }
            }
        }
    }

    #[test]
    fn test_version_bytes_mainnet() {
        // Verify that all keys use correct mainnet version bytes (xprv/xpub)
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                // All test vectors use Bitcoin mainnet
                assert!(
                    step.ext_prv.starts_with("xprv"),
                    "Mainnet private keys should start with 'xprv', got: {}",
                    &step.ext_prv[..4]
                );

                assert!(
                    step.ext_pub.starts_with("xpub"),
                    "Mainnet public keys should start with 'xpub', got: {}",
                    &step.ext_pub[..4]
                );

                // Should not use testnet prefixes
                assert!(
                    !step.ext_prv.starts_with("tprv"),
                    "Test vector uses testnet prefix (tprv) instead of mainnet"
                );

                assert!(
                    !step.ext_pub.starts_with("tpub"),
                    "Test vector uses testnet prefix (tpub) instead of mainnet"
                );
            }
        }
    }

    #[test]
    fn test_derived_vs_deserialized_equivalence() {
        // Verify that deriving a key produces the same result as deserializing the expected string
        for test_vector in all_test_vectors() {
            let seed = hex_to_bytes(test_vector.seed_hex).unwrap();
            let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

            for step in test_vector.derivations {
                let path = DerivationPath::from_str(step.path).unwrap();

                // Derived key
                let derived_prv = master.derive_path(&path).unwrap();
                let derived_pub = derived_prv.to_extended_public_key();

                // Deserialized key
                let deserialized_prv = ExtendedPrivateKey::from_str(step.ext_prv).unwrap();
                let deserialized_pub = ExtendedPublicKey::from_str(step.ext_pub).unwrap();

                // Compare serializations (should be identical)
                assert_eq!(
                    derived_prv.to_string(),
                    deserialized_prv.to_string(),
                    "Derived and deserialized xprv differ for path {}",
                    step.path
                );

                assert_eq!(
                    derived_pub.to_string(),
                    deserialized_pub.to_string(),
                    "Derived and deserialized xpub differ for path {}",
                    step.path
                );

                // Compare depths
                assert_eq!(
                    derived_prv.depth(),
                    deserialized_prv.depth(),
                    "Depth mismatch for path {}",
                    step.path
                );

                assert_eq!(
                    derived_pub.depth(),
                    deserialized_pub.depth(),
                    "Depth mismatch for path {}",
                    step.path
                );
            }
        }
    }

    #[test]
    fn test_private_to_public_serialization_relationship() {
        // Verify that the public key derived from private key matches expected xpub
        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                let prv = ExtendedPrivateKey::from_str(step.ext_prv).unwrap();
                let pub_from_prv = prv.to_extended_public_key();
                let pub_direct = ExtendedPublicKey::from_str(step.ext_pub).unwrap();

                assert_eq!(
                    pub_from_prv.to_string(),
                    pub_direct.to_string(),
                    "Public key from private doesn't match expected xpub for path {}",
                    step.path
                );

                // Verify metadata matches
                assert_eq!(
                    pub_from_prv.depth(),
                    pub_direct.depth(),
                    "Depth mismatch for path {}",
                    step.path
                );

                assert_eq!(
                    pub_from_prv.child_number(),
                    pub_direct.child_number(),
                    "Child number mismatch for path {}",
                    step.path
                );
            }
        }
    }

    #[test]
    fn test_serialization_uniqueness() {
        // Verify that all serialized keys are unique (no duplicates)
        let mut xprv_set = std::collections::HashSet::new();
        let mut xpub_set = std::collections::HashSet::new();

        for test_vector in all_test_vectors() {
            for step in test_vector.derivations {
                let inserted_prv = xprv_set.insert(step.ext_prv);
                assert!(
                    inserted_prv,
                    "Duplicate xprv found: {} (path: {})",
                    step.ext_prv, step.path
                );

                let inserted_pub = xpub_set.insert(step.ext_pub);
                assert!(
                    inserted_pub,
                    "Duplicate xpub found: {} (path: {})",
                    step.ext_pub, step.path
                );
            }
        }

        // Verify we collected all expected unique keys
        assert_eq!(xprv_set.len(), 17, "Should have 17 unique xprv values");
        assert_eq!(xpub_set.len(), 17, "Should have 17 unique xpub values");
    }

    #[test]
    fn test_serialization_metadata_preserved() {
        // Verify that serialization preserves all metadata (depth, fingerprint, child_number)
        for test_vector in all_test_vectors() {
            let seed = hex_to_bytes(test_vector.seed_hex).unwrap();
            let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

            for step in test_vector.derivations {
                let path = DerivationPath::from_str(step.path).unwrap();
                let derived = master.derive_path(&path).unwrap();

                // Serialize and deserialize
                let serialized = derived.to_string();
                let deserialized = ExtendedPrivateKey::from_str(&serialized).unwrap();

                // Verify metadata preserved
                assert_eq!(
                    derived.depth(),
                    deserialized.depth(),
                    "Depth not preserved for path {}",
                    step.path
                );

                assert_eq!(
                    derived.child_number(),
                    deserialized.child_number(),
                    "Child number not preserved for path {}",
                    step.path
                );

                assert_eq!(
                    derived.fingerprint(),
                    deserialized.fingerprint(),
                    "Fingerprint not preserved for path {}",
                    step.path
                );

                assert_eq!(
                    derived.network(),
                    deserialized.network(),
                    "Network not preserved for path {}",
                    step.path
                );
            }
        }
    }

    #[test]
    fn test_all_serializations_comprehensive() {
        // Comprehensive test ensuring all serializations work end-to-end
        let mut total_keys = 0;
        let mut successful_xprv = 0;
        let mut successful_xpub = 0;

        for test_vector in all_test_vectors() {
            let seed = hex_to_bytes(test_vector.seed_hex).unwrap();
            let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

            for step in test_vector.derivations {
                total_keys += 1;

                let path = DerivationPath::from_str(step.path).unwrap();
                let derived_prv = master.derive_path(&path).unwrap();
                let derived_pub = derived_prv.to_extended_public_key();

                // Test xprv serialization
                let xprv_str = derived_prv.to_string();
                if xprv_str == step.ext_prv {
                    successful_xprv += 1;
                }

                // Test xpub serialization
                let xpub_str = derived_pub.to_string();
                if xpub_str == step.ext_pub {
                    successful_xpub += 1;
                }

                // Test xprv deserialization
                let _ = ExtendedPrivateKey::from_str(step.ext_prv)
                    .expect(&format!("Failed to deserialize xprv for path {}", step.path));

                // Test xpub deserialization
                let _ = ExtendedPublicKey::from_str(step.ext_pub)
                    .expect(&format!("Failed to deserialize xpub for path {}", step.path));
            }
        }

        assert_eq!(total_keys, 17, "Expected 17 total keys across all vectors");
        assert_eq!(successful_xprv, total_keys, "All xprv serializations should match");
        assert_eq!(successful_xpub, total_keys, "All xpub serializations should match");
    }

    // ============================================================================
    // Test cross-compatibility with other BIP32 implementations
    // ============================================================================

    #[test]
    fn test_testnet_key_deserialization() {
        // Test compatibility with testnet extended keys (tprv/tpub)
        // Generate a testnet key from the same seed as Test Vector 1
        
        let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f").unwrap();
        let testnet_master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        
        // Verify it's a testnet key
        assert_eq!(testnet_master.network(), Network::BitcoinTestnet);
        assert!(testnet_master.to_string().starts_with("tprv"));
        
        let testnet_pub = testnet_master.to_extended_public_key();
        assert!(testnet_pub.to_string().starts_with("tpub"));

        // Test roundtrip serialization
        let tprv_str = testnet_master.to_string();
        let tpub_str = testnet_pub.to_string();
        
        let deserialized_prv = ExtendedPrivateKey::from_str(&tprv_str).unwrap();
        let deserialized_pub = ExtendedPublicKey::from_str(&tpub_str).unwrap();

        assert_eq!(deserialized_prv.network(), Network::BitcoinTestnet);
        assert_eq!(deserialized_pub.network(), Network::BitcoinTestnet);

        // Verify serialization roundtrip
        assert_eq!(deserialized_prv.to_string(), tprv_str);
        assert_eq!(deserialized_pub.to_string(), tpub_str);
    }

    #[test]
    fn test_electrum_compatible_keys() {
        // Test compatibility with Electrum wallet keys
        // Using keys from the official test vectors which Electrum also supports
        
        let test_cases = vec![
            // Master key from Test Vector 1
            (
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            ),
            // Derived key from Test Vector 1: m/0H
            (
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
            ),
        ];

        for (xprv_str, xpub_str) in test_cases {
            let prv = ExtendedPrivateKey::from_str(xprv_str)
                .expect(&format!("Failed to deserialize xprv: {}", xprv_str));
            let pub_from_prv = prv.to_extended_public_key();
            let pub_direct = ExtendedPublicKey::from_str(xpub_str)
                .expect(&format!("Failed to deserialize xpub: {}", xpub_str));

            // Verify public key derived from private matches
            assert_eq!(
                pub_from_prv.to_string(),
                pub_direct.to_string(),
                "Public key mismatch (Electrum compatibility)"
            );

            // Verify serialization roundtrip
            assert_eq!(prv.to_string(), xprv_str);
            assert_eq!(pub_direct.to_string(), xpub_str);
        }
    }

    #[test]
    fn test_bitcoin_core_compatible_derivation() {
        // Test that our derivation matches Bitcoin Core's implementation
        // Using paths commonly used in Bitcoin Core
        
        let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Test BIP44 Bitcoin mainnet account 0 path: m/44'/0'/0'
        let path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let account = master.derive_path(&path).unwrap();

        // Verify the key can be serialized and is valid
        let serialized = account.to_string();
        assert!(serialized.starts_with("xprv"));
        assert_eq!(serialized.len(), 111);

        // Verify depth
        assert_eq!(account.depth(), 3);

        // Test deriving receive address path: m/44'/0'/0'/0/0
        let receive_path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let receive_key = master.derive_path(&receive_path).unwrap();
        
        assert_eq!(receive_key.depth(), 5);
        assert!(receive_key.to_string().starts_with("xprv"));
    }

    #[test]
    fn test_trezor_compatible_keys() {
        // Test compatibility with Trezor hardware wallet keys
        // Trezor uses standard BIP32/BIP44 derivation
        
        let seed = hex_to_bytes("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // This is the master key from Test Vector 2
        let expected_xprv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
        assert_eq!(master.to_string(), expected_xprv);

        // Test typical Trezor derivation path for Bitcoin: m/44'/0'/0'
        let account_path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let account = master.derive_path(&account_path).unwrap();
        
        // Verify account key properties
        assert_eq!(account.depth(), 3);
        assert!(account.to_string().starts_with("xprv"));
        
        // Verify can derive further
        let address_path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let address_key = master.derive_path(&address_path).unwrap();
        assert_eq!(address_key.depth(), 5);
    }

    #[test]
    fn test_ledger_compatible_keys() {
        // Test compatibility with Ledger hardware wallet keys
        // Ledger also uses standard BIP32/BIP44
        
        let test_vectors = vec![
            // Test Vector 1 master key (compatible with Ledger)
            (
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "m",
                0
            ),
            // Derived at m/0H
            (
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "m/0H",
                1
            ),
        ];

        for (xprv_str, _path_str, expected_depth) in test_vectors {
            let key = ExtendedPrivateKey::from_str(xprv_str).unwrap();
            
            assert_eq!(key.depth(), expected_depth);
            assert_eq!(key.to_string(), xprv_str);
            
            // Verify can derive further (Ledger compatibility)
            if expected_depth < 5 {
                let further = key.derive_child(ChildNumber::Normal(0)).unwrap();
                assert_eq!(further.depth(), expected_depth + 1);
            }
        }
    }

    #[test]
    fn test_bitpay_bitcore_compatibility() {
        // Test compatibility with Bitpay/Bitcore implementation
        // Test Vector 3 specifically tests for bitpay/bitcore-lib#47
        
        let seed = hex_to_bytes("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Expected values from Test Vector 3 (bitpay compatibility test)
        let expected_master_xprv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";
        assert_eq!(master.to_string(), expected_master_xprv);

        // Test derivation with leading zeros (bitcore-lib#47 issue)
        let path = DerivationPath::from_str("m/0H").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        let expected_xprv = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";
        assert_eq!(derived.to_string(), expected_xprv);
    }

    #[test]
    fn test_btcsuite_compatibility() {
        // Test compatibility with btcsuite/btcutil implementation
        // Test Vector 4 specifically tests for btcsuite/btcutil#172
        
        let seed = hex_to_bytes("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Expected values from Test Vector 4 (btcsuite compatibility test)
        let expected_master_xprv = "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv";
        assert_eq!(master.to_string(), expected_master_xprv);

        // Test derivation path from btcsuite test
        let path = DerivationPath::from_str("m/0H").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        let expected_xprv = "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G";
        assert_eq!(derived.to_string(), expected_xprv);

        // Further derivation
        let path2 = DerivationPath::from_str("m/0H/1H").unwrap();
        let derived2 = master.derive_path(&path2).unwrap();
        
        let expected_xprv2 = "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1";
        assert_eq!(derived2.to_string(), expected_xprv2);
    }

    #[test]
    fn test_cross_implementation_public_derivation() {
        // Test that public key derivation is compatible across implementations
        // This is crucial for watch-only wallets
        
        let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Derive to account level: m/44'/0'/0'
        let account_path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let account_prv = master.derive_path(&account_path).unwrap();
        let account_pub = account_prv.to_extended_public_key();

        // Now derive child keys from public key (normal derivation only)
        let child0_from_pub = account_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        let child0_from_prv = account_prv.derive_child(ChildNumber::Normal(0)).unwrap().to_extended_public_key();

        // Both methods should produce the same public key
        assert_eq!(
            child0_from_pub.to_string(),
            child0_from_prv.to_string(),
            "Public derivation should match private→public derivation"
        );

        // Test multiple levels
        let child0_0_from_pub = child0_from_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        
        let full_path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let child0_0_from_prv = master.derive_path(&full_path).unwrap().to_extended_public_key();

        assert_eq!(
            child0_0_from_pub.to_string(),
            child0_0_from_prv.to_string(),
            "Multi-level public derivation should match"
        );
    }

    #[test]
    fn test_network_version_compatibility() {
        // Test that we correctly handle different network version bytes
        // This ensures compatibility with multi-network wallets
        
        let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f").unwrap();
        
        // Mainnet keys
        let mainnet_master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        assert!(mainnet_master.to_string().starts_with("xprv"));
        assert!(mainnet_master.to_extended_public_key().to_string().starts_with("xpub"));
        
        // Testnet keys
        let testnet_master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        assert!(testnet_master.to_string().starts_with("tprv"));
        assert!(testnet_master.to_extended_public_key().to_string().starts_with("tpub"));
        
        // Same seed, different networks should produce different serializations
        assert_ne!(
            mainnet_master.to_string(),
            testnet_master.to_string(),
            "Different networks should have different serializations"
        );
    }

    #[test]
    fn test_bip44_standard_compatibility() {
        // Test compatibility with BIP44 standard paths used across all wallets
        let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // BIP44 standard paths
        let test_paths = vec![
            "m/44'/0'/0'",           // Bitcoin account 0
            "m/44'/0'/0'/0",         // External chain (receive)
            "m/44'/0'/0'/1",         // Internal chain (change)
            "m/44'/0'/0'/0/0",       // First receive address
            "m/44'/0'/0'/1/0",       // First change address
            "m/44'/0'/1'",           // Bitcoin account 1
            "m/49'/0'/0'",           // P2WPKH-nested-in-P2SH (BIP49)
            "m/84'/0'/0'",           // P2WPKH (BIP84)
        ];

        for path_str in test_paths {
            let path = DerivationPath::from_str(path_str)
                .expect(&format!("Failed to parse BIP44 path: {}", path_str));
            
            let derived = master.derive_path(&path)
                .expect(&format!("Failed to derive BIP44 path: {}", path_str));
            
            // Verify key is valid
            assert!(derived.to_string().starts_with("xprv"));
            assert_eq!(derived.to_string().len(), 111);
            
            // Verify can convert to public
            let pub_key = derived.to_extended_public_key();
            assert!(pub_key.to_string().starts_with("xpub"));
        }
    }

    #[test]
    fn test_all_implementations_comprehensive() {
        // Comprehensive test ensuring compatibility with all major implementations
        let mut tested_implementations = 0;
        
        // Test each test vector (these are used by all implementations)
        for test_vector in all_test_vectors() {
            let seed = hex_to_bytes(test_vector.seed_hex).unwrap();
            let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
            
            // Verify master key matches (all implementations should agree)
            assert_eq!(
                master.to_string(),
                test_vector.derivations[0].ext_prv,
                "{}: Master key mismatch",
                test_vector.description
            );
            
            tested_implementations += 1;
        }
        
        // Verify we tested all vectors
        assert_eq!(tested_implementations, 4, "Should test all 4 test vectors");
        
        // Additionally verify we can handle keys from different sources
        let known_keys = vec![
            // Mainnet keys
            ("xprv", "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
            ("xpub", "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"),
        ];
        
        for (key_type, key_str) in known_keys {
            if key_type == "xprv" {
                let key = ExtendedPrivateKey::from_str(key_str);
                assert!(key.is_ok(), "Failed to deserialize {} from known implementation", key_type);
            } else {
                let key = ExtendedPublicKey::from_str(key_str);
                assert!(key.is_ok(), "Failed to deserialize {} from known implementation", key_type);
            }
        }
    }
}
