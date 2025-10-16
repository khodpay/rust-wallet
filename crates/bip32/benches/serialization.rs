//! Benchmarks for BIP32 serialization and deserialization operations.
//!
//! Run benchmarks with:
//! ```bash
//! cargo bench --bench serialization
//! ```
//!
//! View HTML reports in:
//! ```
//! target/criterion/report/index.html
//! ```

use khodpay_bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey, ExtendedPublicKey, Network};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::str::FromStr;

/// Setup function to create keys at various depths for benchmarking
fn setup_keys_at_depths() -> Vec<(String, ExtendedPrivateKey)> {
    let seed = b"benchmark-seed-for-serialization-testing-64bytes-max!!!!!!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)
        .expect("Failed to create master key");

    let paths = vec![
        ("master", "m"),
        ("depth_1", "m/0"),
        ("depth_3", "m/44'/0'/0'"),
        ("depth_5", "m/44'/0'/0'/0/0"),
    ];

    paths
        .into_iter()
        .map(|(name, path_str)| {
            let path = DerivationPath::from_str(path_str).unwrap();
            let key = master.derive_path(&path).unwrap();
            (name.to_string(), key)
        })
        .collect()
}

/// Benchmark extended private key serialization (to string)
fn bench_xprv_serialization(c: &mut Criterion) {
    let keys = setup_keys_at_depths();

    let mut group = c.benchmark_group("xprv_serialization");

    for (name, key) in keys.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(name), key, |b, key| {
            b.iter(|| {
                let _ = black_box(key).to_string();
            })
        });
    }

    group.finish();
}

/// Benchmark extended public key serialization (to string)
fn bench_xpub_serialization(c: &mut Criterion) {
    let keys = setup_keys_at_depths();

    let mut group = c.benchmark_group("xpub_serialization");

    for (name, key) in keys.iter() {
        let pub_key = key.to_extended_public_key();
        group.bench_with_input(BenchmarkId::from_parameter(name), &pub_key, |b, pub_key| {
            b.iter(|| {
                let _ = black_box(pub_key).to_string();
            })
        });
    }

    group.finish();
}

/// Benchmark extended private key deserialization (from string)
fn bench_xprv_deserialization(c: &mut Criterion) {
    let keys = setup_keys_at_depths();

    let serialized_keys: Vec<(String, String)> = keys
        .iter()
        .map(|(name, key)| (name.clone(), key.to_string()))
        .collect();

    let mut group = c.benchmark_group("xprv_deserialization");

    for (name, serialized) in serialized_keys.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            serialized,
            |b, serialized| {
                b.iter(|| {
                    let _ = ExtendedPrivateKey::from_str(black_box(serialized));
                })
            },
        );
    }

    group.finish();
}

/// Benchmark extended public key deserialization (from string)
fn bench_xpub_deserialization(c: &mut Criterion) {
    let keys = setup_keys_at_depths();

    let serialized_keys: Vec<(String, String)> = keys
        .iter()
        .map(|(name, key)| (name.clone(), key.to_extended_public_key().to_string()))
        .collect();

    let mut group = c.benchmark_group("xpub_deserialization");

    for (name, serialized) in serialized_keys.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            serialized,
            |b, serialized| {
                b.iter(|| {
                    let _ = ExtendedPublicKey::from_str(black_box(serialized));
                })
            },
        );
    }

    group.finish();
}

/// Benchmark serialization roundtrip (serialize + deserialize)
fn bench_xprv_roundtrip(c: &mut Criterion) {
    let seed = b"benchmark-seed-for-serialization-testing-64bytes-max!!!!!!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet).unwrap();

    c.bench_function("xprv_roundtrip_master", |b| {
        b.iter(|| {
            let serialized = black_box(&master).to_string();
            let _ = ExtendedPrivateKey::from_str(&serialized);
        })
    });

    let bip44 = master
        .derive_path(&DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap())
        .unwrap();

    c.bench_function("xprv_roundtrip_bip44_address", |b| {
        b.iter(|| {
            let serialized = black_box(&bip44).to_string();
            let _ = ExtendedPrivateKey::from_str(&serialized);
        })
    });
}

/// Benchmark xpub roundtrip
fn bench_xpub_roundtrip(c: &mut Criterion) {
    let seed = b"benchmark-seed-for-serialization-testing-64bytes-max!!!!!!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet).unwrap();
    let master_pub = master.to_extended_public_key();

    c.bench_function("xpub_roundtrip_master", |b| {
        b.iter(|| {
            let serialized = black_box(&master_pub).to_string();
            let _ = ExtendedPublicKey::from_str(&serialized);
        })
    });

    let bip44 = master
        .derive_path(&DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap())
        .unwrap();
    let bip44_pub = bip44.to_extended_public_key();

    c.bench_function("xpub_roundtrip_bip44_address", |b| {
        b.iter(|| {
            let serialized = black_box(&bip44_pub).to_string();
            let _ = ExtendedPublicKey::from_str(&serialized);
        })
    });
}

/// Benchmark Base58Check encoding/decoding performance
fn bench_base58_operations(c: &mut Criterion) {
    let seed = b"benchmark-seed-for-serialization-testing-64bytes-max!!!!!!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet).unwrap();
    let xprv_string = master.to_string();

    let mut group = c.benchmark_group("base58_operations");

    group.bench_function("encode_xprv", |b| {
        b.iter(|| {
            let _ = black_box(&master).to_string();
        })
    });

    group.bench_function("decode_xprv", |b| {
        b.iter(|| {
            let _ = ExtendedPrivateKey::from_str(black_box(&xprv_string));
        })
    });

    group.finish();
}

/// Benchmark network-specific serialization
fn bench_network_serialization(c: &mut Criterion) {
    let seed = b"benchmark-seed-for-serialization-testing-64bytes-max!!!!!!!";

    let mut group = c.benchmark_group("network_serialization");

    // Mainnet
    let mainnet_key = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet).unwrap();
    group.bench_function("mainnet_xprv", |b| {
        b.iter(|| {
            let _ = black_box(&mainnet_key).to_string();
        })
    });

    // Testnet
    let testnet_key = ExtendedPrivateKey::from_seed(seed, Network::BitcoinTestnet).unwrap();
    group.bench_function("testnet_tprv", |b| {
        b.iter(|| {
            let _ = black_box(&testnet_key).to_string();
        })
    });

    group.finish();
}

/// Benchmark bulk serialization (e.g., for batch operations)
fn bench_bulk_serialization(c: &mut Criterion) {
    let seed = b"benchmark-seed-for-serialization-testing-64bytes-max!!!!!!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet).unwrap();
    let account_path = DerivationPath::from_str("m/44'/0'/0'/0").unwrap();
    let account = master.derive_path(&account_path).unwrap();

    // Generate 100 addresses
    let addresses: Vec<ExtendedPrivateKey> = (0..100)
        .map(|i| account.derive_child(ChildNumber::Normal(i)).unwrap())
        .collect();

    c.bench_function("serialize_100_addresses", |b| {
        b.iter(|| {
            for addr in black_box(&addresses) {
                let _ = addr.to_string();
            }
        })
    });
}

/// Benchmark bulk deserialization
fn bench_bulk_deserialization(c: &mut Criterion) {
    let seed = b"benchmark-seed-for-serialization-testing-64bytes-max!!!!!!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet).unwrap();
    let account_path = DerivationPath::from_str("m/44'/0'/0'/0").unwrap();
    let account = master.derive_path(&account_path).unwrap();

    // Generate and serialize 100 addresses
    let serialized_addresses: Vec<String> = (0..100)
        .map(|i| {
            account
                .derive_child(ChildNumber::Normal(i))
                .unwrap()
                .to_string()
        })
        .collect();

    c.bench_function("deserialize_100_addresses", |b| {
        b.iter(|| {
            for serialized in black_box(&serialized_addresses) {
                let _ = ExtendedPrivateKey::from_str(serialized);
            }
        })
    });
}

/// Benchmark Display trait implementation
fn bench_display_trait(c: &mut Criterion) {
    let seed = b"benchmark-seed-for-serialization-testing-64bytes-max!!!!!!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet).unwrap();

    c.bench_function("display_trait_xprv", |b| {
        b.iter(|| {
            let _ = format!("{}", black_box(&master));
        })
    });

    let master_pub = master.to_extended_public_key();
    c.bench_function("display_trait_xpub", |b| {
        b.iter(|| {
            let _ = format!("{}", black_box(&master_pub));
        })
    });
}

/// Benchmark FromStr trait implementation
fn bench_fromstr_trait(c: &mut Criterion) {
    let seed = b"benchmark-seed-for-serialization-testing-64bytes-max!!!!!!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet).unwrap();
    let xprv_string = master.to_string();
    let xpub_string = master.to_extended_public_key().to_string();

    c.bench_function("fromstr_trait_xprv", |b| {
        b.iter(|| {
            let _: ExtendedPrivateKey = black_box(&xprv_string).parse().unwrap();
        })
    });

    c.bench_function("fromstr_trait_xpub", |b| {
        b.iter(|| {
            let _: ExtendedPublicKey = black_box(&xpub_string).parse().unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_xprv_serialization,
    bench_xpub_serialization,
    bench_xprv_deserialization,
    bench_xpub_deserialization,
    bench_xprv_roundtrip,
    bench_xpub_roundtrip,
    bench_base58_operations,
    bench_network_serialization,
    bench_bulk_serialization,
    bench_bulk_deserialization,
    bench_display_trait,
    bench_fromstr_trait,
);

criterion_main!(benches);
