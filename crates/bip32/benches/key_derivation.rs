//! Benchmarks for BIP32 key derivation operations.
//!
//! Run benchmarks with:
//! ```bash
//! cargo bench --bench key_derivation
//! ```
//!
//! View HTML reports in:
//! ```
//! target/criterion/report/index.html
//! ```

use bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey, Network};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::str::FromStr;

/// Setup function to create a master key for benchmarking
fn setup_master_key() -> ExtendedPrivateKey {
    let seed = b"benchmark-seed-for-performance-testing-only-not-for-production-use!!";
    ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)
        .expect("Failed to create master key")
}

/// Benchmark master key generation from seed
fn bench_master_key_from_seed(c: &mut Criterion) {
    let seed = b"benchmark-seed-for-performance-testing-only-not-for-production-use!!";

    c.bench_function("master_key_from_seed", |b| {
        b.iter(|| {
            let _ =
                ExtendedPrivateKey::from_seed(black_box(seed), black_box(Network::BitcoinMainnet));
        })
    });
}

/// Benchmark single child derivation (normal)
fn bench_single_child_normal(c: &mut Criterion) {
    let master = setup_master_key();

    c.bench_function("derive_single_child_normal", |b| {
        b.iter(|| {
            let _ = master.derive_child(black_box(ChildNumber::Normal(0)));
        })
    });
}

/// Benchmark single child derivation (hardened)
fn bench_single_child_hardened(c: &mut Criterion) {
    let master = setup_master_key();

    c.bench_function("derive_single_child_hardened", |b| {
        b.iter(|| {
            let _ = master.derive_child(black_box(ChildNumber::Hardened(0)));
        })
    });
}

/// Benchmark path derivation at various depths
fn bench_path_derivation_by_depth(c: &mut Criterion) {
    let master = setup_master_key();

    let paths = vec![
        ("depth_1", "m/0"),
        ("depth_2", "m/0/0"),
        ("depth_3", "m/44'/0'/0'"),
        ("depth_4", "m/44'/0'/0'/0"),
        ("depth_5", "m/44'/0'/0'/0/0"),
    ];

    let mut group = c.benchmark_group("path_derivation_by_depth");

    for (name, path_str) in paths {
        let path = DerivationPath::from_str(path_str).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(name), &path, |b, path| {
            b.iter(|| {
                let _ = master.derive_path(black_box(path));
            })
        });
    }

    group.finish();
}

/// Benchmark BIP-44 standard paths
fn bench_bip44_paths(c: &mut Criterion) {
    let master = setup_master_key();

    let paths = vec![
        ("bip44_account", "m/44'/0'/0'"),
        ("bip44_receive", "m/44'/0'/0'/0/0"),
        ("bip44_change", "m/44'/0'/0'/1/0"),
    ];

    let mut group = c.benchmark_group("bip44_standard_paths");

    for (name, path_str) in paths {
        let path = DerivationPath::from_str(path_str).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(name), &path, |b, path| {
            b.iter(|| {
                let _ = master.derive_path(black_box(path));
            })
        });
    }

    group.finish();
}

/// Benchmark address generation (multiple derivations)
fn bench_address_generation(c: &mut Criterion) {
    let master = setup_master_key();
    let account_path = DerivationPath::from_str("m/44'/0'/0'/0").unwrap();
    let account = master.derive_path(&account_path).unwrap();

    c.bench_function("generate_10_addresses", |b| {
        b.iter(|| {
            for i in 0..10 {
                let _ = account.derive_child(black_box(ChildNumber::Normal(i)));
            }
        })
    });

    c.bench_function("generate_100_addresses", |b| {
        b.iter(|| {
            for i in 0..100 {
                let _ = account.derive_child(black_box(ChildNumber::Normal(i)));
            }
        })
    });
}

/// Benchmark public key derivation from extended public key
fn bench_public_key_derivation(c: &mut Criterion) {
    let master = setup_master_key();
    let account_path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
    let account = master.derive_path(&account_path).unwrap();
    let account_pub = account.to_extended_public_key();

    c.bench_function("public_key_derivation_normal", |b| {
        b.iter(|| {
            let _ = account_pub.derive_child(black_box(ChildNumber::Normal(0)));
        })
    });
}

/// Benchmark private to public key conversion
fn bench_private_to_public(c: &mut Criterion) {
    let master = setup_master_key();

    c.bench_function("private_to_public_conversion", |b| {
        b.iter(|| {
            let _ = black_box(&master).to_extended_public_key();
        })
    });
}

/// Benchmark fingerprint calculation
fn bench_fingerprint(c: &mut Criterion) {
    let master = setup_master_key();

    c.bench_function("fingerprint_calculation", |b| {
        b.iter(|| {
            let _ = black_box(&master).fingerprint();
        })
    });
}

/// Benchmark incremental vs direct path derivation
fn bench_incremental_vs_direct(c: &mut Criterion) {
    let master = setup_master_key();
    let target_path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();

    let mut group = c.benchmark_group("incremental_vs_direct");

    // Direct derivation
    group.bench_function("direct_derivation", |b| {
        b.iter(|| {
            let _ = master.derive_path(black_box(&target_path));
        })
    });

    // Incremental derivation
    group.bench_function("incremental_derivation", |b| {
        b.iter(|| {
            let mut current = master.clone();
            let components = [
                ChildNumber::Hardened(44),
                ChildNumber::Hardened(0),
                ChildNumber::Hardened(0),
                ChildNumber::Normal(0),
                ChildNumber::Normal(0),
            ];
            for &component in &components {
                current = current.derive_child(black_box(component)).unwrap();
            }
        })
    });

    group.finish();
}

/// Benchmark path parsing
fn bench_path_parsing(c: &mut Criterion) {
    let paths = vec![
        ("simple", "m/0"),
        ("bip44", "m/44'/0'/0'/0/0"),
        ("deep", "m/1/2/3/4/5/6/7/8/9/10"),
    ];

    let mut group = c.benchmark_group("path_parsing");

    for (name, path_str) in paths {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &path_str,
            |b, path_str| {
                b.iter(|| {
                    let _ = DerivationPath::from_str(black_box(path_str));
                })
            },
        );
    }

    group.finish();
}

/// Benchmark hardened vs normal derivation comparison
fn bench_hardened_vs_normal(c: &mut Criterion) {
    let master = setup_master_key();

    let mut group = c.benchmark_group("hardened_vs_normal");

    group.bench_function("normal_derivation", |b| {
        b.iter(|| {
            let _ = master.derive_child(black_box(ChildNumber::Normal(0)));
        })
    });

    group.bench_function("hardened_derivation", |b| {
        b.iter(|| {
            let _ = master.derive_child(black_box(ChildNumber::Hardened(0)));
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_master_key_from_seed,
    bench_single_child_normal,
    bench_single_child_hardened,
    bench_path_derivation_by_depth,
    bench_bip44_paths,
    bench_address_generation,
    bench_public_key_derivation,
    bench_private_to_public,
    bench_fingerprint,
    bench_incremental_vs_direct,
    bench_path_parsing,
    bench_hardened_vs_normal,
);

criterion_main!(benches);
