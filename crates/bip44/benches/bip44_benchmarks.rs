//! Benchmarks for BIP-44 operations.
//!
//! Run with: cargo bench -p khodpay-bip44

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use khodpay_bip32::{ChildNumber, ExtendedPrivateKey, Network};
use khodpay_bip39::{Language, Mnemonic};
use khodpay_bip44::{Account, Bip44Path, Chain, CoinType, Purpose, Wallet};

/// Benchmark path construction
fn bench_path_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_construction");

    group.bench_function("new", |b| {
        b.iter(|| {
            Bip44Path::new(
                black_box(Purpose::BIP44),
                black_box(CoinType::Bitcoin),
                black_box(0),
                black_box(Chain::External),
                black_box(0),
            )
        })
    });

    group.bench_function("builder", |b| {
        b.iter(|| {
            Bip44Path::builder()
                .purpose(black_box(Purpose::BIP44))
                .coin_type(black_box(CoinType::Bitcoin))
                .account(black_box(0))
                .chain(black_box(Chain::External))
                .address_index(black_box(0))
                .build()
        })
    });

    group.bench_function("parse_string", |b| {
        b.iter(|| black_box("m/44'/0'/0'/0/0").parse::<Bip44Path>())
    });

    group.bench_function("to_string", |b| {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        b.iter(|| black_box(&path).to_string())
    });

    group.finish();
}

/// Benchmark path transformations
fn bench_path_transformations(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_transformations");

    let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

    group.bench_function("next_address", |b| {
        b.iter(|| black_box(&path).next_address())
    });

    group.bench_function("next_account", |b| {
        b.iter(|| black_box(&path).next_account())
    });

    group.bench_function("to_external", |b| b.iter(|| black_box(&path).to_external()));

    group.bench_function("to_internal", |b| b.iter(|| black_box(&path).to_internal()));

    group.bench_function("with_address_index", |b| {
        b.iter(|| black_box(&path).with_address_index(black_box(100)))
    });

    group.finish();
}

/// Benchmark wallet creation
fn bench_wallet_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("wallet_creation");

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    group.bench_function("from_mnemonic", |b| {
        b.iter(|| {
            Wallet::from_mnemonic(
                black_box(mnemonic),
                black_box(""),
                black_box(Language::English),
                black_box(Network::BitcoinMainnet),
            )
        })
    });

    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();

    group.bench_function("from_seed", |b| {
        b.iter(|| Wallet::from_seed(black_box(&seed), black_box(Network::BitcoinMainnet)))
    });

    group.finish();
}

/// Benchmark account derivation
fn bench_account_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_derivation");

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    group.bench_function("get_account_first_time", |b| {
        b.iter_batched(
            || {
                let mut w =
                    Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
                w.clear_cache();
                w
            },
            |mut w| {
                let _ = w.get_account(
                    black_box(Purpose::BIP44),
                    black_box(CoinType::Bitcoin),
                    black_box(0),
                );
                w.cached_account_count()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("get_account_cached", |b| {
        b.iter_batched(
            || {
                let mut w =
                    Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
                let _ = w.get_account(Purpose::BIP44, CoinType::Bitcoin, 0);
                w
            },
            |mut w| {
                let _ = w.get_account(
                    black_box(Purpose::BIP44),
                    black_box(CoinType::Bitcoin),
                    black_box(0),
                );
                w.cached_account_count()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark address derivation
fn bench_address_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_derivation");

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();

    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

    group.bench_function("derive_external_single", |b| {
        b.iter(|| account.derive_external(black_box(0)))
    });

    group.bench_function("derive_internal_single", |b| {
        b.iter(|| account.derive_internal(black_box(0)))
    });

    // Benchmark batch derivation with different sizes
    for count in [10, 20, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("derive_batch", count),
            count,
            |b, &count| {
                b.iter(|| {
                    account.derive_address_range(
                        black_box(Chain::External),
                        black_box(0),
                        black_box(count),
                    )
                })
            },
        );
    }

    group.finish();
}

/// Benchmark different coin types
fn bench_coin_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("coin_types");

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let coins = vec![
        ("Bitcoin", CoinType::Bitcoin),
        ("Ethereum", CoinType::Ethereum),
        ("Litecoin", CoinType::Litecoin),
        ("Dogecoin", CoinType::Dogecoin),
    ];

    for (name, coin_type) in coins {
        group.bench_with_input(
            BenchmarkId::new("derive_account", name),
            &coin_type,
            |b, &coin_type| {
                b.iter_batched(
                    || {
                        let mut w =
                            Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet)
                                .unwrap();
                        w.clear_cache();
                        w
                    },
                    |mut w| {
                        let _ = w.get_account(
                            black_box(Purpose::BIP44),
                            black_box(coin_type),
                            black_box(0),
                        );
                        w.cached_account_count()
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

/// Benchmark different BIP purposes
fn bench_purposes(c: &mut Criterion) {
    let mut group = c.benchmark_group("purposes");

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let purposes = vec![
        ("BIP44", Purpose::BIP44),
        ("BIP49", Purpose::BIP49),
        ("BIP84", Purpose::BIP84),
        ("BIP86", Purpose::BIP86),
    ];

    for (name, purpose) in purposes {
        group.bench_with_input(
            BenchmarkId::new("derive_account", name),
            &purpose,
            |b, &purpose| {
                b.iter_batched(
                    || {
                        let mut w =
                            Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet)
                                .unwrap();
                        w.clear_cache();
                        w
                    },
                    |mut w| {
                        let _ = w.get_account(
                            black_box(purpose),
                            black_box(CoinType::Bitcoin),
                            black_box(0),
                        );
                        w.cached_account_count()
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

/// Benchmark account operations at different indices
fn bench_account_indices(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_indices");

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();

    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

    for index in [0, 10, 100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::new("derive_address", index),
            index,
            |b, &index| b.iter(|| account.derive_external(black_box(index))),
        );
    }

    group.finish();
}

/// Benchmark cache operations
fn bench_cache_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_operations");

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Populate cache with 10 accounts
    for i in 0..10 {
        let _ = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, i);
    }

    group.bench_function("cached_account_count", |b| {
        b.iter(|| black_box(&wallet).cached_account_count())
    });

    group.bench_function("clear_cache", |b| {
        b.iter_batched(
            || {
                let mut w =
                    Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
                for i in 0..10 {
                    let _ = w.get_account(Purpose::BIP44, CoinType::Bitcoin, i);
                }
                w
            },
            |mut w| w.clear_cache(),
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_path_construction,
    bench_path_transformations,
    bench_wallet_creation,
    bench_account_derivation,
    bench_address_derivation,
    bench_coin_types,
    bench_purposes,
    bench_account_indices,
    bench_cache_operations,
);

criterion_main!(benches);
