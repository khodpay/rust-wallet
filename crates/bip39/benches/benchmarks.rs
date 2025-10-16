//! Performance benchmarks for the BIP39 crate
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use khodpay_bip39::{
    generate_mnemonic, phrase_to_seed, validate_phrase, Language, Mnemonic, WordCount,
};

fn bench_mnemonic_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_generation");

    for &word_count in WordCount::all_variants() {
        group.bench_with_input(
            BenchmarkId::new("generate", word_count.word_count()),
            &word_count,
            |b, &wc| {
                b.iter(|| Mnemonic::generate(black_box(wc), black_box(Language::English)).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_mnemonic_from_entropy(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_from_entropy");

    let test_cases = vec![
        ([0u8; 16].to_vec(), WordCount::Twelve),
        ([0u8; 20].to_vec(), WordCount::Fifteen),
        ([0u8; 24].to_vec(), WordCount::Eighteen),
        ([0u8; 28].to_vec(), WordCount::TwentyOne),
        ([0u8; 32].to_vec(), WordCount::TwentyFour),
    ];

    for (entropy, word_count) in test_cases {
        group.bench_with_input(
            BenchmarkId::new("from_entropy", word_count.word_count()),
            &entropy,
            |b, e| {
                b.iter(|| Mnemonic::new(black_box(e), black_box(Language::English)).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_mnemonic_from_phrase(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_from_phrase");

    // Pre-generate mnemonics
    let mnemonic_12 = Mnemonic::generate(WordCount::Twelve, Language::English).unwrap();
    let mnemonic_24 = Mnemonic::generate(WordCount::TwentyFour, Language::English).unwrap();

    group.bench_function("from_phrase_12_words", |b| {
        let phrase = mnemonic_12.phrase();
        b.iter(|| Mnemonic::from_phrase(black_box(phrase), black_box(Language::English)).unwrap());
    });

    group.bench_function("from_phrase_24_words", |b| {
        let phrase = mnemonic_24.phrase();
        b.iter(|| Mnemonic::from_phrase(black_box(phrase), black_box(Language::English)).unwrap());
    });

    group.finish();
}

fn bench_seed_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("seed_generation");

    let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English).unwrap();

    group.bench_function("to_seed_no_passphrase", |b| {
        b.iter(|| mnemonic.to_seed(black_box("")).unwrap());
    });

    group.bench_function("to_seed_with_passphrase", |b| {
        b.iter(|| mnemonic.to_seed(black_box("my secure passphrase")).unwrap());
    });

    group.bench_function("to_seed_unicode_passphrase", |b| {
        b.iter(|| mnemonic.to_seed(black_box("пароль 密码 🔑")).unwrap());
    });

    group.finish();
}

fn bench_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation");

    let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English).unwrap();
    let valid_phrase = mnemonic.phrase();
    let invalid_phrase = "invalid words here not bip39 at all";

    group.bench_function("validate_valid_phrase", |b| {
        b.iter(|| validate_phrase(black_box(valid_phrase)).unwrap());
    });

    group.bench_function("validate_invalid_phrase", |b| {
        b.iter(|| {
            let _ = validate_phrase(black_box(invalid_phrase));
        });
    });

    group.finish();
}

fn bench_utility_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("utility_functions");

    group.bench_function("generate_mnemonic", |b| {
        b.iter(|| generate_mnemonic(black_box(WordCount::Twelve)).unwrap());
    });

    let mnemonic = generate_mnemonic(WordCount::Twelve).unwrap();

    group.bench_function("phrase_to_seed", |b| {
        b.iter(|| phrase_to_seed(black_box(&mnemonic), black_box("password")).unwrap());
    });

    group.finish();
}

fn bench_multi_language(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_language");

    let languages = vec![
        Language::English,
        Language::Japanese,
        Language::Korean,
        Language::Spanish,
    ];

    for language in languages {
        group.bench_with_input(
            BenchmarkId::new("generate", language.name()),
            &language,
            |b, &lang| {
                b.iter(|| {
                    Mnemonic::generate(black_box(WordCount::Twelve), black_box(lang)).unwrap()
                });
            },
        );
    }

    group.finish();
}

fn bench_complete_workflow(c: &mut Criterion) {
    c.bench_function("complete_workflow_new_wallet", |b| {
        b.iter(|| {
            // Generate
            let mnemonic = Mnemonic::generate(
                black_box(WordCount::TwentyFour),
                black_box(Language::English),
            )
            .unwrap();

            // Get phrase
            let phrase = mnemonic.phrase();

            // Generate seed
            let seed = mnemonic.to_seed(black_box("passphrase")).unwrap();

            // Recover
            let recovered =
                Mnemonic::from_phrase(black_box(phrase), black_box(Language::English)).unwrap();

            // Verify
            let recovered_seed = recovered.to_seed(black_box("passphrase")).unwrap();

            assert_eq!(seed, recovered_seed);
        });
    });
}

criterion_group!(
    benches,
    bench_mnemonic_generation,
    bench_mnemonic_from_entropy,
    bench_mnemonic_from_phrase,
    bench_seed_generation,
    bench_validation,
    bench_utility_functions,
    bench_multi_language,
    bench_complete_workflow,
);

criterion_main!(benches);
