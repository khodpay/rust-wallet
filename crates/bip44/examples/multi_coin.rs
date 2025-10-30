//! Multi-coin wallet example.
//!
//! This example demonstrates managing multiple cryptocurrencies in a single wallet:
//! - Bitcoin, Ethereum, Litecoin, and Dogecoin
//! - Deriving addresses for each cryptocurrency
//! - Using different BIP purposes (44, 84, 86)
//!
//! Run with: cargo run --example multi_coin

use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Language, Purpose, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Multi-Coin Wallet Example ===\n");

    // Create a wallet from a mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    let mut wallet = Wallet::from_mnemonic(
        mnemonic,
        "",
        Language::English,
        Network::BitcoinMainnet,
    )?;
    
    println!("Wallet created from mnemonic\n");

    // Bitcoin (Legacy BIP-44)
    println!("--- Bitcoin (BIP-44 Legacy) ---");
    let btc_account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
    let btc_addr = btc_account.derive_external(0)?;
    println!("  Coin: {} ({})", btc_account.coin_type().name(), btc_account.coin_type().symbol());
    println!("  Path: m/44'/0'/0'/0/0");
    println!("  Depth: {}", btc_addr.depth());
    println!("  Address type: Legacy (1...)");
    println!();

    // Bitcoin (Native SegWit BIP-84)
    println!("--- Bitcoin (BIP-84 Native SegWit) ---");
    let btc_segwit = wallet.get_account(Purpose::BIP84, CoinType::Bitcoin, 0)?;
    let btc_segwit_addr = btc_segwit.derive_external(0)?;
    println!("  Coin: {} ({})", btc_segwit.coin_type().name(), btc_segwit.coin_type().symbol());
    println!("  Path: m/84'/0'/0'/0/0");
    println!("  Depth: {}", btc_segwit_addr.depth());
    println!("  Address type: Native SegWit (bc1q...)");
    println!();

    // Bitcoin (Taproot BIP-86)
    println!("--- Bitcoin (BIP-86 Taproot) ---");
    let btc_taproot = wallet.get_account(Purpose::BIP86, CoinType::Bitcoin, 0)?;
    let btc_taproot_addr = btc_taproot.derive_external(0)?;
    println!("  Coin: {} ({})", btc_taproot.coin_type().name(), btc_taproot.coin_type().symbol());
    println!("  Path: m/86'/0'/0'/0/0");
    println!("  Depth: {}", btc_taproot_addr.depth());
    println!("  Address type: Taproot (bc1p...)");
    println!();

    // Ethereum
    println!("--- Ethereum ---");
    let eth_account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0)?;
    let eth_addr = eth_account.derive_external(0)?;
    println!("  Coin: {} ({})", eth_account.coin_type().name(), eth_account.coin_type().symbol());
    println!("  Path: m/44'/60'/0'/0/0");
    println!("  Depth: {}", eth_addr.depth());
    println!("  Coin type: {}", eth_account.coin_type().index());
    println!();

    // Litecoin
    println!("--- Litecoin ---");
    let ltc_account = wallet.get_account(Purpose::BIP44, CoinType::Litecoin, 0)?;
    let ltc_addr = ltc_account.derive_external(0)?;
    println!("  Coin: {} ({})", ltc_account.coin_type().name(), ltc_account.coin_type().symbol());
    println!("  Path: m/44'/2'/0'/0/0");
    println!("  Depth: {}", ltc_addr.depth());
    println!("  Coin type: {}", ltc_account.coin_type().index());
    println!();

    // Dogecoin
    println!("--- Dogecoin ---");
    let doge_account = wallet.get_account(Purpose::BIP44, CoinType::Dogecoin, 0)?;
    let doge_addr = doge_account.derive_external(0)?;
    println!("  Coin: {} ({})", doge_account.coin_type().name(), doge_account.coin_type().symbol());
    println!("  Path: m/44'/3'/0'/0/0");
    println!("  Depth: {}", doge_addr.depth());
    println!("  Coin type: {}", doge_account.coin_type().index());
    println!();

    // Custom coin type (e.g., Solana)
    println!("--- Custom Coin (Solana) ---");
    let custom_coin = CoinType::Custom(501);
    let custom_account = wallet.get_account(Purpose::BIP44, custom_coin, 0)?;
    let custom_addr = custom_account.derive_external(0)?;
    println!("  Coin: Custom (SOL)");
    println!("  Path: m/44'/501'/0'/0/0");
    println!("  Depth: {}", custom_addr.depth());
    println!("  Coin type: {}", custom_account.coin_type().index());
    println!();

    // Summary
    println!("--- Summary ---");
    println!("  Total cached accounts: {}", wallet.cached_account_count());
    println!("  Cryptocurrencies: Bitcoin (3 types), Ethereum, Litecoin, Dogecoin, Solana");
    println!("  All addresses derived from the same seed!");
    println!();

    println!("=== Example Complete ===");
    
    Ok(())
}
