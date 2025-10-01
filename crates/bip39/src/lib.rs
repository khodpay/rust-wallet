// Module declarations
mod error;
mod language;
mod word_count;
mod utils;
mod mnemonic;

// Public re-exports
pub use error::{Error, Result};
pub use language::Language;
pub use word_count::WordCount;
pub use mnemonic::Mnemonic;
pub use utils::{
    validate_phrase, 
    validate_phrase_in_language, 
    phrase_to_seed, 
    phrase_to_seed_in_language,
    generate_mnemonic,
    generate_mnemonic_in_language,
};
