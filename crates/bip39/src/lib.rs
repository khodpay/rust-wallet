// Module declarations
mod error;
mod word_count;
mod utils;

// Public re-exports
pub use error::{Error, Result};
pub use word_count::WordCount;
pub use utils::validate_phrase;
