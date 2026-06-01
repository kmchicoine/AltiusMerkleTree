mod error;
mod hash;
mod proof;
mod tree;

// Re-export public API
pub use error::{MerkleError, Result};
pub use hash::Hash;
pub use proof::MerkleProof;
pub use tree::MerkleTree;
