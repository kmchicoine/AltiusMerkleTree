use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum MerkleError {
    InvalidIndex,
    EmptyTree,
    InvalidHex(String),
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::InvalidIndex => write!(f, "Invalid index"),
            MerkleError::EmptyTree => write!(f, "Empty tree"),
            MerkleError::InvalidHex(msg) => write!(f, "Invalid hex: {}", msg),
        }
    }
}

impl Error for MerkleError {}

pub type Result<T> = std::result::Result<T, MerkleError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_invalid_index() {
        let err = MerkleError::InvalidIndex;
        assert_eq!(err.to_string(), "Invalid index");
    }

    #[test]
    fn test_error_empty_tree() {
        let err = MerkleError::EmptyTree;
        assert_eq!(err.to_string(), "Empty tree");
    }

    #[test]
    fn test_error_invalid_hex() {
        let err = MerkleError::InvalidHex("test".to_string());
        assert!(err.to_string().contains("Invalid hex"));
    }

    #[test]
    fn test_error_clone() {
        let err1 = MerkleError::InvalidIndex;
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }
}
