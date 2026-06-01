use crate::error::{MerkleError, Result};
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    // Prefix with 0x00 to distinguish leaf from parent hashes
    // Also prevents preimage attacks where an attacker could craft data that hashes to the same value as a parent hash
    hasher.update([0x00]);
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

pub fn hash_parent(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::new();
    // Prefix with 0x01 to distinguish parent from leaf hashes
    hasher.update([0x01]);
    hasher.update(&left[..]);
    hasher.update(&right[..]);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

pub fn hash_to_hex(hash: &Hash) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_hash(hex: &str) -> Result<Hash> {
    if hex.len() != 64 {
        return Err(MerkleError::InvalidHex("Invalid hex length".to_string()));
    }

    let mut hash = [0u8; 32];
    for i in 0..32 {
        let hex_byte = &hex[i * 2..i * 2 + 2];
        match u8::from_str_radix(hex_byte, 16) {
            Ok(byte) => hash[i] = byte,
            Err(_) => {
                return Err(MerkleError::InvalidHex(
                    "Invalid hex characters".to_string(),
                ))
            }
        }
    }

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash() {
        let h1 = hash_leaf(b"hello");
        let h2 = hash_leaf(b"hello");
        assert_eq!(h1, h2);

        let h3 = hash_leaf(b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_parent_hash() {
        let left = hash_leaf(b"a");
        let right = hash_leaf(b"b");
        let parent = hash_parent(left, right);

        let parent2 = hash_parent(left, right);
        assert_eq!(parent, parent2);

        let parent3 = hash_parent(right, left);
        assert_ne!(parent, parent3);
    }

    #[test]
    fn test_hash_to_hex() {
        let hash = hash_leaf(b"test");
        let hex = hash_to_hex(&hash);

        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hex_to_hash_roundtrip() {
        let original = hash_leaf(b"test");
        let hex = hash_to_hex(&original);
        let recovered = hex_to_hash(&hex).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_hex_to_hash_invalid() {
        assert!(hex_to_hash("invalid").is_err());
        assert!(hex_to_hash("abcd").is_err());
        assert!(
            hex_to_hash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
                .is_err()
        );
    }
}
