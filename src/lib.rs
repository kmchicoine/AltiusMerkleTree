use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

#[derive(Debug, Clone)]
pub struct MerkleTree {
    nodes: Vec<Hash>,
    leaf_count: usize,
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub siblings: Vec<Hash>,
    pub positions: Vec<bool>,
}

fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

fn hash_parent(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(&left[..]);
    hasher.update(&right[..]);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
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
}
