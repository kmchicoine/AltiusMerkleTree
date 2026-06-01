use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

#[derive(Debug, Clone)]
pub struct MerkleTree {
    // flattened binary tree stored in an array
    nodes: Vec<Hash>,
    leaf_count: usize,
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub siblings: Vec<Hash>,
    // binary tree implementation for simplicity
    // true for right sibling, false for left sibling
    pub positions: Vec<bool>,
}

fn hash_leaf(data: &[u8]) -> Hash {
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

fn hash_parent(left: Hash, right: Hash) -> Hash {
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

impl MerkleTree {
    pub fn new<T: AsRef<[u8]>>(items: &[T]) -> Self {
        if items.is_empty() {
            return MerkleTree {
                nodes: Vec::new(),
                leaf_count: 0,
            };
        }

        let n = items.len();
        let leaf_count = n;

        // Single leaf special case: single leaf hash is the root
        if n == 1 {
            return MerkleTree {
                nodes: vec![hash_leaf(items[0].as_ref())],
                leaf_count: 1,
            };
        }

        // For n >= 2: compute height needed for n leaves (smallest power of 2 >= n)
        let leaf_capacity = (n as u32).next_power_of_two() as usize;
        let height = leaf_capacity.trailing_zeros() as usize;

        // Total nodes in a complete binary tree: 2^(height+1) - 1
        let total_nodes = (1 << (height + 1)) - 1;

        let mut nodes = vec![[0u8; 32]; total_nodes];

        // Leaf level starts at index 2^height - 1
        // We will start with the leaf hashes and build the tree "backwards"
        // in the array
        let leaf_start = (1 << height) - 1;

        let mut leaf_hashes = Vec::new();
        for item in items {
            leaf_hashes.push(hash_leaf(item.as_ref()));
        }

        // If odd number of leaves, duplicate the last one
        if leaf_hashes.len() % 2 == 1 {
            leaf_hashes.push(*leaf_hashes.last().unwrap());
        }

        // Add leaves to tree
        for (i, &hash) in leaf_hashes.iter().enumerate() {
            nodes[leaf_start + i] = hash;
        }

        // Build tree upwards by hashing children to get parent hashes
        for level in (0..height).rev() {
            let level_start = (1 << level) - 1;
            let next_level_start = (1 << (level + 1)) - 1;
            for i in 0..(1 << level) {
                let parent_idx = level_start + i;
                let left_idx = next_level_start + i * 2;
                let right_idx = next_level_start + i * 2 + 1;
                if left_idx < nodes.len() && right_idx < nodes.len() {
                    nodes[parent_idx] = hash_parent(nodes[left_idx], nodes[right_idx]);
                }
            }
        }

        MerkleTree { nodes, leaf_count }
    }

    pub fn root(&self) -> Option<Hash> {
        if self.nodes.is_empty() {
            None
        } else {
            Some(self.nodes[0])
        }
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }
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
    fn test_tree_creation_empty() {
        let tree = MerkleTree::new::<&str>(&[]);
        assert_eq!(tree.leaf_count, 0);
    }

    #[test]
    fn test_tree_creation_single() {
        let tree = MerkleTree::new(&["hello"]);
        assert_eq!(tree.leaf_count, 1);
        assert_eq!(tree.nodes.len(), 1);
    }

    #[test]
    fn test_tree_creation_two() {
        let tree = MerkleTree::new(&["a", "b"]);
        assert_eq!(tree.leaf_count, 2);

        let h_a = hash_leaf(b"a");
        let h_b = hash_leaf(b"b");
        let expected_root = hash_parent(h_a, h_b);
        assert_eq!(tree.nodes[0], expected_root);
    }

    #[test]
    fn test_tree_creation_three() {
        let tree = MerkleTree::new(&["a", "b", "c"]);
        assert_eq!(tree.leaf_count, 3);
    }

    #[test]
    fn test_tree_creation_four() {
        let tree = MerkleTree::new(&["a", "b", "c", "d"]);
        assert_eq!(tree.leaf_count, 4);
    }

    #[test]
    fn test_empty_tree_root() {
        let tree = MerkleTree::new::<&str>(&[]);
        assert!(tree.root().is_none());
        assert!(tree.is_empty());
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_single_leaf_root() {
        let tree = MerkleTree::new(&["hello"]);
        let expected_root = hash_leaf(b"hello");
        assert_eq!(tree.root(), Some(expected_root));
        assert!(!tree.is_empty());
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn test_two_leaf_root() {
        let tree = MerkleTree::new(&["hello", "world"]);
        let left_hash = hash_leaf(b"hello");
        let right_hash = hash_leaf(b"world");
        let expected_root = hash_parent(left_hash, right_hash);
        assert_eq!(tree.root(), Some(expected_root));
        assert_eq!(tree.leaf_count(), 2);
    }

    #[test]
    fn test_metadata() {
        let tree4 = MerkleTree::new(&["a", "b", "c", "d"]);
        assert_eq!(tree4.leaf_count(), 4);
        assert!(!tree4.is_empty());
        assert!(tree4.root().is_some());

        let tree_empty = MerkleTree::new::<&str>(&[]);
        assert_eq!(tree_empty.leaf_count(), 0);
        assert!(tree_empty.is_empty());
        assert!(tree_empty.root().is_none());
    }
}
