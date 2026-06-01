use sha2::{Digest, Sha256};
use std::fmt;
use std::error::Error;

pub type Hash = [u8; 32];

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleTree {
    // flattened binary tree stored in an array
    nodes: Vec<Hash>,
    leaf_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    pub siblings: Vec<Hash>,
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
            Err(_) => return Err(MerkleError::InvalidHex("Invalid hex characters".to_string())),
        }
    }

    Ok(hash)
}

impl MerkleProof {
    pub fn to_hex_siblings(&self) -> Vec<String> {
        self.siblings.iter().map(hash_to_hex).collect()
    }

    pub fn from_hex_siblings(hex_siblings: &[String], positions: Vec<bool>) -> Result<Self> {
        let mut siblings = Vec::new();
        for h in hex_siblings {
            siblings.push(hex_to_hash(h)?);
        }
        Ok(MerkleProof {
            siblings,
            positions,
        })
    }
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

    pub fn root(&self) -> Result<Hash> {
        if self.nodes.is_empty() {
            Err(MerkleError::EmptyTree)
        } else {
            Ok(self.nodes[0])
        }
    }

    pub fn root_hex(&self) -> Result<String> {
        self.root().map(|h| hash_to_hex(&h))
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    pub fn proof(&self, index: usize) -> Result<MerkleProof> {
        if index >= self.leaf_count {
            return Err(MerkleError::InvalidIndex);
        }

        if self.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        // Special case: single leaf has no proof (no siblings)
        if self.leaf_count == 1 {
            return Ok(MerkleProof {
                siblings: Vec::new(),
                positions: Vec::new(),
            });
        }

        let leaf_capacity = (self.leaf_count as u32).next_power_of_two() as usize;
        let height = leaf_capacity.trailing_zeros() as usize;
        let leaf_start = (1 << height) - 1;

        let mut current_idx = leaf_start + index;
        let mut siblings = Vec::new();
        let mut positions = Vec::new();

        while current_idx > 0 {
            let parent_idx = (current_idx - 1) / 2;
            let sibling_idx = if current_idx % 2 == 1 {
                current_idx + 1
            } else {
                current_idx - 1
            };

            if sibling_idx < self.nodes.len() {
                let is_left = current_idx % 2 == 1;
                siblings.push(self.nodes[sibling_idx]);
                positions.push(is_left);
            }

            current_idx = parent_idx;
        }

        Ok(MerkleProof { siblings, positions })
    }

    pub fn verify_proof<T: AsRef<[u8]>>(
        item: T,
        _index: usize,
        proof: &MerkleProof,
        expected_root: Hash,
    ) -> bool {
        let mut current_hash = hash_leaf(item.as_ref());

        for (sibling, is_left) in proof.siblings.iter().zip(proof.positions.iter()) {
            current_hash = if *is_left {
                hash_parent(current_hash, *sibling)
            } else {
                hash_parent(*sibling, current_hash)
            };
        }

        current_hash == expected_root
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
        assert!(tree.root().is_err());
        assert!(tree.is_empty());
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_single_leaf_root() {
        let tree = MerkleTree::new(&["hello"]);
        let expected_root = hash_leaf(b"hello");
        assert_eq!(tree.root().unwrap(), expected_root);
        assert!(!tree.is_empty());
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn test_two_leaf_root() {
        let tree = MerkleTree::new(&["hello", "world"]);
        let left_hash = hash_leaf(b"hello");
        let right_hash = hash_leaf(b"world");
        let expected_root = hash_parent(left_hash, right_hash);
        assert_eq!(tree.root().unwrap(), expected_root);
        assert_eq!(tree.leaf_count(), 2);
    }

    #[test]
    fn test_metadata() {
        let tree4 = MerkleTree::new(&["a", "b", "c", "d"]);
        assert_eq!(tree4.leaf_count(), 4);
        assert!(!tree4.is_empty());
        assert!(tree4.root().is_ok());

        let tree_empty = MerkleTree::new::<&str>(&[]);
        assert_eq!(tree_empty.leaf_count(), 0);
        assert!(tree_empty.is_empty());
        assert!(tree_empty.root().is_err());
    }

    #[test]
    fn test_proof_invalid_index() {
        let tree = MerkleTree::new(&["a", "b"]);
        assert!(tree.proof(5).is_err());
    }

    #[test]
    fn test_proof_empty_tree() {
        let tree = MerkleTree::new::<&str>(&[]);
        assert!(tree.proof(0).is_err());
    }

    #[test]
    fn test_proof_single_leaf() {
        let tree = MerkleTree::new(&["a"]);
        let proof = tree.proof(0).unwrap();
        assert_eq!(proof.siblings.len(), 0);
        assert_eq!(proof.positions.len(), 0);
    }

    #[test]
    fn test_proof_two_leaves() {
        let tree = MerkleTree::new(&["a", "b"]);
        
        let proof0 = tree.proof(0).unwrap();
        assert_eq!(proof0.siblings.len(), 1);
        assert_eq!(proof0.positions.len(), 1);
        assert_eq!(proof0.positions[0], true);

        let proof1 = tree.proof(1).unwrap();
        assert_eq!(proof1.siblings.len(), 1);
        assert_eq!(proof1.positions.len(), 1);
        assert_eq!(proof1.positions[0], false);
    }

    #[test]
    fn test_proof_four_leaves() {
        let tree = MerkleTree::new(&["a", "b", "c", "d"]);
        
        let proof0 = tree.proof(0).unwrap();
        assert_eq!(proof0.siblings.len(), 2);
        
        let proof1 = tree.proof(1).unwrap();
        assert_eq!(proof1.siblings.len(), 2);
        
        let proof2 = tree.proof(2).unwrap();
        assert_eq!(proof2.siblings.len(), 2);
        
        let proof3 = tree.proof(3).unwrap();
        assert_eq!(proof3.siblings.len(), 2);
    }

    #[test]
    fn test_verify_proof_single_leaf() {
        let tree = MerkleTree::new(&["a"]);
        let root = tree.root().unwrap();
        let proof = tree.proof(0).unwrap();
        
        assert!(MerkleTree::verify_proof("a", 0, &proof, root));
        assert!(!MerkleTree::verify_proof("b", 0, &proof, root));
    }

    #[test]
    fn test_verify_proof_two_leaves() {
        let tree = MerkleTree::new(&["a", "b"]);
        let root = tree.root().unwrap();
        
        let proof0 = tree.proof(0).unwrap();
        assert!(MerkleTree::verify_proof("a", 0, &proof0, root));
        assert!(!MerkleTree::verify_proof("b", 0, &proof0, root));
        
        let proof1 = tree.proof(1).unwrap();
        assert!(MerkleTree::verify_proof("b", 1, &proof1, root));
        assert!(!MerkleTree::verify_proof("a", 1, &proof1, root));
    }

    #[test]
    fn test_verify_proof_four_leaves() {
        let items = &["a", "b", "c", "d"];
        let tree = MerkleTree::new(items);
        let root = tree.root().unwrap();

        for (idx, item) in items.iter().enumerate() {
            let proof = tree.proof(idx).unwrap();
            assert!(MerkleTree::verify_proof(item, idx, &proof, root));
        }
    }

    #[test]
    fn test_verify_proof_wrong_data() {
        let tree = MerkleTree::new(&["a", "b", "c", "d"]);
        let root = tree.root().unwrap();
        let proof = tree.proof(0).unwrap();

        assert!(!MerkleTree::verify_proof("wrong", 0, &proof, root));
    }

    #[test]
    fn test_verify_proof_tampered() {
        let tree = MerkleTree::new(&["a", "b", "c", "d"]);
        let root = tree.root().unwrap();

        let mut proof = tree.proof(0).unwrap();
        if !proof.siblings.is_empty() {
            proof.siblings[0][0] ^= 0xFF;
        }

        assert!(!MerkleTree::verify_proof("a", 0, &proof, root));
    }

    #[test]
    fn test_verify_proof_duplicate_values() {
        let items = &["a", "a", "b", "b"];
        let tree = MerkleTree::new(items);
        let root = tree.root().unwrap();

        for (idx, item) in items.iter().enumerate() {
            let proof = tree.proof(idx).unwrap();
            assert!(MerkleTree::verify_proof(item, idx, &proof, root));
        }
    }

    #[test]
    fn test_verify_proof_large_tree() {
        let items: Vec<String> = (0..256).map(|i| format!("item_{}", i)).collect();
        let item_refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
        let tree = MerkleTree::new(&item_refs);
        let root = tree.root().unwrap();

        for idx in [0, 50, 100, 200, 255] {
            let proof = tree.proof(idx).unwrap();
            assert!(MerkleTree::verify_proof(item_refs[idx], idx, &proof, root));
        }
    }

    #[test]
    fn test_consistency() {
        let items1 = &["a", "b", "c"];
        let items2 = &["a", "b", "c"];

        let tree1 = MerkleTree::new(items1);
        let tree2 = MerkleTree::new(items2);

        assert_eq!(tree1.root(), tree2.root());
        assert_eq!(tree1.leaf_count(), tree2.leaf_count());

        for idx in 0..3 {
            let proof1 = tree1.proof(idx).unwrap();
            let proof2 = tree2.proof(idx).unwrap();

            assert_eq!(proof1.siblings.len(), proof2.siblings.len());
            for (s1, s2) in proof1.siblings.iter().zip(proof2.siblings.iter()) {
                assert_eq!(s1, s2);
            }
        }
    }

    #[test]
    fn test_binary_items() {
        let items = &[b"binary1", b"binary2", b"binary3"];
        let tree = MerkleTree::new(items);

        let root = tree.root().unwrap();

        for (idx, item) in items.iter().enumerate() {
            let proof = tree.proof(idx).unwrap();
            assert!(MerkleTree::verify_proof(&item[..], idx, &proof, root));
        }
    }

    #[test]
    fn test_string_types() {
        let items: Vec<String> = vec![
            "hello".to_string(),
            "world".to_string(),
            "merkle".to_string(),
            "tree".to_string(),
        ];

        let item_refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
        let tree = MerkleTree::new(&item_refs);

        let root = tree.root().unwrap();

        for (idx, item) in item_refs.iter().enumerate() {
            let proof = tree.proof(idx).unwrap();
            assert!(MerkleTree::verify_proof(item, idx, &proof, root));
        }
    }

    #[test]
    fn test_very_large_tree() {
        let items: Vec<String> = (0..1024).map(|i| format!("item_{}", i)).collect();
        let item_refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();

        let tree = MerkleTree::new(&item_refs);

        assert_eq!(tree.leaf_count(), 1024);
        let root = tree.root().unwrap();

        for idx in [0, 100, 512, 900, 1023] {
            let proof = tree.proof(idx).unwrap();
            assert!(MerkleTree::verify_proof(item_refs[idx], idx, &proof, root));
        }
    }

    #[test]
    fn test_odd_leaf_count() {
        let tree = MerkleTree::new(&["a", "b", "c"]);
        let root = tree.root();
        assert!(root.is_ok());

        let tree2 = MerkleTree::new(&["a", "b", "c", "c"]);
        assert!(tree2.root().is_ok());
    }

    #[test]
    fn test_single_byte_items() {
        let items = &[b"a", b"b", b"c"];
        let tree = MerkleTree::new(items);
        let root = tree.root().unwrap();

        for (idx, item) in items.iter().enumerate() {
            let proof = tree.proof(idx).unwrap();
            assert!(MerkleTree::verify_proof(&item[..], idx, &proof, root));
        }
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
        assert!(hex_to_hash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn test_root_hex() {
        let tree = MerkleTree::new(&["a", "b"]);
        let hex = tree.root_hex();

        assert!(hex.is_ok());
        let hex_str = hex.unwrap();
        assert_eq!(hex_str.len(), 64);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_proof_to_hex_siblings() {
        let tree = MerkleTree::new(&["a", "b", "c", "d"]);
        let proof = tree.proof(0).unwrap();
        let hex_siblings = proof.to_hex_siblings();

        assert_eq!(hex_siblings.len(), proof.siblings.len());
        for hex in hex_siblings {
            assert_eq!(hex.len(), 64);
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_proof_from_hex_siblings() {
        let tree = MerkleTree::new(&["a", "b", "c", "d"]);
        let original_proof = tree.proof(0).unwrap();
        let hex_siblings = original_proof.to_hex_siblings();

        let recovered = MerkleProof::from_hex_siblings(&hex_siblings, original_proof.positions.clone()).unwrap();

        assert_eq!(recovered.siblings.len(), original_proof.siblings.len());
        for (s1, s2) in recovered.siblings.iter().zip(original_proof.siblings.iter()) {
            assert_eq!(s1, s2);
        }
    }

    #[test]
    fn test_tree_serialization() {
        let tree = MerkleTree::new(&["a", "b", "c", "d"]);
        let json = serde_json::to_string(&tree).expect("Failed to serialize");
        let deserialized: MerkleTree = serde_json::from_str(&json).expect("Failed to deserialize");
        
        assert_eq!(tree.root(), deserialized.root());
        assert_eq!(tree.leaf_count(), deserialized.leaf_count());
    }

    #[test]
    fn test_proof_serialization() {
        let tree = MerkleTree::new(&["a", "b", "c", "d"]);
        let proof = tree.proof(1).unwrap();
        let json = serde_json::to_string(&proof).expect("Failed to serialize");
        let deserialized: MerkleProof = serde_json::from_str(&json).expect("Failed to deserialize");
        
        assert_eq!(proof.siblings.len(), deserialized.siblings.len());
        assert_eq!(proof.positions, deserialized.positions);
    }

    #[test]
    fn test_error_invalid_index() {
        let tree = MerkleTree::new(&["a", "b"]);
        match tree.proof(10) {
            Err(MerkleError::InvalidIndex) => {},
            _ => panic!("Expected InvalidIndex error"),
        }
    }

    #[test]
    fn test_error_empty_tree() {
        let tree: MerkleTree = MerkleTree::new::<&str>(&[]);
        match tree.root() {
            Err(MerkleError::EmptyTree) => {},
            _ => panic!("Expected EmptyTree error"),
        }
    }

    #[test]
    fn test_error_invalid_hex() {
        match hex_to_hash("not_valid_hex") {
            Err(MerkleError::InvalidHex(_)) => {},
            _ => panic!("Expected InvalidHex error"),
        }
    }
}

