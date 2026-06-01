use crate::error::Result;
use crate::hash::{hash_to_hex, hex_to_hash, Hash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub siblings: Vec<Hash>,
    // true for right sibling, false for left sibling
    pub positions: Vec<bool>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_leaf;

    #[test]
    fn test_proof_to_hex_siblings() {
        let sibling = hash_leaf(b"test");
        let proof = MerkleProof {
            siblings: vec![sibling],
            positions: vec![true],
        };
        let hex_siblings = proof.to_hex_siblings();

        assert_eq!(hex_siblings.len(), 1);
        assert_eq!(hex_siblings[0].len(), 64);
        assert!(hex_siblings[0].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_proof_from_hex_siblings() {
        let sibling = hash_leaf(b"test");
        let hex_sibling = hash_to_hex(&sibling);
        let positions = vec![true];

        let proof =
            MerkleProof::from_hex_siblings(std::slice::from_ref(&hex_sibling), positions.clone())
                .unwrap();

        assert_eq!(proof.siblings.len(), 1);
        assert_eq!(proof.siblings[0], sibling);
        assert_eq!(proof.positions, positions);
    }

    #[test]
    fn test_proof_serialization() {
        let proof = MerkleProof {
            siblings: vec![hash_leaf(b"test1"), hash_leaf(b"test2")],
            positions: vec![true, false],
        };
        let json = serde_json::to_string(&proof).expect("Failed to serialize");
        let deserialized: MerkleProof = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(proof.siblings.len(), deserialized.siblings.len());
        assert_eq!(proof.positions, deserialized.positions);
    }
}
