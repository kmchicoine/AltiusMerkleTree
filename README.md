# Altius Merkle Tree

A simple, efficient Merkle tree implementation in Rust with support for proof generation and verification.

## Features

- **Tree Construction**: Build a Merkle tree from arbitrary data items
- **Proof Generation**: Generate cryptographic proofs for any leaf
- **Proof Verification**: Verify proofs against a known root hash
- **Domain Separation**: Uses SHA-256 with domain separation to prevent tree-related attacks
- **Edge Case Handling**: Supports empty trees, single leaves, odd leaf counts, and large datasets

## Design Decisions

### Hashing Strategy

The implementation uses SHA-256 with domain separation bytes to prevent vulnerabilities:

- **Leaf hashing**: `SHA256(0x00 || leaf_data)` - Domain byte `0x00` distinguishes leaves
- **Parent hashing**: `SHA256(0x01 || left_hash || right_hash)` - Domain byte `0x01` distinguishes internal nodes

This prevents second-preimage attacks where leaf data could be interpreted as parent node hashes.

### Odd Leaf Handling

When the number of leaves is odd, the last leaf is duplicated to form a balanced binary tree. This strategy ensures:

- All leaves can generate valid proofs
- Tree structure remains deterministic
- Easy to reason about and implement

### Empty Tree Handling

An empty tree returns `None` for the root, clearly indicating no data is present.

### Tree Structure

The tree uses a flattened array representation where:

- Leaves occupy the rightmost level of a complete binary tree
- Parent nodes are indexed such that `parent = (child - 1) / 2`
- This enables efficient traversal without explicit parent pointers

## Building and Testing

### Build

```bash
cargo build --release
```

### Run Tests

```bash
cargo test
```

Includes 10 unit tests covering:

- Empty trees
- Single and double leaf trees
- Odd leaf counts
- Proof verification for all leaves
- Proof tampering detection
- Duplicate leaf values
- Large trees (1000+ leaves)
- Invalid proof indices

### Run Linter

```bash
cargo clippy
```

### Format Code

```bash
cargo fmt
```

## Example Usage

```rust
use altius_merkle_tree::MerkleTree;

fn main() {
    // Create a tree from items
    let items = &["apple", "banana", "cherry"];
    let tree = MerkleTree::new(items);

    // Get the root hash
    if let Some(root) = tree.root() {
        println!("Root: {:?}", root);
    }

    // Generate a proof for leaf 0
    if let Some(proof) = tree.proof(0) {
        // Verify the proof
        let valid = MerkleTree::verify_proof("apple", 0, &proof, root);
        assert!(valid);
    }
}
```

## Limitations

- Tree size is limited by available memory
- Proofs cannot verify that a leaf is NOT in the tree (accumulator would be needed)
- No support for dynamic insertion/deletion (tree is immutable after construction)

## Implementation Notes

- The implementation prioritizes clarity and correctness over performance
- Tree structure is fixed after construction for determinism
- All hashes are 32 bytes (SHA-256)
- Index-based proof generation avoids ambiguity with duplicate values

## AI Tool Disclosure

This implementation was created using GitHub Copilot as a code generation and debugging assistant.
