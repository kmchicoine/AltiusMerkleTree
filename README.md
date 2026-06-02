# Altius Merkle Tree

A binary Merkle tree implementation in Rust with support for proof generation, verification, and comprehensive testing.

## Features

- **Tree Construction**: Build a Merkle tree from arbitrary data items
- **Proof Generation**: Generate cryptographic proofs for any leaf
- **Proof Verification**: Verify proofs against a known root hash
- **Domain Separation**: Uses SHA-256 with domain separation to prevent tree-related attacks
- **Edge Case Handling**: Supports empty trees, single leaves, odd leaf counts, and large datasets
- **Comprehensive Testing**: Unit tests, property-based tests, and integration tests

## Build

```bash
cargo build
```

For an optimized release build:

```bash
cargo build --release
```

## Test

Run all tests (unit, integration, and property-based):

```bash
cargo test
```

Run only unit tests:

```bash
cargo test --lib
```

Run only property-based tests:

```bash
cargo test --test merkle_tree
```


### Test Coverage

The implementation includes **47 comprehensive tests**:

- **42 unit tests** in `src/`:
  - Empty tree handling
  - Single and multiple leaf trees
  - Odd leaf counts and determinism
  - Proof generation and verification
  - Proof tampering detection
  - Duplicate leaf values
  - Large trees (256+ leaves, up to 1024)
  - Serialization/deserialization
  - Binary and string data types

- **5 property-based tests** in `tests/`:
  - Every leaf proof validates (1-100 random items)
  - Wrong leaf values fail verification
  - Tree consistency across rebuilds
  - Proof independence (proof for one leaf doesn't verify with another)
  - Random array sizes (1-200 items)

## Example Usage

### Basic Tree Construction and Proof Verification

```rust
use AltiusMerkleTree::MerkleTree;

fn main() {
    // Create a tree from items
    let items = &["apple", "banana", "cherry"];
    let tree = MerkleTree::new(items);

    // Get the root hash
    let root = tree.root().expect("Tree should have a root");
    println!("Root: {}", tree.root_hex().unwrap());

    // Generate a proof for leaf at index 0
    let proof = tree.proof(0).expect("Index 0 should be valid");

    // Verify the proof
    let is_valid = MerkleTree::verify_proof("apple", 0, &proof, root);
    assert!(is_valid);
    println!("Proof verified!");

    // Wrong data fails verification
    let is_invalid = MerkleTree::verify_proof("orange", 0, &proof, root);
    assert!(!is_invalid);
    println!("Wrong data rejected!");
}
```

### Large Dataset Example

```rust
use AltiusMerkleTree::MerkleTree;

fn main() {
    // Create a tree with many items
    let items: Vec<String> = (0..1000)
        .map(|i| format!("item_{}", i))
        .collect();
    let item_refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
    let tree = MerkleTree::new(&item_refs);

    // Verify proofs for specific items
    for index in [0, 100, 500, 999] {
        let proof = tree.proof(index).expect("Index should be valid");
        let root = tree.root().unwrap();
        let valid = MerkleTree::verify_proof(item_refs[index], index, &proof, root);
        assert!(valid);
    }
    
    println!("All proofs verified!");
}
```

### Serialization

```rust
use AltiusMerkleTree::MerkleTree;

fn main() {
    let tree = MerkleTree::new(&["a", "b", "c"]);
    
    // Serialize to JSON
    let json = serde_json::to_string(&tree).unwrap();
    println!("Tree: {}", json);
    
    // Deserialize back
    let restored: MerkleTree = serde_json::from_str(&json).unwrap();
    assert_eq!(tree.root(), restored.root());
}
```

## Design Decisions

### Hashing Strategy

The implementation uses SHA-256 with domain separation bytes to prevent vulnerabilities:

- **Leaf hashing**: `SHA256(0x00 || leaf_data)` 
  - Domain byte `0x00` distinguishes leaves from parent nodes
  - Prevents second-preimage attacks where leaf data could be misinterpreted as parent hashes

- **Parent hashing**: `SHA256(0x01 || left_hash || right_hash)`
  - Domain byte `0x01` distinguishes internal nodes from leaves
  - Ensures parent hashes cannot be forged from leaf data

**Why this approach?** Domain separation is a best practice in cryptographic protocols. Without it, an attacker could craft data that hashes to the same value as an internal node, potentially forging proofs.

### Odd Leaf Handling

When the number of leaves is odd, the last leaf is duplicated to form a balanced binary tree:

**Example with 3 leaves:**
```
         Root
        /    \
      H(A,B)  H(C,C)
      /  \     /  \
     A    B   C    C
```

**Why this approach?**
- Simple and deterministic - same input always produces same output
- All leaves can generate valid proofs
- Handles duplicate values without ambiguity
- Avoids incomplete subtrees which complicate proof paths

**Alternative considered:** Balanced hashing or variable-height trees would be more complex and harder to reason about.

### Empty Tree Handling

An empty tree (zero leaves) returns an error when requesting the root hash.

**Why this approach?**
- Explicit error handling - no silent failures
- Clear semantics - empty trees have no meaningful root

### Tree Structure

The tree uses a flattened array representation of a complete binary tree for simplicity. Bitwise capacity math (1 << (height + 1)), the memory for the whole tree can be allocated in a single allocation, but this does introduce problems for extremely large trees, as a single contiguous block of memory needs to be free to store the array.

- Leaves occupy the rightmost indices
- Parent index: `(child_index - 1) / 2`
- Left child index: `2 * parent_index + 1`
- Right child index: `2 * parent_index + 2`

**Why this approach?**
- Cache-friendly and memory-efficient
- No need for explicit parent pointers (less structural overhead)
- Straightforward level-order construction
- Deterministic structure (no tree rotations or balancing)

**Disadvantages**
- Need single contiguous block of memory
- Best suited for static/append only datasets, as changes to leaves or insertions in the middle of the dataset cause cascading hash recalculations and potentially reallocation of an array twice the size

### Proof Structure

Proofs consist of:
- **Siblings**: Hash values needed to reconstruct the root
- **Positions**: Boolean flags indicating if each sibling is left or right

This design allows verification without storing the leaf value explicitly, though the leaf value must be provided at verification time.

## Assumptions and Limitations

### Assumptions

1. **Immutability**: Trees are immutable after construction - no insertions/deletions
2. **Determinism**: Same input always produces same tree and proofs
3. **32-byte hashes**: All hashes are exactly 32 bytes (SHA-256)
4. **Index-based proofs**: Leaf identity determined by index, not value (handles duplicates naturally)

### Limitations

1. **Memory**: Tree size limited by available RAM (O(n) space complexity)
2. **Proof of non-inclusion**: Cannot prove a leaf is NOT in the tree (would require accumulator)
3. **Dynamic operations**: No support for efficient insertion/deletion (full rebuild required)
4. **Single thread**: No built-in parallelism (though individual proof verifications are parallelizable)
5. **Fixed hash function**: SHA-256 hardcoded (not pluggable)

```

## API Overview

### Public Types

```rust
pub type Hash = [u8; 32];

pub struct MerkleTree { /* ... */ }
pub struct MerkleProof {
    pub siblings: Vec<Hash>,
    pub positions: Vec<bool>,
}

pub enum MerkleError {
    EmptyTree,
    InvalidIndex,
    InvalidHex(String),
}
```

### Public Methods

```rust
impl MerkleTree {
    // Construction
    pub fn new<T: AsRef<[u8]>>(items: &[T]) -> Self

    // Query
    pub fn root(&self) -> Result<Hash>
    pub fn root_hex(&self) -> Result<String>
    pub fn leaf_count(&self) -> usize
    pub fn is_empty(&self) -> bool

    // Proofs
    pub fn proof(&self, index: usize) -> Result<MerkleProof>
    pub fn verify_proof<T: AsRef<[u8]>>(
        item: T,
        index: usize,
        proof: &MerkleProof,
        expected_root: Hash,
    ) -> bool
}
```

## Dependencies

- `sha2`: SHA-256 hashing
- `serde`: Serialization support
- `proptest`: Property-based testing (dev-dependency)

## AI Tool Disclosure

This implementation was created with assistance from **GitHub Copilot**. Copilot was used for:

- **Code generation**: Initial implementations of tree construction and proof logic
- **Testing**: Generating unit test cases and test structure
- **Documentation**: Initial drafts of comments and design explanations

All code was reviewed, tested, and refined to ensure correctness. The main design decisions (domain separation, odd-leaf duplication, array-based tree structure) were deliberate choices, and function definitions with input/output types were provided to the AI as constraints. 

