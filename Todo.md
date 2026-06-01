Optimized tool selection## Merkle Tree Project TODO

### 1. Project setup
- Create a Rust library crate
  - `Cargo.toml`
  - `src/lib.rs`
- Add a `tests/` folder for integration tests
- Create `README.md` with build/test/examples

### 2. Public API design
- Define `pub struct MerkleTree`
- Define `pub struct MerkleProof`
- Implement `MerkleTree::new<T: AsRef<[u8]>>(items: &[T]) -> Self`
- Implement:
  - `pub fn root(&self) -> Option<[u8; 32]>`
  - `pub fn proof(&self, index: usize) -> Option<MerkleProof>`
  - `pub fn len(&self) -> usize`
  - `pub fn is_empty(&self) -> bool`
- Implement `pub fn verify_proof<T: AsRef<[u8]>>(... ) -> bool`

### 3. Hashing strategy
- Use `sha2 = "0.10"`
- Implement:
  - `leaf_hash = SHA256(0x00 || leaf_data)` (recommended)
  - `parent_hash = SHA256(0x01 || left || right)`
- Keep hashing helpers small and reusable

### 4. Tree construction
- Build leaves from input items
- Compute internal nodes bottom-up
- Ensure empty input is handled gracefully
- Handle odd number of leaves deterministically
  - Choose one strategy and document it clearly
  - Example: duplicate last leaf, promote last leaf, or use domain-separated odd padding

### 5. Proof generation
- For a given leaf index, collect sibling hashes
- Record sibling position (left/right) or derive it from index
- Include enough metadata to avoid ambiguity

### 6. Proof verification
- Recompute hashes from item + proof
- Compare resulting root to expected root
- Fail on:
  - wrong leaf data
  - wrong index
  - modified proof
  - wrong root

### 7. Edge-case support
- Explicitly handle and test:
  - empty tree
  - single-leaf tree
  - two-leaf tree
  - odd number of leaves
  - duplicate leaf values
  - invalid proof index
  - modified leaf data
  - modified proof hash
  - modified root hash
  - large input set (1,000+ leaves)

### 8. Testing
- Unit tests for core behavior:
  - `empty_tree_has_no_root`
  - `single_leaf_root_is_leaf_hash`
  - `two_leaf_tree_root_is_parent_hash`
  - `odd_leaf_count_is_handled_deterministically`
  - `proof_verifies_for_each_leaf`
  - `proof_fails_for_wrong_leaf`
  - `proof_fails_for_wrong_index`
  - `proof_fails_for_wrong_root`
  - `proof_fails_when_proof_is_tampered`
  - `duplicate_values_can_still_be_proven_by_index`
  - `large_tree_builds_and_verifies`
- Optional: property-based tests with `proptest`
- Run `cargo test`, `cargo fmt`, `cargo clippy`

### 9. Documentation
- Add README sections:
  - Build
  - Test
  - Example usage
  - Design decisions
    - Hashing
    - Odd leaf handling
    - Empty tree handling
  - Assumptions / limitations
  - AI tool usage disclosure

### 10. Final polish
- Verify `cargo fmt`
- Verify `cargo clippy`
- Confirm `cargo test` passes
- Ensure API is small, clear, and idiomatic
- Keep implementation minimal and maintainable, not overengineered

--- 
## Recommended priority
1. API + tree/root/proof core
2. Edge-case handling
3. Test coverage
4. README + documentation
5. Optional enhancements if time remains