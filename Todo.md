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



Plan: Merkle Tree Implementation
TL;DR: Build a minimal Rust Merkle tree crate with an idiomatic public API, deterministic odd-leaf handling, domain-separated SHA-256 hashing, robust proof generation/verification, edge-case coverage, and README documentation.

Steps

Project scaffolding
Create Cargo.toml as a library crate.
Create src/lib.rs.
Create tests/ for integration tests.
Create README.md.
API and type definitions
pub struct MerkleTree { levels: Vec<Vec<[u8; 32]>>, leaf_count: usize }
pub struct MerkleProof { leaf_index: usize, sibling_hashes: Vec<[u8; 32]>, sibling_positions: Vec<Side> }
pub enum Side { Left, Right }
Public API functions
pub fn new<T: AsRef<[u8]>>(items: &[T]) -> Self
returns a built tree, always valid, empty tree allowed
calls hash_leaf for each input item
calls build_tree to compute all levels
pub fn root(&self) -> Option<[u8; 32]>
returns Some(root_hash) for non-empty tree
returns None when leaf_count == 0
pub fn proof(&self, index: usize) -> Option<MerkleProof>
returns None for invalid index or empty tree
returns proof metadata for valid index
pub fn len(&self) -> usize
returns self.leaf_count
pub fn is_empty(&self) -> bool
returns self.leaf_count == 0
pub fn verify_proof<T: AsRef<[u8]>>(item: T, index: usize, root: [u8; 32], proof: &MerkleProof) -> bool
returns true only when proof recomputes the exact root
returns false for wrong index, wrong leaf, wrong root, or modified proof
Hashing helpers and domain separation
fn hash_leaf(data: &[u8]) -> [u8; 32]
computes SHA256(0x00 || data)
fn hash_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32]
computes SHA256(0x01 || left || right)
Document this explicit domain separation in README
Tree construction flow
fn build_tree(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>>
returns tree levels from leaves through root
if leaves is empty, return empty levels
if one leaf, return vec![leaves]
otherwise repeatedly call build_level until a single root remains
fn build_level(nodes: &[ [u8; 32] ]) -> Vec<[u8; 32]>
if node count is odd, duplicate the final node
pair every two nodes, call hash_parent(left, right)
return parent hashes
Deterministic odd-leaf rule: duplicate the final node at each level
document in README under "Odd Leaf Handling"
Proof generation flow
pub fn proof(&self, index: usize) -> Option<MerkleProof>
validate index < leaf_count
initialize current_index = index
for each level from leaves to the level before root:
compute sibling_index and position based on parity
if sibling index is out of bounds because count is odd, sibling hash = current node
push sibling_hash and position
set current_index /= 2 for next level
return MerkleProof { leaf_index: index, sibling_hashes, sibling_positions }
The proof stores leaf_index to ensure wrong-index verification fails
If tree has one leaf, produce an empty proof list
Proof verification flow
pub fn verify_proof<T: AsRef<[u8]>>(item: T, index: usize, root: [u8; 32], proof: &MerkleProof) -> bool
return false if proof.leaf_index != index
compute current_hash = hash_leaf(item.as_ref())
iterate sibling hashes and positions in order:
if Side::Left, current_hash = hash_parent(&sibling, &current_hash)
if Side::Right, current_hash = hash_parent(&current_hash, &sibling)
return current_hash == root
Keep verification deterministic and simple
Edge-case handling and expected outcomes
Empty tree
new([]) yields root() == None
proof(0) returns None
len() == 0, is_empty() == true
Single-leaf tree
root equals hash_leaf(item)
proof is empty, verification succeeds for correct leaf/index
Two-leaf tree
root equals hash_parent(leaf0, leaf1)
each leaf proof has one sibling with correct Side
Odd number of leaves
duplicate the final leaf hash when building each parent level
proof generation must use the same duplicate rule
Duplicate leaf values
same hash values, but proof.leaf_index disambiguates position
proofs verify by index, not just hash uniqueness
Invalid proof index
proof returns None for out-of-range index
verify_proof returns false if proof index does not match provided index
Modified leaf data
verification false because leaf hash differs
Modified proof sibling hash or position
verification false due to mismatched recomputed path
Modified root hash
verification false because final hash does not equal expected root
Large input set
build a tree with 1,000+ leaves
generate and verify at least one proof successfully
Testing plan
Unit tests for API and helper correctness
Required tests:
empty_tree_has_no_root
single_leaf_root_is_leaf_hash
two_leaf_tree_root_is_parent_hash
odd_leaf_count_is_handled_deterministically
proof_verifies_for_each_leaf
proof_fails_for_wrong_leaf
proof_fails_for_wrong_index
proof_fails_for_wrong_root
proof_fails_when_proof_is_tampered
duplicate_values_can_still_be_proven_by_index
large_tree_builds_and_verifies
Integration tests in tests/ can validate public API end-to-end
Optional tests if time permits:
property-based tests using proptest
serialization tests if serde support is added
hex encoding helpers tests
Documentation and review polish
README.md sections:
Build
Test
Example usage
Design decisions
Hashing
Odd leaf handling
Empty tree handling
Assumptions / limitations
AI tool usage disclosure
Add a short example showing MerkleTree::new, root, proof, and verify_proof
Mention the chosen deterministic odd-leaf strategy explicitly
Confirm final commands:
cargo fmt
cargo clippy
cargo test
Relevant files

Cargo.toml
src/lib.rs
tests/ folder
README.md
Verification

cargo test
cargo fmt -- --check
cargo clippy -- -D warnings
Review README for completeness and honesty about AI assistance
Decisions

Use an explicit domain-separated SHA-256 hash scheme.
Handle odd leaf counts by duplicating the last node at each level.
Store all tree levels in MerkleTree for simple proof generation.
Keep proofs explicit with leaf_index and sibling_positions.
Return Option for root and proof, bool for verification.
Further considerations

If time remains, add a Result-based verify_proof with error types.
If memory is a concern, consider a minimal representation for large trees later.
If tests are complete, add proptest for randomized proof validation.