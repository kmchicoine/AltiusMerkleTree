use altius_merkle_tree::MerkleTree;
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_every_leaf_proof_validates(
        items in prop::collection::vec("[a-z0-9]{1,20}", 1..100)
    ) {
        let tree = MerkleTree::new(&items);
        let root = tree.root().expect("Non-empty tree should have root");

        for (idx, item) in items.iter().enumerate() {
            let proof = tree.proof(idx).expect("Valid index should produce proof");
            prop_assert!(
                MerkleTree::verify_proof(item.as_str(), idx, &proof, root),
                "Proof for leaf {} should verify", idx
            );
        }
    }

    #[test]
    fn prop_wrong_leaf_value_fails_verification(
        items in prop::collection::vec("[a-z0-9]{1,20}", 1..100),
        wrong_item in "[a-z0-9]{1,20}"
    ) {
        let tree = MerkleTree::new(&items);
        let root = tree.root().expect("Non-empty tree should have root");

        // Only test if wrong_item is actually different from the leaf
        if items.len() > 0 && wrong_item != items[0] {
            let proof = tree.proof(0).expect("Index 0 is valid");
            prop_assert!(
                !MerkleTree::verify_proof(&wrong_item, 0, &proof, root),
                "Proof with wrong leaf value should not verify"
            );
        }
    }

    #[test]
    fn prop_tree_consistency_across_rebuilds(
        items in prop::collection::vec("[a-z0-9]{1,20}", 1..50)
    ) {
        let tree1 = MerkleTree::new(&items);
        let tree2 = MerkleTree::new(&items);

        prop_assert_eq!(tree1.root(), tree2.root(), "Same items should produce same root");
        prop_assert_eq!(tree1.leaf_count(), tree2.leaf_count());

        for idx in 0..items.len() {
            let proof1 = tree1.proof(idx).expect("Valid index");
            let proof2 = tree2.proof(idx).expect("Valid index");

            prop_assert_eq!(proof1.siblings.len(), proof2.siblings.len());
            for (s1, s2) in proof1.siblings.iter().zip(proof2.siblings.iter()) {
                prop_assert_eq!(s1, s2);
            }
        }
    }

    #[test]
    fn prop_proof_independence(
        items in prop::collection::vec("[a-z0-9]{1,20}", 2..50)
    ) {
        let tree = MerkleTree::new(&items);
        let root = tree.root().expect("Non-empty tree should have root");

        // Test that proof for one index doesn't verify with a different leaf value
        if items.len() > 1 {
            let proof0 = tree.proof(0).expect("Valid index");
            let proof1 = tree.proof(1).expect("Valid index");

            // If items[0] and items[1] are different, proof0 should not verify with items[1]
            if items[0] != items[1] {
                prop_assert!(
                    !MerkleTree::verify_proof(items[1].as_str(), 0, &proof0, root),
                    "Proof for leaf 0 should not verify with different leaf value"
                );
                prop_assert!(
                    !MerkleTree::verify_proof(items[0].as_str(), 1, &proof1, root),
                    "Proof for leaf 1 should not verify with different leaf value"
                );
            }
        }
    }

    #[test]
    fn prop_random_array_sizes(
        items in prop::collection::vec("[a-z0-9]{1,10}", 1..200)
    ) {
        let tree = MerkleTree::new(&items);

        prop_assert_eq!(tree.leaf_count(), items.len());

        if !items.is_empty() {
            let root = tree.root().expect("Non-empty tree should have root");

            // Verify a few random proofs
            for idx in 0..std::cmp::min(5, items.len()) {
                let proof = tree.proof(idx).expect("Valid index");
                prop_assert!(
                    MerkleTree::verify_proof(items[idx].as_str(), idx, &proof, root),
                    "Proof at index {} should verify", idx
                );
            }
        }
    }
}
