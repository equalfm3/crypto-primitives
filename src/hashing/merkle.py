"""Merkle tree for data integrity verification.

Builds a binary hash tree from data blocks using SHA-256, enabling
efficient proof of inclusion for any individual block.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from src.hashing.sha256 import sha256


@dataclass
class MerkleNode:
    """A node in the Merkle tree.

    Attributes:
        hash_val: SHA-256 hash of this node.
        left: Left child node.
        right: Right child node.
    """
    hash_val: bytes
    left: Optional["MerkleNode"] = None
    right: Optional["MerkleNode"] = None


@dataclass
class MerkleProof:
    """Proof of inclusion for a leaf in the Merkle tree.

    Attributes:
        leaf_hash: Hash of the leaf being proved.
        siblings: List of (hash, direction) pairs from leaf to root.
            direction is 'left' if sibling is on the left, 'right' if on the right.
    """
    leaf_hash: bytes
    siblings: List[Tuple[bytes, str]] = field(default_factory=list)


class MerkleTree:
    """Binary Merkle tree using SHA-256.

    Builds a complete binary tree from data blocks. If the number of leaves
    is odd, the last leaf is duplicated to make it even.

    Attributes:
        root: Root node of the tree.
        leaves: List of leaf nodes.
    """

    def __init__(self, data_blocks: List[bytes]) -> None:
        """Build a Merkle tree from data blocks.

        Args:
            data_blocks: List of data blocks to include in the tree.

        Raises:
            ValueError: If no data blocks are provided.
        """
        if not data_blocks:
            raise ValueError("At least one data block is required")
        self.leaves: List[MerkleNode] = [
            MerkleNode(hash_val=sha256(block)) for block in data_blocks
        ]
        self.root: MerkleNode = self._build_tree(self.leaves)

    def _build_tree(self, nodes: List[MerkleNode]) -> MerkleNode:
        """Recursively build the tree from a list of nodes.

        Args:
            nodes: Current level of nodes.

        Returns:
            Root node of the subtree.
        """
        if len(nodes) == 1:
            return nodes[0]
        # Duplicate last node if odd number
        if len(nodes) % 2 == 1:
            nodes = nodes + [nodes[-1]]
        parents: List[MerkleNode] = []
        for i in range(0, len(nodes), 2):
            combined = nodes[i].hash_val + nodes[i + 1].hash_val
            parent = MerkleNode(
                hash_val=sha256(combined),
                left=nodes[i],
                right=nodes[i + 1],
            )
            parents.append(parent)
        return self._build_tree(parents)

    @property
    def root_hash(self) -> bytes:
        """Get the root hash of the tree."""
        return self.root.hash_val

    def get_proof(self, index: int) -> MerkleProof:
        """Generate a proof of inclusion for the leaf at the given index.

        Args:
            index: Index of the leaf (0-based).

        Returns:
            MerkleProof with sibling hashes from leaf to root.

        Raises:
            IndexError: If index is out of range.
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of range [0, {len(self.leaves)})")
        proof = MerkleProof(leaf_hash=self.leaves[index].hash_val)
        nodes = list(self.leaves)
        # Duplicate last if odd
        if len(nodes) % 2 == 1:
            nodes = nodes + [nodes[-1]]
        idx = index
        while len(nodes) > 1:
            if len(nodes) % 2 == 1:
                nodes = nodes + [nodes[-1]]
            sibling_idx = idx ^ 1  # Toggle last bit to get sibling
            direction = "left" if sibling_idx < idx else "right"
            proof.siblings.append((nodes[sibling_idx].hash_val, direction))
            # Move to parent level
            next_nodes: List[MerkleNode] = []
            for i in range(0, len(nodes), 2):
                combined = nodes[i].hash_val + nodes[i + 1].hash_val
                next_nodes.append(MerkleNode(hash_val=sha256(combined)))
            nodes = next_nodes
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(proof: MerkleProof, root_hash: bytes) -> bool:
        """Verify a Merkle proof against a known root hash.

        Args:
            proof: The inclusion proof to verify.
            root_hash: Expected root hash.

        Returns:
            True if the proof is valid.
        """
        current = proof.leaf_hash
        for sibling_hash, direction in proof.siblings:
            if direction == "left":
                current = sha256(sibling_hash + current)
            else:
                current = sha256(current + sibling_hash)
        return current == root_hash


if __name__ == "__main__":
    print("=== Merkle Tree Demo ===")
    blocks = [f"block-{i}".encode() for i in range(8)]
    tree = MerkleTree(blocks)
    print(f"Root hash: {tree.root_hash.hex()}")
    print(f"Leaves:    {len(tree.leaves)}")

    # Generate and verify proof for block 3
    proof = tree.get_proof(3)
    valid = MerkleTree.verify_proof(proof, tree.root_hash)
    print(f"\nProof for block 3:")
    print(f"  Leaf hash: {proof.leaf_hash.hex()[:32]}...")
    print(f"  Siblings:  {len(proof.siblings)}")
    print(f"  Valid:     {valid}")

    # Tamper detection
    tampered_proof = MerkleProof(
        leaf_hash=sha256(b"tampered"),
        siblings=proof.siblings,
    )
    print(f"  Tampered:  {MerkleTree.verify_proof(tampered_proof, tree.root_hash)}")
