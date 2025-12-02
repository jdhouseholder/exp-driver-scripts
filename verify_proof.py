from typing import List, Optional, Tuple
import rlp
from Crypto.Hash import keccak

# This is the RLP hash of an empty trie.
EMPTY_TRIE_ROOT = keccak.new(digest_bits=256, data=rlp.encode(b"")).digest()


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def bytes_to_nibbles(b: bytes) -> List[int]:
    # Convert bytes to a list of nibbles (4-bit values)
    n = []
    for byte in b:
        n.append((byte >> 4) & 0xF)
        n.append(byte & 0xF)
    return n


def compact_decode_path(encoded: bytes) -> Tuple[List[int], bool]:
    """
    Decode the compact-encoded path for leaf/extension nodes.
    Returns (nibbles, is_leaf).
    See Ethereum's hex prefix encoding:
      flags nibble = (is_leaf ? 2 : 0) | (is_odd ? 1 : 0)
    If odd, the next nibble is part of the key; if even, one filler nibble (0) follows.
    """
    nibbles = bytes_to_nibbles(encoded)
    if not nibbles:
        # This should not happen for valid MPT nodes, but handle defensively.
        return [], False
    flags = nibbles[0]
    is_leaf = (flags & 2) != 0
    odd = (flags & 1) != 0
    if odd:
        path = nibbles[1:]
    else:
        # skip filler nibble too
        path = nibbles[2:]
    return path, is_leaf


def shared_prefix_len(a: List[int], b: List[int]) -> int:
    i = 0
    m = min(len(a), len(b))
    while i < m and a[i] == b[i]:
        i += 1
    return i


def verify_eth_trie_proof(
    root_hash: bytes,
    key: bytes,
    proof_nodes: List[bytes],
) -> Optional[bytes]:
    """
    Verify an Ethereum MPT proof against the given root hash and key.
    - root_hash: 32-byte trie root hash OR short, RLP-encoded root node (<32 bytes)
    - key: bytes of the trie key (for state: keccak(address), for storage: keccak(slot))
    - proof_nodes: list of RLP-encoded nodes (bytes)

    Returns:
      - value (bytes) if the key exists in the trie (can be b'' for an empty value)
      - None if the key is not present
    Raises:
      - ValueError on invalid proof (missing nodes, wrong structure, hash mismatch)
    """

    # 1. Handle the special case of an empty trie.
    if root_hash == EMPTY_TRIE_ROOT:
        return None  # Key not in empty trie

    # Build proof database: hash -> node_bytes
    proof_db = {}
    for node_bytes in proof_nodes:
        h = keccak256(node_bytes)
        proof_db[h] = node_bytes

    key_nibbles = bytes_to_nibbles(key)
    current_node_ref = root_hash

    # Traverse
    while True:
        # Determine the current node's RLP data.
        # If the ref is < 32 bytes, it's an embedded node.
        # If the ref is 32 bytes, it's a hash to look up in the proof DB.
        if len(current_node_ref) < 32:
            node_bytes = current_node_ref
            # Embedded nodes must still be present in the proof set for completeness.
            if node_bytes not in proof_nodes:
                raise ValueError("Proof is missing an embedded node")
        else:
            node_bytes = proof_db.get(current_node_ref)
            if node_bytes is None:
                raise ValueError(
                    f"Proof is missing node for hash {current_node_ref.hex()}"
                )
            # Sanity check that the provided node matches the hash we are looking for.
            if keccak256(node_bytes) != current_node_ref:
                raise ValueError("Node hash mismatch in proof")

        node = rlp.decode(node_bytes)

        if not isinstance(node, list):
            # This should not happen for valid nodes (branch, leaf, extension).
            raise ValueError(f"Invalid node type: expected list, got {type(node)}")

        # --- BRANCH NODE ---
        if len(node) == 17:
            if len(key_nibbles) == 0:
                # We've consumed the key, the value is in the 17th slot.
                val = node[16]
                if not isinstance(val, (bytes, bytearray)):
                    raise ValueError("Branch node value is not bytes")
                # BUG FIX: Return the value, even if it's empty (b'').
                return val

            # Select child by next nibble
            nib = key_nibbles[0]
            key_nibbles = key_nibbles[1:]
            current_node_ref = node[nib]
            if len(current_node_ref) == 0:
                # No child at this path -> key not in trie
                return None
            continue  # Continue traversal with the new node reference

        # --- LEAF / EXTENSION NODE ---
        elif len(node) == 2:
            path_enc, child_or_value = node[1] if isinstance(node[0], list) else node
            if not isinstance(path_enc, (bytes, bytearray)):
                raise ValueError("Short node path is not bytes")
            path_nibbles, is_leaf = compact_decode_path(path_enc)

            cp = shared_prefix_len(path_nibbles, key_nibbles)

            if is_leaf:
                # Leaf must match the remaining key exactly
                if cp == len(path_nibbles) and cp == len(key_nibbles):
                    if not isinstance(child_or_value, (bytes, bytearray)):
                        raise ValueError("Leaf value is not bytes")
                    return child_or_value
                else:
                    return None  # Key does not match leaf path
            else:  # Extension Node
                # Extension path must be a full prefix of the remaining key
                if cp != len(path_nibbles):
                    return None  # Key diverges from extension path
                key_nibbles = key_nibbles[cp:]
                current_node_ref = child_or_value
                continue  # Continue traversal with the new node reference
        else:
            raise ValueError(f"Invalid node list length: {len(node)}")
