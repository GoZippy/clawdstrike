"""Tests for RFC 6962-compatible Merkle tree implementation."""
import pytest


def test_hash_leaf_produces_32_bytes():
    """Leaf hash should be 32 bytes with 0x00 prefix."""
    from hush.merkle import hash_leaf

    result = hash_leaf(b"hello")
    assert isinstance(result, bytes)
    assert len(result) == 32
