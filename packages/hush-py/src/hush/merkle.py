"""RFC 6962-compatible Merkle tree implementation.

This module implements Certificate Transparency style Merkle trees:
- LeafHash(data) = SHA256(0x00 || data)
- NodeHash(left, right) = SHA256(0x01 || left || right)

The tree uses left-balanced semantics (odd node carried upward unchanged).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .core import sha256


def hash_leaf(data: bytes) -> bytes:
    """Hash a leaf node per RFC 6962: SHA256(0x00 || data).

    Args:
        data: Raw leaf data bytes

    Returns:
        32-byte leaf hash
    """
    return sha256(b'\x00' + data)
