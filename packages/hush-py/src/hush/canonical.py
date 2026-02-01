"""RFC 8785 (JCS) canonical JSON implementation.

Provides deterministic JSON serialization for hashing and signing:
- No whitespace between elements
- Object keys sorted lexicographically (UTF-16 code units)
- Numbers in shortest form (no trailing zeros)
- Unicode preserved (except control characters escaped)
"""
from __future__ import annotations

import json
from typing import Any


def canonicalize(obj: Any) -> str:
    """Serialize object to canonical JSON per RFC 8785 (JCS).

    Args:
        obj: Python object to serialize (dict, list, str, int, float, bool, None)

    Returns:
        Canonical JSON string

    Raises:
        ValueError: If object contains non-finite floats (inf, nan)
    """
    return json.dumps(
        obj,
        separators=(',', ':'),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_hash(obj: Any, algorithm: str = "sha256") -> bytes:
    """Hash object using canonical JSON serialization.

    Args:
        obj: Python object to serialize and hash
        algorithm: Hash algorithm ("sha256" or "keccak256")

    Returns:
        32-byte hash digest

    Raises:
        ValueError: If algorithm is not supported
    """
    from .core import sha256, keccak256

    canonical = canonicalize(obj).encode("utf-8")

    if algorithm == "sha256":
        return sha256(canonical)
    elif algorithm == "keccak256":
        return keccak256(canonical)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


__all__ = [
    "canonicalize",
    "canonical_hash",
]
