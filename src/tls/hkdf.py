"""HKDF: HMAC-based Key Derivation Function (RFC 5869).

Implements HKDF-Extract and HKDF-Expand for deriving cryptographic
keys from input keying material, used in TLS 1.3 key schedule.
"""

import struct
from typing import Optional

from src.hashing.hmac import hmac_sha256
from src.hashing.sha256 import sha256

HASH_LEN: int = 32  # SHA-256 output length


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: derive a pseudorandom key from input keying material.

    PRK = HMAC-Hash(salt, IKM)

    Args:
        salt: Optional salt value (if empty, uses zero-filled hash-length bytes).
        ikm: Input keying material.

    Returns:
        Pseudorandom key (32 bytes for SHA-256).
    """
    if not salt:
        salt = b'\x00' * HASH_LEN
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: expand a pseudorandom key to the desired length.

    OKM = T(1) || T(2) || ... where T(i) = HMAC-Hash(PRK, T(i-1) || info || i)

    Args:
        prk: Pseudorandom key (from HKDF-Extract).
        info: Context and application-specific information.
        length: Desired output length in bytes (max 255 * HASH_LEN).

    Returns:
        Output keying material of the specified length.

    Raises:
        ValueError: If requested length exceeds maximum.
    """
    max_length = 255 * HASH_LEN
    if length > max_length:
        raise ValueError(f"Requested length {length} exceeds max {max_length}")

    n = (length + HASH_LEN - 1) // HASH_LEN
    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm.extend(t)
    return bytes(okm[:length])


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Full HKDF: Extract-then-Expand.

    Args:
        ikm: Input keying material.
        salt: Salt value.
        info: Context information.
        length: Desired output length.

    Returns:
        Derived key material.
    """
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


def hkdf_expand_label(
    secret: bytes, label: str, context: bytes, length: int
) -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1).

    Derives keys using TLS 1.3 label format:
    HKDF-Expand(Secret, HkdfLabel, Length) where
    HkdfLabel = length || "tls13 " || label || context

    Args:
        secret: Input secret.
        label: TLS label string (without "tls13 " prefix).
        context: Hash of handshake context (or empty).
        length: Desired output length.

    Returns:
        Derived key material.
    """
    full_label = b"tls13 " + label.encode()
    # HkdfLabel structure
    hkdf_label = (
        struct.pack(">H", length)
        + bytes([len(full_label)]) + full_label
        + bytes([len(context)]) + context
    )
    return hkdf_expand(secret, hkdf_label, length)


def derive_secret(secret: bytes, label: str, messages: bytes) -> bytes:
    """TLS 1.3 Derive-Secret (RFC 8446 Section 7.1).

    Derive-Secret(Secret, Label, Messages) =
        HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)

    Args:
        secret: Input secret.
        label: Derivation label.
        messages: Concatenated handshake messages.

    Returns:
        32-byte derived secret.
    """
    transcript_hash = sha256(messages)
    return hkdf_expand_label(secret, label, transcript_hash, HASH_LEN)


if __name__ == "__main__":
    print("=== HKDF Demo ===")
    # RFC 5869 Test Vector 1
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")

    prk = hkdf_extract(salt, ikm)
    print(f"PRK:    {prk.hex()}")
    expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    print(f"Match:  {prk.hex() == expected_prk}")

    okm = hkdf_expand(prk, info, 42)
    print(f"OKM:    {okm.hex()}")
    expected_okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    print(f"Match:  {okm.hex() == expected_okm}")

    # TLS 1.3 style derivation
    secret = bytes(32)
    derived = hkdf_expand_label(secret, "derived", sha256(b""), 32)
    print(f"\nTLS derived: {derived.hex()[:32]}...")
