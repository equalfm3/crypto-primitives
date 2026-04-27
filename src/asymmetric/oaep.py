"""OAEP (Optimal Asymmetric Encryption Padding) for RSA.

Implements RSAES-OAEP encoding and decoding per PKCS#1 v2.2 (RFC 8017)
using SHA-256 as the hash function and MGF1 as the mask generation function.
"""

import os
from typing import Tuple

from src.hashing.sha256 import sha256

HASH_LEN: int = 32  # SHA-256 output length in bytes


def _mgf1(seed: bytes, length: int) -> bytes:
    """MGF1 mask generation function using SHA-256.

    Generates a pseudorandom mask of the specified length from a seed.

    Args:
        seed: Input seed bytes.
        length: Desired output length in bytes.

    Returns:
        Mask bytes of the specified length.
    """
    mask = bytearray()
    counter = 0
    while len(mask) < length:
        c = counter.to_bytes(4, "big")
        mask.extend(sha256(seed + c))
        counter += 1
    return bytes(mask[:length])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def oaep_encode(
    message: bytes, key_len: int, label: bytes = b""
) -> bytes:
    """OAEP encode a message for RSA encryption.

    Args:
        message: Message to encode (must fit within key size constraints).
        key_len: RSA key length in bytes (n_bytes).
        label: Optional label (default empty).

    Returns:
        Encoded message of key_len bytes.

    Raises:
        ValueError: If message is too long for the key size.
    """
    l_hash = sha256(label)
    max_msg_len = key_len - 2 * HASH_LEN - 2
    if len(message) > max_msg_len:
        raise ValueError(
            f"Message too long: {len(message)} > {max_msg_len} bytes"
        )

    # DB = lHash || PS || 0x01 || M
    ps_len = max_msg_len - len(message)
    db = l_hash + b'\x00' * ps_len + b'\x01' + message

    # Generate random seed
    seed = os.urandom(HASH_LEN)

    # Mask DB with MGF1(seed)
    db_mask = _mgf1(seed, len(db))
    masked_db = _xor_bytes(db, db_mask)

    # Mask seed with MGF1(maskedDB)
    seed_mask = _mgf1(masked_db, HASH_LEN)
    masked_seed = _xor_bytes(seed, seed_mask)

    # EM = 0x00 || maskedSeed || maskedDB
    return b'\x00' + masked_seed + masked_db


def oaep_decode(encoded: bytes, label: bytes = b"") -> bytes:
    """OAEP decode an encoded message after RSA decryption.

    Args:
        encoded: Encoded message bytes.
        label: Optional label (must match encoding label).

    Returns:
        Original message bytes.

    Raises:
        ValueError: If decoding fails (invalid padding).
    """
    l_hash = sha256(label)

    if len(encoded) < 2 * HASH_LEN + 2:
        raise ValueError("Encoded message too short")

    if encoded[0] != 0x00:
        raise ValueError("Invalid OAEP encoding (leading byte)")

    masked_seed = encoded[1:1 + HASH_LEN]
    masked_db = encoded[1 + HASH_LEN:]

    # Recover seed
    seed_mask = _mgf1(masked_db, HASH_LEN)
    seed = _xor_bytes(masked_seed, seed_mask)

    # Recover DB
    db_mask = _mgf1(seed, len(masked_db))
    db = _xor_bytes(masked_db, db_mask)

    # Verify lHash
    recovered_l_hash = db[:HASH_LEN]
    if recovered_l_hash != l_hash:
        raise ValueError("OAEP label hash mismatch")

    # Find 0x01 separator
    rest = db[HASH_LEN:]
    sep_idx = -1
    for i, b in enumerate(rest):
        if b == 0x01:
            sep_idx = i
            break
        elif b != 0x00:
            raise ValueError("Invalid OAEP padding")

    if sep_idx == -1:
        raise ValueError("OAEP separator not found")

    return rest[sep_idx + 1:]


def oaep_encode_with_seed(
    message: bytes, key_len: int, seed: bytes, label: bytes = b""
) -> bytes:
    """OAEP encode with a deterministic seed (for testing).

    Args:
        message: Message to encode.
        key_len: RSA key length in bytes.
        seed: 32-byte seed (instead of random).
        label: Optional label.

    Returns:
        Encoded message of key_len bytes.
    """
    l_hash = sha256(label)
    max_msg_len = key_len - 2 * HASH_LEN - 2
    if len(message) > max_msg_len:
        raise ValueError(f"Message too long: {len(message)} > {max_msg_len}")

    ps_len = max_msg_len - len(message)
    db = l_hash + b'\x00' * ps_len + b'\x01' + message
    db_mask = _mgf1(seed, len(db))
    masked_db = _xor_bytes(db, db_mask)
    seed_mask = _mgf1(masked_db, HASH_LEN)
    masked_seed = _xor_bytes(seed, seed_mask)
    return b'\x00' + masked_seed + masked_db


if __name__ == "__main__":
    print("=== OAEP Padding Demo ===")
    msg = b"Hello, OAEP!"
    key_len = 256  # 2048-bit RSA key = 256 bytes

    encoded = oaep_encode(msg, key_len)
    print(f"Message:  {msg.decode()}")
    print(f"Encoded:  {encoded[:32].hex()}... ({len(encoded)} bytes)")

    decoded = oaep_decode(encoded)
    print(f"Decoded:  {decoded.decode()}")
    print(f"Match:    {msg == decoded}")

    # Test with deterministic seed
    seed = bytes(range(32))
    enc1 = oaep_encode_with_seed(msg, key_len, seed)
    enc2 = oaep_encode_with_seed(msg, key_len, seed)
    print(f"\nDeterministic: {enc1 == enc2}")
