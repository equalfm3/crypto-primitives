"""AES block cipher modes: ECB, CBC, CTR, and GCM.

Implements standard block cipher modes of operation with PKCS#7 padding
for ECB/CBC and authenticated encryption for GCM.
"""

import os
import struct
from typing import Tuple

from src.symmetric.aes_core import aes_encrypt_block, aes_decrypt_block
from src.symmetric.key_schedule import expand_key
from src.symmetric.galois import gf_mul_128

BLOCK_SIZE: int = 16


def _pkcs7_pad(data: bytes) -> bytes:
    """Apply PKCS#7 padding to make data a multiple of BLOCK_SIZE."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding. Raises ValueError on invalid padding."""
    if not data:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError(f"Invalid padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-ECB mode.

    Args:
        plaintext: Data to encrypt.
        key: AES key (16, 24, or 32 bytes).

    Returns:
        Ciphertext.
    """
    round_keys = expand_key(key)
    padded = _pkcs7_pad(plaintext)
    ct = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        ct.extend(aes_encrypt_block(padded[i:i + BLOCK_SIZE], round_keys))
    return bytes(ct)


def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt with AES-ECB mode.

    Args:
        ciphertext: Data to decrypt (must be multiple of block size).
        key: AES key (16, 24, or 32 bytes).

    Returns:
        Decrypted plaintext.
    """
    round_keys = expand_key(key)
    pt = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        pt.extend(aes_decrypt_block(ciphertext[i:i + BLOCK_SIZE], round_keys))
    return _pkcs7_unpad(bytes(pt))


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt with AES-CBC mode.

    Args:
        plaintext: Data to encrypt.
        key: AES key (16, 24, or 32 bytes).
        iv: 16-byte initialization vector.

    Returns:
        Ciphertext.
    """
    round_keys = expand_key(key)
    padded = _pkcs7_pad(plaintext)
    prev = iv
    ct = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        block = _xor_bytes(padded[i:i + BLOCK_SIZE], prev)
        encrypted = aes_encrypt_block(block, round_keys)
        ct.extend(encrypted)
        prev = encrypted
    return bytes(ct)


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt with AES-CBC mode.

    Args:
        ciphertext: Data to decrypt.
        key: AES key (16, 24, or 32 bytes).
        iv: 16-byte initialization vector.

    Returns:
        Decrypted plaintext.
    """
    round_keys = expand_key(key)
    prev = iv
    pt = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted = aes_decrypt_block(block, round_keys)
        pt.extend(_xor_bytes(decrypted, prev))
        prev = block
    return _pkcs7_unpad(bytes(pt))


def ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt (or decrypt) with AES-CTR mode.

    Args:
        plaintext: Data to encrypt/decrypt.
        key: AES key (16, 24, or 32 bytes).
        nonce: 8-byte nonce (counter starts at 0).

    Returns:
        Ciphertext (same length as plaintext).
    """
    round_keys = expand_key(key)
    result = bytearray()
    counter = 0
    for i in range(0, len(plaintext), BLOCK_SIZE):
        ctr_block = nonce[:8] + struct.pack(">Q", counter)
        keystream = aes_encrypt_block(ctr_block, round_keys)
        chunk = plaintext[i:i + BLOCK_SIZE]
        result.extend(_xor_bytes(chunk, keystream[:len(chunk)]))
        counter += 1
    return bytes(result)


# CTR decrypt is identical to encrypt
ctr_decrypt = ctr_encrypt


def _ghash(h_key: int, aad: bytes, ciphertext: bytes) -> bytes:
    """Compute GHASH for GCM authentication.

    Args:
        h_key: Hash subkey as 128-bit integer.
        aad: Additional authenticated data.
        ciphertext: Ciphertext to authenticate.

    Returns:
        16-byte GHASH tag.
    """
    def _pad_to_block(data: bytes) -> bytes:
        r = len(data) % 16
        return data + b'\x00' * (16 - r) if r else data

    tag = 0
    # Process AAD
    padded_aad = _pad_to_block(aad)
    for i in range(0, len(padded_aad), 16):
        block = int.from_bytes(padded_aad[i:i + 16], 'big')
        tag = gf_mul_128(tag ^ block, h_key)
    # Process ciphertext
    padded_ct = _pad_to_block(ciphertext)
    for i in range(0, len(padded_ct), 16):
        block = int.from_bytes(padded_ct[i:i + 16], 'big')
        tag = gf_mul_128(tag ^ block, h_key)
    # Length block: len(AAD) || len(CT) in bits
    len_block = (len(aad) * 8 << 64) | (len(ciphertext) * 8)
    tag = gf_mul_128(tag ^ len_block, h_key)
    return tag.to_bytes(16, 'big')


def gcm_encrypt(
    plaintext: bytes, key: bytes, iv: bytes, aad: bytes = b""
) -> Tuple[bytes, bytes]:
    """Encrypt with AES-GCM (authenticated encryption).

    Args:
        plaintext: Data to encrypt.
        key: AES key (16, 24, or 32 bytes).
        iv: 12-byte initialization vector.
        aad: Additional authenticated data.

    Returns:
        Tuple of (ciphertext, 16-byte authentication tag).
    """
    round_keys = expand_key(key)
    # Compute hash subkey H = AES(K, 0^128)
    h_bytes = aes_encrypt_block(b'\x00' * 16, round_keys)
    h_key = int.from_bytes(h_bytes, 'big')
    # Initial counter J0
    j0 = iv[:12] + b'\x00\x00\x00\x01'
    # Encrypt plaintext with CTR starting at J0 + 1
    ct = bytearray()
    counter = 2
    for i in range(0, len(plaintext), BLOCK_SIZE):
        ctr_block = iv[:12] + struct.pack(">I", counter)
        keystream = aes_encrypt_block(ctr_block, round_keys)
        chunk = plaintext[i:i + BLOCK_SIZE]
        ct.extend(_xor_bytes(chunk, keystream[:len(chunk)]))
        counter += 1
    ciphertext = bytes(ct)
    # Compute GHASH
    ghash_val = _ghash(h_key, aad, ciphertext)
    # Tag = GHASH XOR AES(K, J0)
    j0_enc = aes_encrypt_block(j0, round_keys)
    tag = _xor_bytes(ghash_val, j0_enc)
    return ciphertext, tag


def gcm_decrypt(
    ciphertext: bytes, key: bytes, iv: bytes, tag: bytes, aad: bytes = b""
) -> bytes:
    """Decrypt with AES-GCM. Raises ValueError if authentication fails."""
    round_keys = expand_key(key)
    h_bytes = aes_encrypt_block(b'\x00' * 16, round_keys)
    h_key = int.from_bytes(h_bytes, 'big')
    j0 = iv[:12] + b'\x00\x00\x00\x01'
    # Verify tag
    ghash_val = _ghash(h_key, aad, ciphertext)
    j0_enc = aes_encrypt_block(j0, round_keys)
    expected_tag = _xor_bytes(ghash_val, j0_enc)
    if expected_tag != tag:
        raise ValueError("GCM authentication failed")
    # Decrypt
    pt = bytearray()
    counter = 2
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        ctr_block = iv[:12] + struct.pack(">I", counter)
        keystream = aes_encrypt_block(ctr_block, round_keys)
        chunk = ciphertext[i:i + BLOCK_SIZE]
        pt.extend(_xor_bytes(chunk, keystream[:len(chunk)]))
        counter += 1
    return bytes(pt)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AES block cipher modes demo")
    parser.add_argument("--mode", choices=["ecb", "cbc", "ctr", "gcm"], default="cbc")
    parser.add_argument("--key-size", type=int, choices=[128, 192, 256], default=128)
    parser.add_argument("--plaintext", default="Hello, World!")
    args = parser.parse_args()

    key = os.urandom(args.key_size // 8)
    pt = args.plaintext.encode()
    print(f"Mode: {args.mode.upper()}, Key size: {args.key_size}")
    print(f"Plaintext: {args.plaintext}")

    if args.mode == "ecb":
        ct = ecb_encrypt(pt, key)
        dt = ecb_decrypt(ct, key)
    elif args.mode == "cbc":
        iv = os.urandom(16)
        ct = cbc_encrypt(pt, key, iv)
        dt = cbc_decrypt(ct, key, iv)
    elif args.mode == "ctr":
        nonce = os.urandom(8)
        ct = ctr_encrypt(pt, key, nonce)
        dt = ctr_decrypt(ct, key, nonce)
    else:
        iv = os.urandom(12)
        ct, tag = gcm_encrypt(pt, key, iv, aad=b"metadata")
        dt = gcm_decrypt(ct, key, iv, tag, aad=b"metadata")
        print(f"Auth tag:   {tag.hex()}")

    print(f"Ciphertext: {ct.hex()}")
    print(f"Decrypted:  {dt.decode()}")
    print(f"Match: {pt == dt}")
