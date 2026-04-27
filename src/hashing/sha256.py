"""SHA-256 cryptographic hash function.

Implements the SHA-256 algorithm per FIPS 180-4: message padding,
message schedule expansion, and 64-round compression function.
"""

import struct
from typing import List

# First 32 bits of fractional parts of cube roots of first 64 primes
K: List[int] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

# Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
H0: List[int] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

MASK32: int = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    """32-bit right rotation."""
    return ((x >> n) | (x << (32 - n))) & MASK32


def _sigma0(x: int) -> int:
    """Lowercase sigma_0 for message schedule."""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _sigma1(x: int) -> int:
    """Lowercase sigma_1 for message schedule."""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def _big_sigma0(x: int) -> int:
    """Uppercase Sigma_0 for compression."""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _big_sigma1(x: int) -> int:
    """Uppercase Sigma_1 for compression."""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _ch(e: int, f: int, g: int) -> int:
    """Choice function: Ch(e, f, g) = (e AND f) XOR (NOT e AND g)."""
    return (e & f) ^ (~e & g) & MASK32


def _maj(a: int, b: int, c: int) -> int:
    """Majority function: Maj(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)."""
    return (a & b) ^ (a & c) ^ (b & c)


def _pad_message(message: bytes) -> bytes:
    """Pad message to multiple of 512 bits per SHA-256 spec.

    Appends bit '1', then zeros, then 64-bit big-endian length.

    Args:
        message: Input message bytes.

    Returns:
        Padded message (length is multiple of 64 bytes).
    """
    msg_len = len(message)
    bit_len = msg_len * 8
    # Append 0x80 byte
    message += b'\x80'
    # Pad with zeros until length ≡ 56 (mod 64)
    while len(message) % 64 != 56:
        message += b'\x00'
    # Append original length as 64-bit big-endian
    message += struct.pack(">Q", bit_len)
    return message


def sha256(message: bytes) -> bytes:
    """Compute SHA-256 hash of a message.

    Args:
        message: Input bytes to hash.

    Returns:
        32-byte (256-bit) digest.
    """
    padded = _pad_message(message)
    h = list(H0)

    # Process each 512-bit (64-byte) block
    for block_start in range(0, len(padded), 64):
        block = padded[block_start:block_start + 64]

        # Prepare message schedule W
        w: List[int] = list(struct.unpack(">16I", block))
        for t in range(16, 64):
            w.append((_sigma1(w[t - 2]) + w[t - 7] +
                       _sigma0(w[t - 15]) + w[t - 16]) & MASK32)

        # Initialize working variables
        a, b, c, d, e, f, g, hh = h

        # 64 compression rounds
        for t in range(64):
            t1 = (hh + _big_sigma1(e) + _ch(e, f, g) + K[t] + w[t]) & MASK32
            t2 = (_big_sigma0(a) + _maj(a, b, c)) & MASK32
            hh = g
            g = f
            f = e
            e = (d + t1) & MASK32
            d = c
            c = b
            b = a
            a = (t1 + t2) & MASK32

        # Add compressed chunk to hash value
        vals = [a, b, c, d, e, f, g, hh]
        h = [(h[i] + vals[i]) & MASK32 for i in range(8)]

    return struct.pack(">8I", *h)


def sha256_hex(message: bytes) -> str:
    """Compute SHA-256 hash and return as hex string.

    Args:
        message: Input bytes to hash.

    Returns:
        64-character hex digest string.
    """
    return sha256(message).hex()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SHA-256 hash")
    parser.add_argument("--input", help="File to hash")
    parser.add_argument("--text", help="Text to hash")
    args = parser.parse_args()

    if args.input:
        with open(args.input, "rb") as f:
            data = f.read()
        print(f"SHA-256({args.input}): {sha256_hex(data)}")
    else:
        text = (args.text or "Hello, World!").encode()
        digest = sha256_hex(text)
        print(f"SHA-256('{text.decode()}'): {digest}")
        # Verify against known test vectors
        empty_hash = sha256_hex(b"")
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        print(f"SHA-256(''): {empty_hash}")
        print(f"Match empty: {empty_hash == expected}")
