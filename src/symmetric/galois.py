"""GF(2^8) arithmetic for AES MixColumns and GCM GHASH.

Implements multiplication, inversion, and the AES S-box over the Galois field
GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
"""

from typing import List

# AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
AES_POLY: int = 0x11B


def gf_mul(a: int, b: int, poly: int = AES_POLY) -> int:
    """Multiply two elements in GF(2^8) using Russian peasant algorithm.

    Args:
        a: First operand (0-255).
        b: Second operand (0-255).
        poly: Irreducible polynomial for reduction.

    Returns:
        Product a * b in GF(2^8).
    """
    result = 0
    a &= 0xFF
    b &= 0xFF
    for _ in range(8):
        if b & 1:
            result ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= poly & 0xFF
        b >>= 1
    return result


def gf_pow(a: int, exp: int) -> int:
    """Raise element a to power exp in GF(2^8).

    Args:
        a: Base element (0-255).
        exp: Non-negative exponent.

    Returns:
        a^exp in GF(2^8).
    """
    result = 1
    base = a & 0xFF
    while exp > 0:
        if exp & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exp >>= 1
    return result


def gf_inv(a: int) -> int:
    """Compute multiplicative inverse in GF(2^8) via Fermat's little theorem.

    Uses a^(-1) = a^254 since a^255 = 1 for all nonzero a in GF(2^8).

    Args:
        a: Element to invert (0-255). Returns 0 for input 0.

    Returns:
        Multiplicative inverse of a in GF(2^8).
    """
    if a == 0:
        return 0
    return gf_pow(a, 254)


def _affine_transform(b: int) -> int:
    """Apply the AES affine transformation to a byte.

    Args:
        b: Input byte (0-255).

    Returns:
        Transformed byte.
    """
    result = 0
    for i in range(8):
        bit = (
            ((b >> i) & 1)
            ^ ((b >> ((i + 4) % 8)) & 1)
            ^ ((b >> ((i + 5) % 8)) & 1)
            ^ ((b >> ((i + 6) % 8)) & 1)
            ^ ((b >> ((i + 7) % 8)) & 1)
            ^ ((0x63 >> i) & 1)
        )
        result |= (bit & 1) << i
    return result


def build_sbox() -> List[int]:
    """Build the AES S-box using algebraic construction.

    For each byte, computes the multiplicative inverse in GF(2^8)
    then applies the AES affine transformation.

    Returns:
        List of 256 S-box values.
    """
    sbox = []
    for i in range(256):
        inv = gf_inv(i)
        sbox.append(_affine_transform(inv))
    return sbox


def build_inv_sbox(sbox: List[int]) -> List[int]:
    """Build the inverse S-box from the forward S-box.

    Args:
        sbox: Forward S-box (256 entries).

    Returns:
        Inverse S-box (256 entries).
    """
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox


# Pre-computed S-box and inverse S-box
SBOX: List[int] = build_sbox()
INV_SBOX: List[int] = build_inv_sbox(SBOX)


def gf_mul_128(a: int, b: int) -> int:
    """Multiply two 128-bit elements in GF(2^128) for GCM GHASH.

    Uses the GCM polynomial x^128 + x^7 + x^2 + x + 1.

    Args:
        a: First 128-bit operand.
        b: Second 128-bit operand.

    Returns:
        Product in GF(2^128).
    """
    result = 0
    # GCM reduction polynomial (bit-reflected representation)
    R = 0xE1000000000000000000000000000000
    for i in range(128):
        if (b >> (127 - i)) & 1:
            result ^= a
        carry = a & 1
        a >>= 1
        if carry:
            a ^= R
    return result


if __name__ == "__main__":
    print("=== GF(2^8) Arithmetic Demo ===")
    print(f"gf_mul(0x57, 0x83) = 0x{gf_mul(0x57, 0x83):02X}")
    print(f"gf_inv(0x53) = 0x{gf_inv(0x53):02X}")
    verify = gf_mul(0x53, gf_inv(0x53))
    print(f"0x53 * gf_inv(0x53) = 0x{verify:02X} (should be 0x01)")
    print(f"\nFirst 16 S-box entries: {[f'0x{x:02X}' for x in SBOX[:16]]}")
    print(f"S-box[0x00] = 0x{SBOX[0x00]:02X} (expected 0x63)")
    print(f"S-box[0x01] = 0x{SBOX[0x01]:02X} (expected 0x7C)")
    print(f"INV_SBOX[SBOX[0xAB]] = 0x{INV_SBOX[SBOX[0xAB]]:02X} (expected 0xAB)")
