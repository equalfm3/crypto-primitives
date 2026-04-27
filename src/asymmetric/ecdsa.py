"""ECDSA (Elliptic Curve Digital Signature Algorithm) on secp256k1.

Implements ECDSA signing and verification using the secp256k1 curve.
Signing requires a random nonce k; nonce reuse is catastrophic for security.
"""

import os
from dataclasses import dataclass
from typing import Tuple

from src.asymmetric.elliptic_curve import (
    Point, G, N, scalar_multiply, point_add, point_from_private_key,
)
from src.hashing.sha256 import sha256


@dataclass
class ECDSASignature:
    """An ECDSA signature (r, s).

    Attributes:
        r: X-coordinate of kG mod n.
        s: k^(-1) * (hash + r*d) mod n.
    """
    r: int
    s: int


@dataclass
class ECDSAKeyPair:
    """ECDSA key pair.

    Attributes:
        private_key: Secret scalar d in [1, N-1].
        public_key: Public point Q = d*G.
    """
    private_key: int
    public_key: Point


def generate_keypair() -> ECDSAKeyPair:
    """Generate a random ECDSA key pair on secp256k1.

    Returns:
        ECDSAKeyPair with private key and corresponding public key.
    """
    # Generate random private key in [1, N-1]
    while True:
        d = int.from_bytes(os.urandom(32), "big")
        if 1 <= d < N:
            break
    q = point_from_private_key(d)
    return ECDSAKeyPair(private_key=d, public_key=q)


def _hash_to_int(message: bytes) -> int:
    """Hash a message and convert to integer for signing.

    Args:
        message: Message bytes to hash.

    Returns:
        Integer representation of the SHA-256 hash, reduced mod N.
    """
    h = sha256(message)
    z = int.from_bytes(h, "big")
    # Truncate to bit length of N if hash is longer
    bit_len = N.bit_length()
    if z.bit_length() > bit_len:
        z >>= z.bit_length() - bit_len
    return z


def sign(message: bytes, private_key: int, k: int = 0) -> ECDSASignature:
    """Sign a message with ECDSA.

    Args:
        message: Message to sign.
        private_key: Private key scalar d.
        k: Nonce (if 0, generated randomly). WARNING: nonce reuse
           with different messages reveals the private key.

    Returns:
        ECDSASignature(r, s).

    Raises:
        ValueError: If signing fails (degenerate nonce).
    """
    z = _hash_to_int(message)

    while True:
        if k == 0:
            k_val = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
        else:
            k_val = k

        # R = k * G
        r_point = scalar_multiply(k_val, G)
        assert r_point.x is not None
        r = r_point.x % N
        if r == 0:
            k = 0
            continue

        # s = k^(-1) * (z + r*d) mod n
        k_inv = pow(k_val, N - 2, N)
        s = (k_inv * (z + r * private_key)) % N
        if s == 0:
            k = 0
            continue

        return ECDSASignature(r=r, s=s)


def verify(message: bytes, signature: ECDSASignature, public_key: Point) -> bool:
    """Verify an ECDSA signature.

    Args:
        message: Original message.
        signature: Signature (r, s) to verify.
        public_key: Signer's public key point Q.

    Returns:
        True if the signature is valid.
    """
    r, s = signature.r, signature.s

    # Check r, s are in [1, N-1]
    if not (1 <= r < N and 1 <= s < N):
        return False

    z = _hash_to_int(message)

    # w = s^(-1) mod n
    w = pow(s, N - 2, N)

    # u1 = z * w mod n, u2 = r * w mod n
    u1 = (z * w) % N
    u2 = (r * w) % N

    # R' = u1*G + u2*Q
    p1 = scalar_multiply(u1, G)
    p2 = scalar_multiply(u2, public_key)
    r_prime = point_add(p1, p2)

    if r_prime.is_infinity:
        return False

    assert r_prime.x is not None
    return r_prime.x % N == r


if __name__ == "__main__":
    print("=== ECDSA on secp256k1 Demo ===")
    kp = generate_keypair()
    print(f"Private key: {hex(kp.private_key)[:24]}...")
    print(f"Public key on curve: {kp.public_key.is_on_curve()}")

    msg = b"Hello, ECDSA!"
    sig = sign(msg, kp.private_key)
    print(f"\nMessage: {msg.decode()}")
    print(f"Signature r: {hex(sig.r)[:24]}...")
    print(f"Signature s: {hex(sig.s)[:24]}...")

    valid = verify(msg, sig, kp.public_key)
    print(f"Valid: {valid}")

    tampered = verify(b"Tampered!", sig, kp.public_key)
    print(f"Tampered: {tampered}")

    # Verify with wrong key
    other_kp = generate_keypair()
    wrong_key = verify(msg, sig, other_kp.public_key)
    print(f"Wrong key: {wrong_key}")
