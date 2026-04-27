"""ECDHE (Ephemeral Elliptic Curve Diffie-Hellman) key exchange.

Implements ephemeral key agreement using secp256k1 for TLS 1.3.
Both parties generate ephemeral key pairs and derive a shared secret
from the ECDH computation: shared = a * (b*G) = b * (a*G) = ab*G.
"""

import os
from dataclasses import dataclass
from typing import Tuple

from src.asymmetric.elliptic_curve import (
    Point, G, N, scalar_multiply, point_from_private_key,
)


@dataclass
class ECDHEKeyPair:
    """Ephemeral ECDHE key pair.

    Attributes:
        private_key: Ephemeral private scalar.
        public_key: Ephemeral public point.
    """
    private_key: int
    public_key: Point


def generate_ephemeral_keypair() -> ECDHEKeyPair:
    """Generate an ephemeral ECDHE key pair.

    Returns:
        ECDHEKeyPair with random private key and corresponding public key.
    """
    while True:
        d = int.from_bytes(os.urandom(32), "big")
        if 1 <= d < N:
            break
    pub = point_from_private_key(d)
    return ECDHEKeyPair(private_key=d, public_key=pub)


def compute_shared_secret(
    our_private: int, their_public: Point
) -> bytes:
    """Compute the ECDHE shared secret.

    shared_point = our_private * their_public
    shared_secret = x-coordinate of shared_point (32 bytes, big-endian)

    Args:
        our_private: Our ephemeral private key scalar.
        their_public: Their ephemeral public key point.

    Returns:
        32-byte shared secret (x-coordinate of the shared point).

    Raises:
        ValueError: If the shared point is the point at infinity.
    """
    shared_point = scalar_multiply(our_private, their_public)
    if shared_point.is_infinity:
        raise ValueError("ECDHE shared point is at infinity (invalid key)")
    assert shared_point.x is not None
    return shared_point.x.to_bytes(32, "big")


def ecdhe_exchange(
    client_keypair: ECDHEKeyPair, server_keypair: ECDHEKeyPair
) -> Tuple[bytes, bytes]:
    """Perform a complete ECDHE key exchange between client and server.

    Both sides compute the same shared secret independently.

    Args:
        client_keypair: Client's ephemeral key pair.
        server_keypair: Server's ephemeral key pair.

    Returns:
        Tuple of (client_shared_secret, server_shared_secret).
        Both should be identical if the exchange is correct.
    """
    client_secret = compute_shared_secret(
        client_keypair.private_key, server_keypair.public_key
    )
    server_secret = compute_shared_secret(
        server_keypair.private_key, client_keypair.public_key
    )
    return client_secret, server_secret


def serialize_public_key(point: Point) -> bytes:
    """Serialize an EC public key in uncompressed format.

    Format: 0x04 || x (32 bytes) || y (32 bytes)

    Args:
        point: Public key point.

    Returns:
        65-byte serialized public key.
    """
    if point.is_infinity:
        raise ValueError("Cannot serialize point at infinity")
    assert point.x is not None and point.y is not None
    return (
        b'\x04'
        + point.x.to_bytes(32, "big")
        + point.y.to_bytes(32, "big")
    )


def deserialize_public_key(data: bytes) -> Point:
    """Deserialize an EC public key from uncompressed format.

    Args:
        data: 65-byte serialized public key (0x04 || x || y).

    Returns:
        Public key point.

    Raises:
        ValueError: If format is invalid or point is not on curve.
    """
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError("Invalid uncompressed point format")
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:65], "big")
    point = Point(x=x, y=y)
    if not point.is_on_curve():
        raise ValueError("Point is not on the secp256k1 curve")
    return point


if __name__ == "__main__":
    print("=== ECDHE Key Exchange Demo ===")
    client_kp = generate_ephemeral_keypair()
    server_kp = generate_ephemeral_keypair()

    print(f"Client public key on curve: {client_kp.public_key.is_on_curve()}")
    print(f"Server public key on curve: {server_kp.public_key.is_on_curve()}")

    client_secret, server_secret = ecdhe_exchange(client_kp, server_kp)
    print(f"\nClient shared secret: {client_secret.hex()[:32]}...")
    print(f"Server shared secret: {server_secret.hex()[:32]}...")
    print(f"Secrets match: {client_secret == server_secret}")

    # Serialization round-trip
    serialized = serialize_public_key(client_kp.public_key)
    deserialized = deserialize_public_key(serialized)
    print(f"\nSerialized key: {serialized[:8].hex()}... ({len(serialized)} bytes)")
    print(f"Round-trip match: {deserialized == client_kp.public_key}")
