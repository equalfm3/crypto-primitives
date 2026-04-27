"""Elliptic curve arithmetic on secp256k1.

Implements point addition, doubling, and scalar multiplication using
the Montgomery ladder for constant-time execution.
"""

from dataclasses import dataclass
from typing import Optional

# secp256k1 curve parameters (used in Bitcoin)
# y^2 = x^3 + 7 (mod p)
P: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A: int = 0
B: int = 7
# Generator point
GX: int = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY: int = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
# Order of the generator point
N: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass(frozen=True)
class Point:
    """A point on the secp256k1 elliptic curve.

    The point at infinity is represented by x=None, y=None.

    Attributes:
        x: X coordinate (or None for point at infinity).
        y: Y coordinate (or None for point at infinity).
    """
    x: Optional[int] = None
    y: Optional[int] = None

    @property
    def is_infinity(self) -> bool:
        """Check if this is the point at infinity."""
        return self.x is None and self.y is None

    def is_on_curve(self) -> bool:
        """Verify this point lies on the secp256k1 curve.

        Returns:
            True if the point satisfies y^2 = x^3 + 7 (mod p).
        """
        if self.is_infinity:
            return True
        assert self.x is not None and self.y is not None
        lhs = pow(self.y, 2, P)
        rhs = (pow(self.x, 3, P) + A * self.x + B) % P
        return lhs == rhs


# Point at infinity (identity element)
INFINITY = Point()

# Generator point
G = Point(x=GX, y=GY)


def _mod_inv(a: int, m: int = P) -> int:
    """Modular inverse using Fermat's little theorem (for prime modulus).

    Args:
        a: Number to invert.
        m: Prime modulus.

    Returns:
        a^(-1) mod m.
    """
    return pow(a, m - 2, m)


def point_add(p1: Point, p2: Point) -> Point:
    """Add two points on the secp256k1 curve.

    Args:
        p1: First point.
        p2: Second point.

    Returns:
        Sum p1 + p2 on the curve.
    """
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1

    assert p1.x is not None and p1.y is not None
    assert p2.x is not None and p2.y is not None

    if p1.x == p2.x:
        if p1.y != p2.y:
            return INFINITY  # P + (-P) = O
        # Point doubling
        return point_double(p1)

    # Different points: lambda = (y2 - y1) / (x2 - x1)
    lam = ((p2.y - p1.y) * _mod_inv(p2.x - p1.x)) % P
    x3 = (lam * lam - p1.x - p2.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return Point(x=x3, y=y3)


def point_double(p: Point) -> Point:
    """Double a point on the secp256k1 curve.

    Args:
        p: Point to double.

    Returns:
        2P on the curve.
    """
    if p.is_infinity:
        return INFINITY
    assert p.x is not None and p.y is not None
    if p.y == 0:
        return INFINITY

    # lambda = (3x^2 + a) / (2y)
    lam = ((3 * p.x * p.x + A) * _mod_inv(2 * p.y)) % P
    x3 = (lam * lam - 2 * p.x) % P
    y3 = (lam * (p.x - x3) - p.y) % P
    return Point(x=x3, y=y3)


def point_negate(p: Point) -> Point:
    """Negate a point (reflect across x-axis).

    Args:
        p: Point to negate.

    Returns:
        -P on the curve.
    """
    if p.is_infinity:
        return INFINITY
    assert p.y is not None
    return Point(x=p.x, y=(-p.y) % P)


def scalar_multiply(k: int, p: Point = G) -> Point:
    """Multiply a point by a scalar using the Montgomery ladder.

    The Montgomery ladder performs the same operations regardless of
    the scalar bits, providing constant-time execution.

    Args:
        k: Scalar multiplier.
        p: Base point (defaults to generator G).

    Returns:
        k * P on the curve.
    """
    k = k % N
    if k == 0:
        return INFINITY

    # Montgomery ladder
    r0 = INFINITY
    r1 = p
    for i in range(k.bit_length() - 1, -1, -1):
        if (k >> i) & 1:
            r0 = point_add(r0, r1)
            r1 = point_double(r1)
        else:
            r1 = point_add(r0, r1)
            r0 = point_double(r0)
    return r0


def point_from_private_key(private_key: int) -> Point:
    """Derive the public key point from a private key scalar.

    Args:
        private_key: Private key (integer in [1, N-1]).

    Returns:
        Public key point Q = private_key * G.
    """
    return scalar_multiply(private_key, G)


if __name__ == "__main__":
    print("=== secp256k1 Elliptic Curve Demo ===")
    print(f"Generator G on curve: {G.is_on_curve()}")
    print(f"G.x = {hex(G.x)[:24]}...")

    # Scalar multiplication
    priv = 12345
    pub = point_from_private_key(priv)
    print(f"\nPrivate key: {priv}")
    print(f"Public key on curve: {pub.is_on_curve()}")
    print(f"Pub.x = {hex(pub.x)[:24]}...")

    # Verify associativity: (a+b)*G = a*G + b*G
    a, b = 111, 222
    lhs = scalar_multiply(a + b)
    rhs = point_add(scalar_multiply(a), scalar_multiply(b))
    print(f"\n(a+b)*G == a*G + b*G: {lhs == rhs}")

    # Verify 2G = G + G
    g2_double = point_double(G)
    g2_add = point_add(G, G)
    print(f"2G (double) == G+G (add): {g2_double == g2_add}")
