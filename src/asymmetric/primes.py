"""Prime number generation and testing for RSA key generation.

Implements Miller-Rabin primality testing with deterministic witnesses
for small numbers and probabilistic testing for large numbers.
"""

import random
from typing import List, Optional

# Deterministic witnesses for numbers below specific bounds
# These guarantee correctness (not just probabilistic) for small numbers
SMALL_PRIMES: List[int] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
]


def _miller_rabin_test(n: int, a: int) -> bool:
    """Run a single Miller-Rabin witness test.

    Args:
        n: Odd number to test (n > 2).
        a: Witness value.

    Returns:
        True if n passes the test (probably prime), False if composite.
    """
    # Write n-1 as 2^r * d where d is odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Compute a^d mod n
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True

    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False


def is_prime(n: int, rounds: int = 40) -> bool:
    """Test if n is prime using Miller-Rabin primality test.

    Uses deterministic witnesses for small numbers and probabilistic
    testing with the specified number of rounds for larger numbers.

    Args:
        n: Number to test.
        rounds: Number of random witness rounds for large numbers.

    Returns:
        True if n is (probably) prime.
    """
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False

    # Quick check against small primes
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Deterministic witnesses for small ranges
    if n < 2047:
        witnesses = [2]
    elif n < 1373653:
        witnesses = [2, 3]
    elif n < 3215031751:
        witnesses = [2, 3, 5, 7]
    elif n < 3317044064679887385961981:
        witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    else:
        # Probabilistic for very large numbers
        witnesses = [random.randrange(2, n - 1) for _ in range(rounds)]

    return all(_miller_rabin_test(n, a) for a in witnesses)


def generate_prime(bits: int, rng: Optional[random.Random] = None) -> int:
    """Generate a random prime number with the specified bit length.

    Args:
        bits: Desired bit length of the prime.
        rng: Optional random number generator (defaults to system random).

    Returns:
        A prime number with exactly the specified number of bits.
    """
    if rng is None:
        rng = random.SystemRandom()

    while True:
        # Generate random odd number with MSB set
        n = rng.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1  # Set MSB and LSB
        if is_prime(n):
            return n


def mod_inverse(a: int, m: int) -> int:
    """Compute modular multiplicative inverse using extended Euclidean algorithm.

    Args:
        a: Number to invert.
        m: Modulus.

    Returns:
        a^(-1) mod m.

    Raises:
        ValueError: If inverse does not exist (gcd(a, m) != 1).
    """
    if m == 1:
        return 0
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist (gcd={g})")
    return x % m


def _extended_gcd(a: int, b: int):
    """Extended Euclidean algorithm.

    Args:
        a: First number.
        b: Second number.

    Returns:
        Tuple (gcd, x, y) such that a*x + b*y = gcd.
    """
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


if __name__ == "__main__":
    print("=== Prime Generation Demo ===")
    for bits in [64, 128, 256]:
        p = generate_prime(bits)
        print(f"{bits}-bit prime: {p}")
        print(f"  Is prime: {is_prime(p)}")
        print(f"  Bit length: {p.bit_length()}")

    print(f"\nis_prime(17): {is_prime(17)}")
    print(f"is_prime(18): {is_prime(18)}")
    print(f"is_prime(104729): {is_prime(104729)}")
    print(f"mod_inverse(3, 11) = {mod_inverse(3, 11)} (expected 4)")
