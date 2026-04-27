"""RSA public-key cryptosystem: key generation, encryption, decryption, signing.

Implements RSA with OAEP padding for encryption and PKCS#1 v1.5-style
signing using SHA-256 for message hashing.
"""

import argparse
from dataclasses import dataclass
from typing import Tuple

from src.asymmetric.primes import generate_prime, mod_inverse
from src.asymmetric.oaep import oaep_encode, oaep_decode
from src.hashing.sha256 import sha256


@dataclass
class RSAPublicKey:
    """RSA public key.

    Attributes:
        n: Modulus (product of two primes).
        e: Public exponent.
    """
    n: int
    e: int

    @property
    def key_size_bytes(self) -> int:
        """Key size in bytes."""
        return (self.n.bit_length() + 7) // 8


@dataclass
class RSAPrivateKey:
    """RSA private key.

    Attributes:
        n: Modulus.
        d: Private exponent.
        p: First prime factor.
        q: Second prime factor.
    """
    n: int
    d: int
    p: int
    q: int

    @property
    def public_key(self) -> RSAPublicKey:
        """Derive the public key from this private key."""
        # Recompute e from d and phi(n)
        phi = (self.p - 1) * (self.q - 1)
        e = mod_inverse(self.d, phi)
        return RSAPublicKey(n=self.n, e=e)

    @property
    def key_size_bytes(self) -> int:
        """Key size in bytes."""
        return (self.n.bit_length() + 7) // 8


def generate_keypair(
    bits: int = 2048, e: int = 65537
) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    """Generate an RSA key pair.

    Args:
        bits: Key size in bits (e.g., 1024, 2048, 4096).
        e: Public exponent (default 65537).

    Returns:
        Tuple of (public_key, private_key).
    """
    half_bits = bits // 2
    while True:
        p = generate_prime(half_bits)
        q = generate_prime(half_bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        try:
            d = mod_inverse(e, phi)
        except ValueError:
            continue
        pub = RSAPublicKey(n=n, e=e)
        priv = RSAPrivateKey(n=n, d=d, p=p, q=q)
        return pub, priv


def encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """Encrypt a message with RSA-OAEP.

    Args:
        plaintext: Message to encrypt.
        public_key: RSA public key.

    Returns:
        Ciphertext bytes.
    """
    k = public_key.key_size_bytes
    encoded = oaep_encode(plaintext, k)
    m = int.from_bytes(encoded, "big")
    c = pow(m, public_key.e, public_key.n)
    return c.to_bytes(k, "big")


def decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """Decrypt a message with RSA-OAEP.

    Args:
        ciphertext: Ciphertext to decrypt.
        private_key: RSA private key.

    Returns:
        Decrypted plaintext bytes.
    """
    k = private_key.key_size_bytes
    c = int.from_bytes(ciphertext, "big")
    m = pow(c, private_key.d, private_key.n)
    encoded = m.to_bytes(k, "big")
    return oaep_decode(encoded)


def sign(message: bytes, private_key: RSAPrivateKey) -> bytes:
    """Sign a message with RSA (SHA-256 hash then private key operation).

    Args:
        message: Message to sign.
        private_key: RSA private key.

    Returns:
        Signature bytes.
    """
    k = private_key.key_size_bytes
    digest = sha256(message)
    # Simple PKCS#1 v1.5-style padding: 0x00 0x01 || PS || 0x00 || DigestInfo
    # DigestInfo = SHA-256 OID prefix + digest
    digest_info = (
        b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
        b'\x05\x00\x04\x20' + digest
    )
    ps_len = k - len(digest_info) - 3
    if ps_len < 8:
        raise ValueError("Key too small for signing")
    padded = b'\x00\x01' + b'\xff' * ps_len + b'\x00' + digest_info
    m = int.from_bytes(padded, "big")
    s = pow(m, private_key.d, private_key.n)
    return s.to_bytes(k, "big")


def verify(message: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    """Verify an RSA signature.

    Args:
        message: Original message.
        signature: Signature to verify.
        public_key: RSA public key.

    Returns:
        True if signature is valid.
    """
    k = public_key.key_size_bytes
    s = int.from_bytes(signature, "big")
    m = pow(s, public_key.e, public_key.n)
    padded = m.to_bytes(k, "big")

    # Verify PKCS#1 v1.5 padding structure
    if padded[0] != 0x00 or padded[1] != 0x01:
        return False

    # Find 0x00 separator after PS
    sep_idx = padded.index(b'\x00', 2) if b'\x00' in padded[2:] else -1
    if sep_idx == -1:
        return False
    # Verify PS is all 0xFF
    if not all(b == 0xFF for b in padded[2:sep_idx]):
        return False

    digest_info = padded[sep_idx + 1:]
    digest = sha256(message)
    expected_info = (
        b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
        b'\x05\x00\x04\x20' + digest
    )
    return digest_info == expected_info


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RSA demo")
    parser.add_argument("--generate", action="store_true", help="Generate key pair")
    parser.add_argument("--bits", type=int, default=1024, help="Key size")
    parser.add_argument("--sign", action="store_true", help="Sign a message")
    parser.add_argument("--message", default="Hello, RSA!")
    args = parser.parse_args()

    print(f"=== RSA-{args.bits} Demo ===")
    pub, priv = generate_keypair(args.bits)
    print(f"Public key:  n={pub.n.bit_length()} bits, e={pub.e}")

    msg = args.message.encode()
    ct = encrypt(msg, pub)
    pt = decrypt(ct, priv)
    print(f"Plaintext:   {msg.decode()}")
    print(f"Ciphertext:  {ct[:16].hex()}... ({len(ct)} bytes)")
    print(f"Decrypted:   {pt.decode()}")
    print(f"Match:       {msg == pt}")

    sig = sign(msg, priv)
    valid = verify(msg, sig, pub)
    print(f"Signature:   {sig[:16].hex()}... ({len(sig)} bytes)")
    print(f"Valid:       {valid}")
    print(f"Tampered:    {verify(b'tampered', sig, pub)}")
