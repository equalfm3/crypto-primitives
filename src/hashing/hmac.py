"""HMAC-SHA256: Hash-based Message Authentication Code.

Implements HMAC per RFC 2104 using SHA-256 as the underlying hash function.
HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
"""

from src.hashing.sha256 import sha256

BLOCK_SIZE: int = 64  # SHA-256 block size in bytes
IPAD: int = 0x36
OPAD: int = 0x5C


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256 of a message with a secret key.

    If the key is longer than the block size, it is hashed first.
    If shorter, it is zero-padded to the block size.

    Args:
        key: Secret key (any length).
        message: Message to authenticate.

    Returns:
        32-byte HMAC digest.
    """
    # Step 1: Normalize key length
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    key_padded = key + b'\x00' * (BLOCK_SIZE - len(key))

    # Step 2: Create inner and outer padded keys
    inner_key = bytes(b ^ IPAD for b in key_padded)
    outer_key = bytes(b ^ OPAD for b in key_padded)

    # Step 3: HMAC = H(outer_key || H(inner_key || message))
    inner_hash = sha256(inner_key + message)
    return sha256(outer_key + inner_hash)


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """Compute HMAC-SHA256 and return as hex string.

    Args:
        key: Secret key.
        message: Message to authenticate.

    Returns:
        64-character hex digest string.
    """
    return hmac_sha256(key, message).hex()


def verify_hmac(key: bytes, message: bytes, expected_mac: bytes) -> bool:
    """Verify an HMAC-SHA256 tag in constant time.

    Args:
        key: Secret key.
        message: Message that was authenticated.
        expected_mac: Expected HMAC tag to verify against.

    Returns:
        True if the MAC is valid, False otherwise.
    """
    computed = hmac_sha256(key, message)
    # Constant-time comparison to prevent timing attacks
    if len(computed) != len(expected_mac):
        return False
    result = 0
    for a, b in zip(computed, expected_mac):
        result |= a ^ b
    return result == 0


if __name__ == "__main__":
    print("=== HMAC-SHA256 Demo ===")
    key = b"secret-key"
    msg = b"Hello, World!"
    mac = hmac_sha256(key, msg)
    print(f"Key:     {key.decode()}")
    print(f"Message: {msg.decode()}")
    print(f"HMAC:    {mac.hex()}")
    print(f"Verify:  {verify_hmac(key, msg, mac)}")
    print(f"Tamper:  {verify_hmac(key, b'Tampered!', mac)}")

    # RFC 4231 test vector 1
    tv_key = bytes.fromhex("0b" * 20)
    tv_msg = b"Hi There"
    tv_mac = hmac_sha256_hex(tv_key, tv_msg)
    expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    print(f"\nRFC 4231 Test Vector 1:")
    print(f"HMAC:     {tv_mac}")
    print(f"Expected: {expected}")
    print(f"Match:    {tv_mac == expected}")
