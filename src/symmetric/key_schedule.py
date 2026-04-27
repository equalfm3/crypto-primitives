"""AES key expansion for 128, 192, and 256-bit keys.

Expands the cipher key into round keys using RotWord, SubWord,
and XOR with round constants (Rcon).
"""

from typing import List

from src.symmetric.galois import SBOX

# Type alias for 4x4 state/key matrix
State = List[List[int]]

# Round constants for key expansion
RCON: List[int] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
]


def _sub_word(word: List[int]) -> List[int]:
    """Apply S-box substitution to each byte of a 4-byte word.

    Args:
        word: 4-byte list.

    Returns:
        Substituted 4-byte list.
    """
    return [SBOX[b] for b in word]


def _rot_word(word: List[int]) -> List[int]:
    """Rotate a 4-byte word left by one byte.

    Args:
        word: 4-byte list.

    Returns:
        Rotated 4-byte list.
    """
    return word[1:] + word[:1]


def _xor_words(a: List[int], b: List[int]) -> List[int]:
    """XOR two 4-byte words.

    Args:
        a: First word.
        b: Second word.

    Returns:
        XOR result.
    """
    return [x ^ y for x, y in zip(a, b)]


def key_expansion(key: bytes) -> List[List[int]]:
    """Expand AES key into round key words.

    Supports 128-bit (16 bytes), 192-bit (24 bytes), and 256-bit (32 bytes) keys.

    Args:
        key: Cipher key (16, 24, or 32 bytes).

    Returns:
        List of 4-byte words forming all round keys.

    Raises:
        ValueError: If key length is not 16, 24, or 32.
    """
    key_len = len(key)
    if key_len == 16:
        nk, nr = 4, 10
    elif key_len == 24:
        nk, nr = 6, 12
    elif key_len == 32:
        nk, nr = 8, 14
    else:
        raise ValueError(f"Invalid key length: {key_len} (must be 16, 24, or 32)")

    total_words = 4 * (nr + 1)
    words: List[List[int]] = []

    # Copy key bytes into initial words
    for i in range(nk):
        words.append(list(key[4 * i: 4 * i + 4]))

    for i in range(nk, total_words):
        temp = words[i - 1][:]
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[(i // nk) - 1]
        elif nk > 6 and i % nk == 4:
            temp = _sub_word(temp)
        words.append(_xor_words(words[i - nk], temp))

    return words


def expand_key(key: bytes) -> List[State]:
    """Expand key and format as list of 4x4 round key matrices.

    Args:
        key: Cipher key (16, 24, or 32 bytes).

    Returns:
        List of 4x4 round key matrices (Nr+1 matrices).
    """
    words = key_expansion(key)
    nr = len(words) // 4
    round_keys: List[State] = []
    for r in range(nr):
        # Build 4x4 matrix from 4 consecutive words (column-major)
        rk: State = [[0] * 4 for _ in range(4)]
        for col in range(4):
            word = words[r * 4 + col]
            for row in range(4):
                rk[row][col] = word[row]
        round_keys.append(rk)
    return round_keys


if __name__ == "__main__":
    print("=== AES Key Schedule Demo ===")
    # AES-128 test vector from FIPS 197
    key_128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    words = key_expansion(key_128)
    print(f"AES-128 key: {key_128.hex()}")
    print(f"Total round key words: {len(words)} (expected 44)")
    print(f"First round key word:  {bytes(words[0]).hex()}")
    print(f"Last round key word:   {bytes(words[-1]).hex()}")

    # AES-256 test
    key_256 = bytes(range(32))
    words_256 = key_expansion(key_256)
    print(f"\nAES-256 key: {key_256.hex()}")
    print(f"Total round key words: {len(words_256)} (expected 60)")

    round_keys = expand_key(key_128)
    print(f"\nRound keys as matrices: {len(round_keys)} (expected 11)")
