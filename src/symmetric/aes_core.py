"""AES round functions: SubBytes, ShiftRows, MixColumns, AddRoundKey.

Implements the four core transformations of the AES cipher operating
on a 4x4 state matrix of bytes (128-bit block).
"""

from typing import List

from src.symmetric.galois import SBOX, INV_SBOX, gf_mul

# Type alias for the 4x4 AES state matrix (row-major)
State = List[List[int]]


def bytes_to_state(data: bytes) -> State:
    """Convert 16 bytes to a 4x4 AES state matrix (column-major layout).

    AES state is column-major: state[row][col] = data[row + 4*col].

    Args:
        data: Exactly 16 bytes of input.

    Returns:
        4x4 state matrix.
    """
    if len(data) != 16:
        raise ValueError(f"Expected 16 bytes, got {len(data)}")
    state: State = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = data[row + 4 * col]
    return state


def state_to_bytes(state: State) -> bytes:
    """Convert a 4x4 AES state matrix back to 16 bytes.

    Args:
        state: 4x4 state matrix.

    Returns:
        16 bytes in column-major order.
    """
    result = bytearray(16)
    for col in range(4):
        for row in range(4):
            result[row + 4 * col] = state[row][col]
    return bytes(result)


def sub_bytes(state: State) -> State:
    """Apply SubBytes: substitute each byte using the AES S-box.

    Args:
        state: 4x4 state matrix.

    Returns:
        New state with S-box substitution applied.
    """
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state: State) -> State:
    """Apply inverse SubBytes using the inverse S-box.

    Args:
        state: 4x4 state matrix.

    Returns:
        New state with inverse S-box substitution applied.
    """
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state: State) -> State:
    """Apply ShiftRows: cyclic left shift of row i by i positions.

    Row 0: no shift, Row 1: shift 1, Row 2: shift 2, Row 3: shift 3.

    Args:
        state: 4x4 state matrix.

    Returns:
        New state with rows shifted.
    """
    result: State = [row[:] for row in state]
    for i in range(1, 4):
        result[i] = state[i][i:] + state[i][:i]
    return result


def inv_shift_rows(state: State) -> State:
    """Apply inverse ShiftRows: cyclic right shift of row i by i positions.

    Args:
        state: 4x4 state matrix.

    Returns:
        New state with rows shifted back.
    """
    result: State = [row[:] for row in state]
    for i in range(1, 4):
        result[i] = state[i][4 - i:] + state[i][:4 - i]
    return result


# MixColumns fixed matrix and its inverse
MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]

INV_MIX_MATRIX = [
    [14, 11, 13, 9],
    [9, 14, 11, 13],
    [13, 9, 14, 11],
    [11, 13, 9, 14],
]


def mix_columns(state: State) -> State:
    """Apply MixColumns: matrix multiply each column in GF(2^8).

    Args:
        state: 4x4 state matrix.

    Returns:
        New state with columns mixed.
    """
    result: State = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mul(MIX_MATRIX[row][k], state[k][col])
            result[row][col] = val
    return result


def inv_mix_columns(state: State) -> State:
    """Apply inverse MixColumns using the inverse mix matrix.

    Args:
        state: 4x4 state matrix.

    Returns:
        New state with inverse column mixing applied.
    """
    result: State = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mul(INV_MIX_MATRIX[row][k], state[k][col])
            result[row][col] = val
    return result


def add_round_key(state: State, round_key: List[List[int]]) -> State:
    """XOR state with round key.

    Args:
        state: 4x4 state matrix.
        round_key: 4x4 round key matrix.

    Returns:
        New state XORed with the round key.
    """
    return [
        [state[r][c] ^ round_key[r][c] for c in range(4)]
        for r in range(4)
    ]


def aes_encrypt_block(plaintext: bytes, round_keys: List[State]) -> bytes:
    """Encrypt a single 128-bit block with AES.

    Args:
        plaintext: 16 bytes of plaintext.
        round_keys: List of 4x4 round key matrices (Nr+1 keys).

    Returns:
        16 bytes of ciphertext.
    """
    nr = len(round_keys) - 1
    state = bytes_to_state(plaintext)
    state = add_round_key(state, round_keys[0])
    for i in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[i])
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[nr])
    return state_to_bytes(state)


def aes_decrypt_block(ciphertext: bytes, round_keys: List[State]) -> bytes:
    """Decrypt a single 128-bit block with AES.

    Args:
        ciphertext: 16 bytes of ciphertext.
        round_keys: List of 4x4 round key matrices (Nr+1 keys).

    Returns:
        16 bytes of plaintext.
    """
    nr = len(round_keys) - 1
    state = bytes_to_state(ciphertext)
    state = add_round_key(state, round_keys[nr])
    for i in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[i])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state_to_bytes(state)


if __name__ == "__main__":
    from src.symmetric.key_schedule import expand_key

    print("=== AES Core Demo ===")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    round_keys = expand_key(key)
    ct = aes_encrypt_block(pt, round_keys)
    print(f"Plaintext:  {pt.hex()}")
    print(f"Key:        {key.hex()}")
    print(f"Ciphertext: {ct.hex()}")
    dt = aes_decrypt_block(ct, round_keys)
    print(f"Decrypted:  {dt.hex()}")
    print(f"Match: {pt == dt}")
