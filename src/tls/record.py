"""TLS 1.3 record layer: encryption and decryption of application data.

Implements the TLS 1.3 record protocol using AES-GCM for authenticated
encryption of records, with per-record nonce construction.
"""

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import List

from src.symmetric.modes import gcm_encrypt, gcm_decrypt


class ContentType(IntEnum):
    """TLS record content types."""
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


@dataclass
class TLSRecord:
    """A TLS 1.3 record.

    Attributes:
        content_type: Type of record content.
        data: Record payload (plaintext or ciphertext).
        tag: Authentication tag (for encrypted records).
    """
    content_type: ContentType
    data: bytes
    tag: bytes = b""


@dataclass
class RecordLayerKeys:
    """Keys for TLS record layer encryption/decryption.

    Attributes:
        key: AES key (16 or 32 bytes).
        iv: Base IV/nonce (12 bytes).
        sequence_number: Current sequence number for nonce construction.
    """
    key: bytes
    iv: bytes
    sequence_number: int = 0

    def next_nonce(self) -> bytes:
        """Construct the per-record nonce and increment sequence number.

        TLS 1.3 nonce = base_iv XOR padded_sequence_number.

        Returns:
            12-byte nonce for this record.
        """
        # Pad sequence number to 12 bytes
        seq_bytes = self.sequence_number.to_bytes(12, "big")
        nonce = bytes(a ^ b for a, b in zip(self.iv, seq_bytes))
        self.sequence_number += 1
        return nonce


def encrypt_record(
    plaintext: bytes,
    content_type: ContentType,
    keys: RecordLayerKeys,
) -> TLSRecord:
    """Encrypt a TLS record using AES-GCM.

    The inner content type is appended to the plaintext before encryption.
    The additional authenticated data (AAD) is the TLS record header.

    Args:
        plaintext: Record payload to encrypt.
        content_type: Inner content type.
        keys: Record layer encryption keys.

    Returns:
        Encrypted TLS record with authentication tag.
    """
    # TLS 1.3: append real content type to plaintext
    inner_plaintext = plaintext + bytes([content_type])

    # Construct nonce
    nonce = keys.next_nonce()

    # AAD: TLS record header (type=0x17, version=0x0303, length)
    encrypted_len = len(inner_plaintext) + 16  # ciphertext + tag
    aad = struct.pack(">BHH", 0x17, 0x0303, encrypted_len)

    # Encrypt with AES-GCM
    ciphertext, tag = gcm_encrypt(inner_plaintext, keys.key, nonce, aad)

    return TLSRecord(
        content_type=ContentType.APPLICATION_DATA,
        data=ciphertext,
        tag=tag,
    )


def decrypt_record(
    record: TLSRecord,
    keys: RecordLayerKeys,
) -> TLSRecord:
    """Decrypt a TLS record using AES-GCM.

    Args:
        record: Encrypted TLS record.
        keys: Record layer decryption keys.

    Returns:
        Decrypted TLS record with inner content type.

    Raises:
        ValueError: If authentication fails or record is malformed.
    """
    nonce = keys.next_nonce()

    # Reconstruct AAD
    encrypted_len = len(record.data) + 16
    aad = struct.pack(">BHH", 0x17, 0x0303, encrypted_len)

    # Decrypt with AES-GCM
    inner_plaintext = gcm_decrypt(record.data, keys.key, nonce, record.tag, aad)

    if not inner_plaintext:
        raise ValueError("Empty decrypted record")

    # Extract inner content type (last byte)
    real_content_type = ContentType(inner_plaintext[-1])
    payload = inner_plaintext[:-1]

    return TLSRecord(
        content_type=real_content_type,
        data=payload,
    )


def serialize_record(record: TLSRecord) -> bytes:
    """Serialize a TLS record to wire format.

    Format: content_type (1) || version (2) || length (2) || data || tag

    Args:
        record: TLS record to serialize.

    Returns:
        Serialized bytes.
    """
    payload = record.data + record.tag
    header = struct.pack(">BHH", record.content_type, 0x0303, len(payload))
    return header + payload


def deserialize_record(data: bytes) -> TLSRecord:
    """Deserialize a TLS record from wire format.

    Args:
        data: Raw bytes from the wire.

    Returns:
        Parsed TLS record.

    Raises:
        ValueError: If data is too short or malformed.
    """
    if len(data) < 5:
        raise ValueError("Record too short")
    content_type = ContentType(data[0])
    length = struct.unpack(">H", data[3:5])[0]
    payload = data[5:5 + length]

    if content_type == ContentType.APPLICATION_DATA and len(payload) >= 16:
        return TLSRecord(
            content_type=content_type,
            data=payload[:-16],
            tag=payload[-16:],
        )
    return TLSRecord(content_type=content_type, data=payload)


if __name__ == "__main__":
    import os

    print("=== TLS Record Layer Demo ===")
    key = os.urandom(16)
    iv = os.urandom(12)

    enc_keys = RecordLayerKeys(key=key, iv=iv)
    dec_keys = RecordLayerKeys(key=key, iv=iv)

    # Encrypt application data
    message = b"Hello, TLS 1.3!"
    encrypted = encrypt_record(message, ContentType.APPLICATION_DATA, enc_keys)
    print(f"Plaintext:  {message.decode()}")
    print(f"Encrypted:  {encrypted.data[:16].hex()}...")
    print(f"Tag:        {encrypted.tag.hex()}")

    # Decrypt
    decrypted = decrypt_record(encrypted, dec_keys)
    print(f"Decrypted:  {decrypted.data.decode()}")
    print(f"Type:       {decrypted.content_type.name}")
    print(f"Match:      {message == decrypted.data}")

    # Serialize round-trip
    wire = serialize_record(encrypted)
    parsed = deserialize_record(wire)
    print(f"\nWire format: {wire[:16].hex()}... ({len(wire)} bytes)")
    print(f"Round-trip:  {parsed.data == encrypted.data}")
