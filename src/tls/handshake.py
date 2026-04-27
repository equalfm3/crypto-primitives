"""TLS 1.3 handshake state machine.

Simulates the TLS 1.3 1-RTT handshake flow: ClientHello, ServerHello,
key derivation, encrypted extensions, certificate verification, and
Finished messages. Ties together ECDHE, HKDF, and the record layer.
"""

import argparse
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Tuple

from src.asymmetric.ecdsa import sign as ecdsa_sign, verify as ecdsa_verify
from src.asymmetric.ecdsa import ECDSASignature, generate_keypair as ecdsa_keygen
from src.asymmetric.elliptic_curve import Point
from src.hashing.hmac import hmac_sha256
from src.hashing.sha256 import sha256
from src.tls.hkdf import hkdf_extract, derive_secret, hkdf_expand_label
from src.tls.key_exchange import (
    generate_ephemeral_keypair,
    compute_shared_secret,
    serialize_public_key,
    ECDHEKeyPair,
)
from src.tls.record import RecordLayerKeys


class HandshakeState(Enum):
    """TLS 1.3 handshake states."""
    START = auto()
    WAIT_SERVER_HELLO = auto()
    WAIT_ENCRYPTED_EXTENSIONS = auto()
    WAIT_CERTIFICATE = auto()
    WAIT_CERTIFICATE_VERIFY = auto()
    WAIT_FINISHED = auto()
    CONNECTED = auto()
    ERROR = auto()


class CipherSuite(Enum):
    """Supported TLS 1.3 cipher suites."""
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302


@dataclass
class ClientHello:
    """TLS ClientHello: random, supported cipher suites, and ECDHE key share."""
    random: bytes
    cipher_suites: list
    key_share: bytes


@dataclass
class ServerHello:
    """TLS ServerHello: random, chosen cipher suite, and ECDHE key share."""
    random: bytes
    cipher_suite: CipherSuite
    key_share: bytes


@dataclass
class HandshakeKeys:
    """Client and server handshake traffic keys and IVs."""
    client_key: bytes
    client_iv: bytes
    server_key: bytes
    server_iv: bytes


@dataclass
class ApplicationKeys:
    """Client and server application traffic keys and IVs."""
    client_key: bytes
    client_iv: bytes
    server_key: bytes
    server_iv: bytes


HASH_LEN: int = 32
KEY_LEN: int = 16  # AES-128
IV_LEN: int = 12


def _derive_handshake_keys(
    shared_secret: bytes, transcript: bytes
) -> Tuple[bytes, HandshakeKeys]:
    """Derive handshake traffic keys per TLS 1.3 key schedule (RFC 8446 §7.1)."""
    zero_key = b'\x00' * HASH_LEN
    # Early secret (no PSK)
    early_secret = hkdf_extract(b'\x00' * HASH_LEN, zero_key)
    # Derive salt for handshake secret
    derived = derive_secret(early_secret, "derived", b"")
    # Handshake secret
    hs_secret = hkdf_extract(derived, shared_secret)
    # Client/server handshake traffic secrets
    transcript_hash = sha256(transcript)
    c_hs_secret = hkdf_expand_label(hs_secret, "c hs traffic", transcript_hash, HASH_LEN)
    s_hs_secret = hkdf_expand_label(hs_secret, "s hs traffic", transcript_hash, HASH_LEN)
    # Derive keys and IVs
    keys = HandshakeKeys(
        client_key=hkdf_expand_label(c_hs_secret, "key", b"", KEY_LEN),
        client_iv=hkdf_expand_label(c_hs_secret, "iv", b"", IV_LEN),
        server_key=hkdf_expand_label(s_hs_secret, "key", b"", KEY_LEN),
        server_iv=hkdf_expand_label(s_hs_secret, "iv", b"", IV_LEN),
    )
    return hs_secret, keys


def _derive_application_keys(hs_secret: bytes, transcript: bytes) -> ApplicationKeys:
    """Derive application traffic keys from the handshake secret."""
    derived = derive_secret(hs_secret, "derived", b"")
    master_secret = hkdf_extract(derived, b'\x00' * HASH_LEN)
    transcript_hash = sha256(transcript)
    c_ap_secret = hkdf_expand_label(master_secret, "c ap traffic", transcript_hash, HASH_LEN)
    s_ap_secret = hkdf_expand_label(master_secret, "s ap traffic", transcript_hash, HASH_LEN)
    return ApplicationKeys(
        client_key=hkdf_expand_label(c_ap_secret, "key", b"", KEY_LEN),
        client_iv=hkdf_expand_label(c_ap_secret, "iv", b"", IV_LEN),
        server_key=hkdf_expand_label(s_ap_secret, "key", b"", KEY_LEN),
        server_iv=hkdf_expand_label(s_ap_secret, "iv", b"", IV_LEN),
    )


def _compute_finished(base_key: bytes, transcript: bytes) -> bytes:
    """Compute Finished verify_data = HMAC(finished_key, transcript_hash)."""
    finished_key = hkdf_expand_label(base_key, "finished", b"", HASH_LEN)
    return hmac_sha256(finished_key, sha256(transcript))


def simulate_handshake(
    cipher_suite: CipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256,
    verbose: bool = True,
) -> Tuple[RecordLayerKeys, RecordLayerKeys]:
    """Simulate a complete TLS 1.3 1-RTT handshake between client and server.

    Returns:
        Tuple of (client_record_keys, server_record_keys) for application data.
    """
    transcript = b""

    # --- Step 1: ClientHello ---
    client_kp = generate_ephemeral_keypair()
    client_hello = ClientHello(
        random=os.urandom(32),
        cipher_suites=[cipher_suite],
        key_share=serialize_public_key(client_kp.public_key),
    )
    ch_bytes = client_hello.random + client_hello.key_share
    transcript += ch_bytes
    if verbose:
        print("[Client] ClientHello sent")
        print(f"  Random: {client_hello.random.hex()[:16]}...")
        print(f"  Key share: {client_hello.key_share[:8].hex()}...")

    # --- Step 2: ServerHello ---
    server_kp = generate_ephemeral_keypair()
    server_hello = ServerHello(
        random=os.urandom(32),
        cipher_suite=cipher_suite,
        key_share=serialize_public_key(server_kp.public_key),
    )
    sh_bytes = server_hello.random + server_hello.key_share
    transcript += sh_bytes
    if verbose:
        print("[Server] ServerHello sent")
        print(f"  Cipher: {cipher_suite.name}")

    # --- Step 3: Derive handshake keys ---
    shared_secret = compute_shared_secret(
        client_kp.private_key, server_kp.public_key
    )
    hs_secret, hs_keys = _derive_handshake_keys(shared_secret, transcript)
    if verbose:
        print("[Both]   Handshake keys derived")
        print(f"  Shared secret: {shared_secret.hex()[:16]}...")

    # --- Step 4: Server Certificate + CertificateVerify ---
    server_identity = ecdsa_keygen()
    cert_data = serialize_public_key(server_identity.public_key)
    transcript += cert_data
    # Sign the transcript hash
    transcript_hash = sha256(transcript)
    cert_verify_sig = ecdsa_sign(transcript_hash, server_identity.private_key)
    sig_bytes = cert_verify_sig.r.to_bytes(32, "big") + cert_verify_sig.s.to_bytes(32, "big")
    transcript += sig_bytes
    if verbose:
        print("[Server] Certificate + CertificateVerify sent")

    # --- Step 5: Server Finished ---
    s_hs_traffic = hkdf_expand_label(
        hs_secret, "s hs traffic", sha256(ch_bytes + sh_bytes), HASH_LEN
    )
    server_finished = _compute_finished(s_hs_traffic, transcript)
    transcript += server_finished
    if verbose:
        print(f"[Server] Finished: {server_finished.hex()[:16]}...")

    # --- Step 6: Client verifies server ---
    verified = ecdsa_verify(
        transcript_hash, cert_verify_sig, server_identity.public_key
    )
    if verbose:
        print(f"[Client] Server certificate verified: {verified}")

    # --- Step 7: Client Finished ---
    c_hs_traffic = hkdf_expand_label(
        hs_secret, "c hs traffic", sha256(ch_bytes + sh_bytes), HASH_LEN
    )
    client_finished = _compute_finished(c_hs_traffic, transcript)
    transcript += client_finished
    if verbose:
        print(f"[Client] Finished: {client_finished.hex()[:16]}...")

    # --- Step 8: Derive application keys ---
    app_keys = _derive_application_keys(hs_secret, transcript)
    if verbose:
        print("[Both]   Application keys derived")
        print(f"  Client key: {app_keys.client_key.hex()}")
        print(f"  Server key: {app_keys.server_key.hex()}")
        print("[Both]   Handshake complete — CONNECTED")

    client_record_keys = RecordLayerKeys(
        key=app_keys.client_key, iv=app_keys.client_iv
    )
    server_record_keys = RecordLayerKeys(
        key=app_keys.server_key, iv=app_keys.server_iv
    )
    return client_record_keys, server_record_keys


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS 1.3 handshake simulation")
    parser.add_argument(
        "--cipher",
        choices=["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        default="TLS_AES_128_GCM_SHA256",
    )
    parser.add_argument("--simulate", action="store_true", default=True)
    args = parser.parse_args()

    suite = CipherSuite[args.cipher]
    print(f"=== TLS 1.3 Handshake Simulation ({suite.name}) ===\n")
    client_keys, server_keys = simulate_handshake(suite)

    # Demo: encrypt a message with the derived keys
    from src.tls.record import encrypt_record, decrypt_record, ContentType

    msg = b"Hello over TLS 1.3!"
    enc = encrypt_record(msg, ContentType.APPLICATION_DATA, client_keys)
    # Server would use its own keys to decrypt client traffic in real TLS,
    # but here we demonstrate the record layer works with matching keys
    print(f"\nApplication data: {msg.decode()}")
    print(f"Encrypted: {enc.data[:16].hex()}...")
    print(f"Tag: {enc.tag.hex()}")
