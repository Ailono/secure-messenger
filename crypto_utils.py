#!/usr/bin/python3
"""Cryptographic utilities for the secure messenger."""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_der_public_key
)
import os, secrets


def generate_keypair():
    """Generate an ephemeral ECDH key pair on SECP256R1."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def public_key_to_bytes(public_key) -> bytes:
    return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def public_key_from_bytes(data: bytes):
    return load_der_public_key(data)


def compute_shared_secret(private_key, peer_public_key) -> bytes:
    return private_key.exchange(ec.ECDH(), peer_public_key)


def derive_keys(shared_secret: bytes) -> bytes:
    """Derive a 32-byte AES key from shared secret using HKDF."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure_messenger_v1'
    ).derive(shared_secret)


def encrypt(message: str, key: bytes) -> bytes:
    """Encrypt message with AES-256-GCM. Returns nonce+ciphertext."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    return nonce + ct


def decrypt(data: bytes, key: bytes) -> str:
    """Decrypt AES-256-GCM payload. Expects nonce+ciphertext."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(data[:12], data[12:], None).decode('utf-8')
