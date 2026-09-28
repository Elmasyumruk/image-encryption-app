"""
Cryptographic utilities for Image Encryption Application.
Implements DES encryption, RSA key exchange, and digital signatures.
"""
import os
import json
import base64
import hashlib
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


def generate_des_key():
    """Generate a random 8-byte DES key."""
    return os.urandom(8)


def des_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt bytes with DES (CBC mode). Returns IV + ciphertext."""
    iv = os.urandom(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, DES.block_size))


def des_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt DES-CBC ciphertext (IV prepended)."""
    iv = data[:8]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[8:]), DES.block_size)


def generate_rsa_keypair(bits=2048):
    """Generate RSA key pair. Returns (private_key, public_key) as PEM strings."""
    key = RSA.generate(bits)
    return key.export_key().decode(), key.publickey().export_key().decode()


def rsa_encrypt(data: bytes, public_key_pem: str) -> bytes:
    """Encrypt data with RSA public key (for session key exchange)."""
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)


def rsa_decrypt(data: bytes, private_key_pem: str) -> bytes:
    """Decrypt data with RSA private key."""
    key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(data)


def sign_data(data: bytes, private_key_pem: str) -> bytes:
    """Create RSA-SHA256 digital signature."""
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(data)
    return pkcs1_15.new(key).sign(h)


def verify_signature(data: bytes, signature: bytes, public_key_pem: str) -> bool:
    """Verify RSA-SHA256 digital signature. Returns True if valid."""
    try:
        key = RSA.import_key(public_key_pem)
        h = SHA256.new(data)
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)
