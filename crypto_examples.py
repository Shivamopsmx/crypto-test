"""Intentional cryptography usage for testing CBOM generation.

Mix of quantum-vulnerable (RSA), weak (MD5/SHA-1/DES), and modern (AES-GCM,
SHA-256) primitives so a CBOM scan produces varied cryptographic-asset findings.
Not for production use.
"""
import hashlib
import hmac
import os
import ssl

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as c_hmac
from cryptography.fernet import Fernet


# --- Hashing ---------------------------------------------------------------
def weak_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()            # MD5 — broken

def weak_sha1(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()         # SHA-256 — replaces deprecated SHA-1

def strong_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()         # SHA-256 — ok


# --- MAC -------------------------------------------------------------------
def make_hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()   # HMAC-SHA256


# --- Symmetric encryption --------------------------------------------------
def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    iv = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()   # AES-GCM — ok
    return iv, enc.update(plaintext) + enc.finalize(), enc.tag

def triple_des(key: bytes, data: bytes):
    enc = Cipher(algorithms.TripleDES(key), modes.CBC(b"\0" * 8)).encryptor()  # 3DES — weak
    return enc.update(data) + enc.finalize()

def fernet_token(data: bytes) -> bytes:
    return Fernet(Fernet.generate_key()).encrypt(data)   # Fernet (AES-128-CBC + HMAC)


# --- Asymmetric (quantum-vulnerable) --------------------------------------
def gen_rsa_2048():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)  # RSA-2048 — quantum-vulnerable

def gen_ecdsa_p256():
    return ec.generate_private_key(ec.SECP256R1())      # ECDSA P-256 — quantum-vulnerable


# --- TLS -------------------------------------------------------------------
def make_tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2        # TLS 1.2
    return ctx


if __name__ == "__main__":
    print(weak_md5(b"x"), strong_sha256(b"x"))
    gen_rsa_2048(); gen_ecdsa_p256()
    aes_gcm_encrypt(os.urandom(32), b"secret")
