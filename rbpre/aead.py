"""rbpre.aead: AES-256-GCM for IoMT data (Eq. 31, 35-36) and EHR payloads (Eq. 42, 93).

A ciphertext blob is nonce (12 bytes) || ciphertext || tag (16 bytes), so CT_m
"includes the nonce and authentication tag" as the paper states. Any change to
the blob or to the associated data makes decryption fail.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12
KEY_BYTES = 32


class AEADError(Exception):
    pass


def new_key() -> bytes:
    return os.urandom(KEY_BYTES)


def encrypt(key: bytes, plaintext: bytes, ad: bytes, nonce: bytes | None = None) -> bytes:
    nonce = nonce or os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, ad)


def decrypt(key: bytes, blob: bytes, ad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], ad)
    except (InvalidTag, ValueError) as e:
        raise AEADError("AEAD verification failed") from e
