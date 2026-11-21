"""rbpre.sig: Ed25519 signatures for the off-circuit protocol signatures.

Used for the patient consent signature (Eq. 26), delegation tokens (Eq. 33),
the consent-service attestation (Eq. 60), the gateway's AuthTok (Eq. 64) and
retrieval-set signature (Eq. 85), and the KMS descriptor signature (Eq. 10).
The credential and holder signatures that the circuit verifies (Eq. 18, 52)
use EdDSA on Jubjub instead (zk/).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


class SigningKey:
    """An Ed25519 key pair; `pk` is the 32-byte raw public key."""

    def __init__(self, sk: Ed25519PrivateKey | None = None):
        self._sk = sk or Ed25519PrivateKey.generate()
        self.pk: bytes = self._sk.public_key().public_bytes(**_RAW)

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)


def keygen() -> SigningKey:
    return SigningKey()


def verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False
