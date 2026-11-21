"""rbpre.encoding: the hash H(.), the "||" concatenation and the KDF.

The paper writes H(a || b || ...) with H collision resistant and requires
canonical encoding of every cryptographic input. Here H is SHA-256 and "||" is
an unambiguous encoding: each component is length-prefixed (4-byte big-endian)
before hashing, so ("ab", "c") and ("a", "bc") never collide. Nested tuples and
lists are encoded recursively.

Hashes that the Groth16 circuit recomputes (Eq. 18, 51 and h_A) use MiMC over
the BLS12-381 scalar field instead; they are computed by the Go helper in zk/.
"""

from __future__ import annotations

import hashlib
import hmac

DIGEST_BYTES = 32


def _b(x) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("utf-8")
    if isinstance(x, bool):
        raise TypeError("bool is not encoded implicitly; encode it explicitly")
    if isinstance(x, int):
        return str(x).encode("ascii")
    if isinstance(x, (tuple, list)):
        return encode(*x)
    raise TypeError(f"cannot encode {type(x).__name__}")


def encode(*parts) -> bytes:
    """Canonical encoding of a || b || ... (length-prefixed components)."""
    out = bytearray()
    for p in parts:
        pb = _b(p)
        out += len(pb).to_bytes(4, "big") + pb
    return bytes(out)


def H(*parts) -> bytes:
    """H(a || b || ...) -> 32-byte SHA-256 digest."""
    return hashlib.sha256(encode(*parts)).digest()


def Hhex(*parts) -> str:
    return H(*parts).hex()


def kdf(key: bytes, *info, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869) with an all-zero salt; info = encode(*info).

    Used for the device keys K_dev^(i,e) = KDF(K_Hj, ID_i || e) (Eq. 30).
    """
    prk = hmac.new(b"\x00" * 32, key, hashlib.sha256).digest()
    info_b = encode(*info)
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info_b + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]
