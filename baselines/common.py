"""Shared primitives and workload index for the compared schemes."""

from __future__ import annotations

import hashlib
import hmac
import os
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from charm.schemes.pksig.pksig_hess import Hess
from charm.toolbox.eccurve import prime256v1
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.ecgroup import G as EC_G
from charm.toolbox.ecgroup import ZR as EC_ZR
from charm.toolbox.pairinggroup import G1, ZR, PairingGroup, pair

from rbpre import aead


@dataclass(frozen=True)
class IndexEntry:
    """One repository record as a scan-based scheme sees it."""

    owner: bytes   # owner tag H(patient identifier)
    rid: str
    hosp: str
    cls: str


class Prims:
    """The operations of Table III, on the same groups as RBPRE-CALX.

    T_P pairing, T_E exponentiation and T_M multiplication in G1 (SS512);
    T_sm scalar multiplication and T_add point addition on P-256; T_H SHA-256;
    T_sym AES-256-GCM; T_p a PUF evaluation (HMAC-SHA256 with a device secret);
    T_IBS sign/verify the Hess identity-based signature on SS512.
    """

    def __init__(self, curve: str = "SS512"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            self.grp = PairingGroup(curve)
        self.g, self.h = self.grp.random(G1), self.grp.random(G1)
        self.ec = ECGroup(prime256v1)
        self.P = self.ec.random(EC_G)
        self.ibs = Hess(self.grp)
        self.ibs_mpk, self.ibs_msk = self.ibs.setup()
        self.sym_key = aead.new_key()
        self.puf_secret = os.urandom(32)

    # pairing group
    def zr(self):
        return self.grp.random(ZR)

    def g1(self):
        return self.grp.random(G1)

    def T_P(self, a, b):
        return pair(a, b)

    def T_E(self, a, r):
        return a ** r

    def T_M(self, a, b):
        return a * b

    # P-256
    def ec_scalar(self):
        return self.ec.random(EC_ZR)

    def T_sm(self, P, k):
        return P ** k

    def T_add(self, P, Q):
        return P * Q

    # symmetric
    @staticmethod
    def T_H(*parts: bytes) -> bytes:
        h = hashlib.sha256()
        for p in parts:
            h.update(p)
        return h.digest()

    def T_sym_enc(self, data: bytes, ad: bytes = b"") -> bytes:
        return aead.encrypt(self.sym_key, data, ad)

    def T_sym_dec(self, blob: bytes, ad: bytes = b"") -> bytes:
        return aead.decrypt(self.sym_key, blob, ad)

    def T_p(self, challenge: bytes) -> bytes:
        return hmac.new(self.puf_secret, challenge, hashlib.sha256).digest()

    # identity-based signatures
    def ibs_keygen(self, ident: str):
        return self.ibs.keygen(self.ibs_msk, ident)

    def T_IBS_sign(self, sk, msg: str):
        return self.ibs.sign(self.ibs_mpk, sk, msg)

    def T_IBS_ver(self, pk, msg: str, sig) -> bool:
        return self.ibs.verify(self.ibs_mpk, pk, msg, sig)


def scan(index: list[IndexEntry], owner: bytes, prims: Prims) -> list[IndexEntry]:
    """Repository scan for schemes without a retrieval index: one owner-tag
    comparison per stored record."""
    want = prims.T_H(b"tag", owner)
    return [e for e in index if hmac.compare_digest(prims.T_H(b"tag", e.owner), want)]


def per_event_invoke(ledger, fn: str, payloads: list[str], concurrency: int) -> None:
    """One transaction per event, submitted with a fixed number of concurrent
    clients (each waits for commit)."""
    with ThreadPoolExecutor(max(1, concurrency)) as ex:
        list(ex.map(lambda p: ledger.invoke(fn, p), payloads))
