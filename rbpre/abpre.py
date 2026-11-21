"""rbpre.abpre: the CP-ABPRE construction of Ibraimi, Asim and Petkovic [41].

L. Ibraimi, M. Asim, M. Petkovic, "An encryption scheme for a secure policy
updating", SECRYPT 2010, pp. 399-408. Symmetric pairing e: G0 x G0 -> GT of
prime order p, here Charm-Crypto's SS512 (about 80-bit security).

    Setup      PK = (g, e(g,g)^(a+b), g^f, {T_j = g^(x_j)}),  MK = (a, b, f, {x_j})
    KeyGen     SK = (D1 = g^(a-r), {D2_j = g^((r+b)/x_j)})
    Enc        C1 = g^s, C2 = m e(g,g)^((a+b)s), C3 = g^(fs), {C4_j = T_j^(s_j)}
    RKGen      D^1 = D1 g^l, D^2 = Enc'(g^(x-l), P2), D^3 = g^(x'), {D^4_j = D2_j}
    ReEnc      C^1 = C1, C^2 = e(C3, D^3) C2 / (e(C1, D^1) prod e(D^4_j, C4_j)),
               C^3 = D^2
    Dec        m = C2 / (e(D1, C1) prod e(D2_j, C4_j))
    Dec (re)   g^(x-l) = Dec'(C^3);  m = C^2 / e(C^1, g^(x-l))

Enc' encrypts a G0 element under the mask H1(e(g,g)^((a+b)z)), H1: GT -> G0.

Resolutions of points the paper leaves open (see DESIGN.md):
  * x is not defined in [41]. The delegator picks x' at random, publishes
    D^3 = g^(x'), and uses g^x = (g^f)^(x'), i.e. x = f x'. It never needs f.
  * H1 is Charm's hash-to-group on the serialized GT element.
  * Every attribute appears at most once per policy (enforced by policy.parse).
  * The attribute universe can be extended by the MK holder (add_attribute),
    so that each recipient DID can get its own certified attribute idAttr(DID).

The 256-bit AES data key is carried as a KEM (encapsulate / decapsulate):
K_AES = SHA-256(serialize(R)) for a random R in GT, and only CT_k = Enc(R) is
ever re-encrypted.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from charm.toolbox.pairinggroup import G1, GT, ZR, PairingGroup, pair

from rbpre import policy as pol

CURVE = os.environ.get("RBPRE_CURVE", "SS512")


class ABPREError(Exception):
    """Raised for every cryptographic or policy failure (the paper's bottom)."""


class CPABPRE:
    def __init__(self, curve: str = CURVE):
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # SS512 notice
            self.group = PairingGroup(curve)
        self.curve = curve

    # ------------------------------------------------------------------ utils

    def _rand(self):
        return self.group.random(ZR)

    def _h1(self, z_gt) -> Any:
        """H1: GT -> G0."""
        return self.group.hash(self.group.serialize(z_gt), G1)

    # ------------------------------------------------------------------ Setup

    def setup(self, universe):
        g = self.group.random(G1)
        a, b, f = self._rand(), self._rand(), self._rand()
        x = {at: self._rand() for at in universe}
        pk = {
            "g": g,
            "egg_ab": pair(g, g) ** (a + b),
            "g_f": g ** f,
            "T": {at: g ** xj for at, xj in x.items()},
        }
        mk = {"a": a, "b": b, "f": f, "x": x}
        return pk, mk

    def add_attribute(self, pk, mk, attr: str) -> None:
        """Extend the attribute universe (MK holder only)."""
        if attr in mk["x"]:
            return
        xj = self._rand()
        mk["x"][attr] = xj
        pk["T"][attr] = pk["g"] ** xj

    # ----------------------------------------------------------------- KeyGen

    def keygen(self, pk, mk, attrs) -> dict:
        attrs = list(dict.fromkeys(attrs))
        missing = [at for at in attrs if at not in mk["x"]]
        if missing:
            raise ABPREError(f"attributes outside the universe: {missing}")
        g, r = pk["g"], self._rand()
        return {
            "S": attrs,
            "D1": g ** (mk["a"] - r),
            "D2": {at: g ** ((r + mk["b"]) / mk["x"][at]) for at in attrs},
        }

    # ---------------------------------------------------------------- Encrypt

    def _enc_core(self, pk, policy: str):
        node = pol.parse(policy)
        missing = [at for at in pol.attributes(node) if at not in pk["T"]]
        if missing:
            raise ABPREError(f"policy attributes outside the universe: {missing}")
        s = self._rand()
        shares = pol.share(node, s, self._rand)
        g = pk["g"]
        core = {
            "policy": pol.canonical(node),
            "C1": g ** s,
            "C3": pk["g_f"] ** s,
            "C4": {at: pk["T"][at] ** sh for at, sh in shares.items()},
        }
        return core, s

    def encrypt(self, pk, m_gt, policy: str) -> dict:
        """CT_P <- Enc(m, P, PK), m in GT."""
        core, s = self._enc_core(pk, policy)
        core["C2"] = m_gt * (pk["egg_ab"] ** s)
        return core

    def _encrypt_g0(self, pk, m_g0, policy: str) -> dict:
        """Enc' for a G0 message (used inside RKGen for g^(x-l))."""
        core, z = self._enc_core(pk, policy)
        core["C2"] = m_g0 * self._h1(pk["egg_ab"] ** z)
        return core

    # ---------------------------------------------------------------- Decrypt

    def _blind(self, sk, ct) -> Any:
        """e(g,g)^((a+b)s) from a key whose attributes satisfy ct's policy."""
        leaves = pol.satisfying_set(pol.parse(ct["policy"]), sk["S"])
        if leaves is None:
            raise ABPREError("attributes do not satisfy the ciphertext policy")
        z = pair(sk["D1"], ct["C1"])
        for at in leaves:
            z *= pair(sk["D2"][at], ct["C4"][at])
        return z

    def decrypt(self, pk, sk, ct) -> Any:
        """m <- Dec(CT, SK) for an original or a re-encrypted ciphertext."""
        if ct.get("re"):
            inner = ct["C3"]
            g_xl = inner["C2"] / self._h1(self._blind(sk, inner))
            return ct["C2"] / pair(ct["C1"], g_xl)
        return ct["C2"] / self._blind(sk, ct)

    # ------------------------------------------------------------ Re-encrypt

    def rekeygen(self, pk, sk, p1: str, p2: str) -> dict:
        """rk_{P1->P2} <- RKGen(SK, P1, P2, PK), run by the delegator."""
        n1 = pol.parse(p1)
        leaves = pol.satisfying_set(n1, sk["S"])
        if leaves is None:
            raise ABPREError("delegator key does not satisfy the source policy")
        g = pk["g"]
        l, xp = self._rand(), self._rand()
        g_x = pk["g_f"] ** xp  # g^x with x = f x'
        return {
            "p1": pol.canonical(n1),
            "p2": pol.canon(p2),
            "D1": sk["D1"] * (g ** l),
            "D2": self._encrypt_g0(pk, g_x / (g ** l), p2),
            "D3": g ** xp,
            "D4": {at: sk["D2"][at] for at in leaves},
        }

    def reencrypt(self, pk, rk, ct) -> dict:
        """CT_P2 <- ReEnc(CT_P1, rk_{P1->P2}), run by the proxy."""
        if ct.get("re"):
            raise ABPREError("ciphertext is already re-encrypted (single hop)")
        if ct["policy"] != rk["p1"]:
            raise ABPREError("re-encryption key does not match the ciphertext policy")
        i1 = None
        for at, d4 in rk["D4"].items():
            t = pair(d4, ct["C4"][at])
            i1 = t if i1 is None else i1 * t
        i2 = pair(ct["C1"], rk["D1"]) * i1
        c2 = pair(ct["C3"], rk["D3"]) * (ct["C2"] / i2)
        return {"policy": rk["p2"], "re": 1, "C1": ct["C1"], "C2": c2, "C3": rk["D2"]}

    # -------------------------------------------------------------------- KEM

    def encapsulate(self, pk, policy: str) -> tuple[bytes, dict]:
        """(K_AES, CT_k): CT_k = Enc(R, P) for a random R in GT."""
        r = self.group.random(GT)
        return self.kdf(r), self.encrypt(pk, r, policy)

    def decapsulate(self, pk, sk, ct) -> bytes:
        return self.kdf(self.decrypt(pk, sk, ct))

    def kdf(self, r_gt) -> bytes:
        return hashlib.sha256(b"rbpre-kem|" + self.group.serialize(r_gt)).digest()

    # ----------------------------------------------------------- serialization

    def dumps(self, obj) -> bytes:
        """Deterministic byte encoding of keys and ciphertexts (sorted JSON)."""

        def enc(o):
            if isinstance(o, dict):
                return {k: enc(v) for k, v in o.items()}
            if isinstance(o, (list, tuple)):
                return [enc(v) for v in o]
            if isinstance(o, (str, int)) and not isinstance(o, bool):
                return o
            return {"__e": self.group.serialize(o).decode("ascii")}

        return json.dumps(enc(obj), sort_keys=True, separators=(",", ":")).encode()

    def loads(self, data: bytes):
        def dec(o):
            if isinstance(o, dict):
                if set(o) == {"__e"}:
                    return self.group.deserialize(o["__e"].encode("ascii"))
                return {k: dec(v) for k, v in o.items()}
            if isinstance(o, list):
                return [dec(v) for v in o]
            return o

        return dec(json.loads(data))
