"""rbpre.rbabpre: the retrieval-bound interface RB = (Setup, KeyGen, Enc,
ReKeyGen, ReEnc, Dec) of Section III-C (Eq. 1-15), over the CP-ABPRE of [41].

    chi    = (ComC, ctx, e, sid, Scope, Purpose)                  (Eq. 2, 67)
    h_chi  = H(ComC || ctx || e || sid || Scope || Purpose)          (Eq. 3, 68)
    rk     <- ABPRE.ReKeyGen(PP, sk_{A,S_A}, P_A, P_B)               (Eq. 8)
    D_RK   = (H(rk), h_chi, pk_B, H(P_A), H(P_B))                    (Eq. 9)
    s_KMS  = Sign_skKMS(D_RK)                                         (Eq. 10)
    RK_AB  = (rk, h_chi, pk_B, P_A, P_B, s_KMS)                       (Eq. 11)
    ReEnc: Verify_pkKMS(s_KMS, D_RK) = 1 and H(chi) = h_chi, then
           CT_B <- ABPRE.ReEnc(PP, CT_A, rk)                         (Eq. 12-13)

The binding of chi to the re-key is authenticated (a KMS signature over the
descriptor), not algebraic: the proxy is assumed protocol-compliant, as in the
paper's security model. The proxy's additional checks (current authorization,
recipient correspondence and membership of the ciphertext in T_auth) depend on
protocol state and are made by the Proxy role in rbpre/protocol.py before it
calls reencrypt().
"""

from __future__ import annotations

from dataclasses import dataclass

from rbpre import policy as pol
from rbpre import sig
from rbpre.abpre import ABPREError, CPABPRE
from rbpre.encoding import H, encode


def id_attr(did: str) -> str:
    """The unique certified recipient attribute idAttr(DID) (Eq. 20)."""
    return "id:" + did


@dataclass(frozen=True)
class Descriptor:
    """The retrieval descriptor chi (Eq. 2, 67)."""

    com_c: bytes
    ctx: bytes
    e: int
    sid: bytes
    scope: str
    purpose: str

    def digest(self) -> bytes:
        return H(self.com_c, self.ctx, self.e, self.sid, self.scope, self.purpose)


class RBError(Exception):
    """Every RB-ABPRE validation failure (the paper's bottom)."""


def descriptor_bytes(scheme: CPABPRE, rk_state: dict) -> bytes:
    """D_RK = (H(rk), h_chi, pk_B, H(P_A), H(P_B)) (Eq. 9), canonically encoded."""
    return encode(
        H(scheme.dumps(rk_state["rk"])),
        rk_state["h_chi"],
        rk_state["pk_b"],
        H(rk_state["p_a"]),
        H(rk_state["p_b"]),
    )


class KMS:
    """Holds MSK_RB and sk_KMS; issues keys and authenticated re-key states."""

    def __init__(self, scheme: CPABPRE, universe):
        self.scheme = scheme
        self.pp, self._msk = scheme.setup(universe)  # Eq. 4
        self._sig = sig.keygen()  # Eq. 5
        self.pk_kms = self._sig.pk
        self._registered: dict[bytes, tuple[str, list[str]]] = {}  # pk_ID -> (ID, S)
        self._source_keys: dict[str, dict] = {}  # DID_HA -> sk_{A,S_A}

    def add_attribute(self, attr: str) -> None:
        self.scheme.add_attribute(self.pp, self._msk, attr)

    def keygen(self, ident: str, pk_id: bytes, attrs) -> dict:
        """sk_{ID,S} <- KeyGen(MSK, ID, S) (Eq. 6, 21); delivered to the entity."""
        for at in attrs:
            self.add_attribute(at)
        sk = self.scheme.keygen(self.pp, self._msk, attrs)
        self._registered[pk_id] = (ident, list(attrs))
        return sk

    def keygen_source(self, did_h: str, pk_h: bytes, attrs) -> None:
        """sk_{A,S_A} <- KeyGen(MSK, DID_HA, S_A), retained by the KMS (Eq. 22)."""
        self._source_keys[did_h] = self.keygen(did_h, pk_h, attrs)

    def rekeygen(self, did_ha: str, p_a: str, p_b: str, pk_b: bytes, chi: Descriptor) -> dict:
        """RK_AB <- ReKeyGen(MSK, pk_B, P_A, ., ., chi) (Eq. 8-11).

        The consent, delegation, authorization, epoch and session checks of
        Eq. 82 are made by the protocol layer before this call.
        """
        if did_ha not in self._source_keys:
            raise RBError(f"no source key for {did_ha}")
        reg = self._registered.get(pk_b)
        if reg is None:
            raise RBError("recipient public key is not registered")
        if id_attr(reg[0]) not in pol.attributes(pol.parse(p_b)):
            raise RBError("destination policy lacks the recipient's idAttr(DID_B)")
        try:
            rk = self.scheme.rekeygen(self.pp, self._source_keys[did_ha], p_a, p_b)
        except ABPREError as e:
            raise RBError(str(e)) from e
        state = {
            "rk": rk,
            "h_chi": chi.digest(),
            "pk_b": pk_b,
            "p_a": pol.canon(p_a),
            "p_b": pol.canon(p_b),
        }
        state["sigma_kms"] = self._sig.sign(descriptor_bytes(self.scheme, state))
        return state


def enc(scheme: CPABPRE, pp: dict, p_a: str) -> tuple[bytes, dict]:
    """(K_AES, CT_A) <- Enc(PP, pk_A, P_A, M) (Eq. 7, 43), as a KEM."""
    return scheme.encapsulate(pp, p_a)


def reencrypt(scheme: CPABPRE, pp: dict, pk_kms: bytes, ct_a: dict, rk_state: dict,
              chi: Descriptor) -> dict:
    """CT_B <- ReEnc(PP, CT_A, RK_AB, chi) (Eq. 12-13)."""
    if not sig.verify(pk_kms, rk_state["sigma_kms"], descriptor_bytes(scheme, rk_state)):
        raise RBError("KMS signature on the re-key descriptor is invalid")
    if chi.digest() != rk_state["h_chi"]:
        raise RBError("retrieval descriptor does not match the re-key state")
    if ct_a.get("policy") != rk_state["p_a"]:
        raise RBError("ciphertext policy does not match the re-key source policy")
    try:
        return scheme.reencrypt(pp, rk_state["rk"], ct_a)
    except ABPREError as e:
        raise RBError(str(e)) from e


def dec(scheme: CPABPRE, pp: dict, sk_b: dict, ct_b: dict) -> bytes:
    """K_AES <- Dec(sk_{B,S_B}, CT_B, chi) (Eq. 14, 91)."""
    try:
        return scheme.decapsulate(pp, sk_b, ct_b)
    except (ABPREError, ZeroDivisionError) as e:
        raise RBError(str(e)) from e
