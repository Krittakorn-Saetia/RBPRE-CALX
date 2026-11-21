"""Correctness tests for the crypto core: policy, CP-ABPRE [41], RB-ABPRE
(Eq. 1-15), AEAD, signatures, Merkle tree.

Run inside WSL:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import unittest

from rbpre import aead, merkle, sig
from rbpre import policy as pol
from rbpre import rbabpre as rb
from rbpre.abpre import ABPREError, CPABPRE
from rbpre.encoding import H, encode

UNIVERSE = ["hosp:HA", "hosp:HB", "role:physician", "role:nurse", "dept:cardio",
            "dept:er", "class:lab", "class:rx"]


class TestPolicy(unittest.TestCase):
    def test_parse_and_canonical(self):
        n = pol.parse("hosp:HA and (role:physician OR role:nurse)")
        self.assertEqual(pol.canonical(n), "(hosp:HA AND (role:physician OR role:nurse))")
        self.assertEqual(pol.attributes(n), ["hosp:HA", "role:physician", "role:nurse"])

    def test_repeated_attribute_rejected(self):
        with self.assertRaises(pol.PolicyError):
            pol.parse("a AND (a OR b)")

    def test_bad_syntax(self):
        for bad in ["", "a AND", "(a OR b", "a b", "AND a"]:
            with self.assertRaises(pol.PolicyError, msg=bad):
                pol.parse(bad)

    def test_satisfying_set_minimal(self):
        n = pol.parse("(a AND b) OR c")
        self.assertEqual(pol.satisfying_set(n, {"a", "b", "c"}), ["c"])
        self.assertEqual(pol.satisfying_set(n, {"a", "b"}), ["a", "b"])
        self.assertIsNone(pol.satisfying_set(n, {"a"}))

    def test_shares_reconstruct(self):
        n = pol.parse("(a AND b AND c) OR (d AND e)")
        import random
        sh = pol.share(n, 1000, lambda: random.randrange(-10**6, 10**6))
        self.assertEqual(sh["a"] + sh["b"] + sh["c"], 1000)
        self.assertEqual(sh["d"] + sh["e"], 1000)


class TestCPABPRE(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = CPABPRE("SS512")
        cls.pk, cls.mk = cls.s.setup(UNIVERSE + ["id:docB", "id:docC"])

    def test_encrypt_decrypt(self):
        from charm.toolbox.pairinggroup import GT
        m = self.s.group.random(GT)
        ct = self.s.encrypt(self.pk, m, "hosp:HA AND (role:physician OR role:nurse)")
        sk = self.s.keygen(self.pk, self.mk, ["hosp:HA", "role:nurse"])
        self.assertEqual(self.s.decrypt(self.pk, sk, ct), m)

    def test_non_satisfying_key_fails(self):
        from charm.toolbox.pairinggroup import GT
        ct = self.s.encrypt(self.pk, self.s.group.random(GT), "hosp:HA AND role:physician")
        sk = self.s.keygen(self.pk, self.mk, ["hosp:HB", "role:physician"])
        with self.assertRaises(ABPREError):
            self.s.decrypt(self.pk, sk, ct)

    def test_reencrypt_policy_to_policy(self):
        from charm.toolbox.pairinggroup import GT
        m = self.s.group.random(GT)
        p1 = "hosp:HA AND dept:cardio AND class:lab"
        p2 = "id:docB AND role:physician"
        ct = self.s.encrypt(self.pk, m, p1)
        sk_a = self.s.keygen(self.pk, self.mk, ["hosp:HA", "dept:cardio", "class:lab", "class:rx"])
        rk = self.s.rekeygen(self.pk, sk_a, p1, p2)
        ct2 = self.s.reencrypt(self.pk, rk, ct)
        self.assertEqual(ct2["policy"], pol.canon(p2))
        sk_b = self.s.keygen(self.pk, self.mk, ["id:docB", "role:physician"])
        self.assertEqual(self.s.decrypt(self.pk, sk_b, ct2), m)
        # a key satisfying only the old policy cannot open the new ciphertext
        with self.assertRaises(ABPREError):
            self.s.decrypt(self.pk, sk_a, ct2)
        # another recipient without idAttr(docB) cannot open it either
        sk_c = self.s.keygen(self.pk, self.mk, ["id:docC", "role:physician"])
        with self.assertRaises(ABPREError):
            self.s.decrypt(self.pk, sk_c, ct2)

    def test_reencrypt_with_or_policies(self):
        from charm.toolbox.pairinggroup import GT
        m = self.s.group.random(GT)
        p1 = "(hosp:HA AND dept:er) OR (hosp:HA AND class:rx)"
        with self.assertRaises(pol.PolicyError):  # hosp:HA repeated
            self.s.encrypt(self.pk, m, p1)
        p1 = "hosp:HA AND (dept:er OR class:rx)"
        p2 = "id:docB AND (role:physician OR role:nurse)"
        ct = self.s.encrypt(self.pk, m, p1)
        sk_a = self.s.keygen(self.pk, self.mk, ["hosp:HA", "class:rx"])
        ct2 = self.s.reencrypt(self.pk, self.s.rekeygen(self.pk, sk_a, p1, p2), ct)
        sk_b = self.s.keygen(self.pk, self.mk, ["id:docB", "role:nurse"])
        self.assertEqual(self.s.decrypt(self.pk, sk_b, ct2), m)

    def test_rekey_for_other_policy_rejected(self):
        from charm.toolbox.pairinggroup import GT
        ct = self.s.encrypt(self.pk, self.s.group.random(GT), "hosp:HA AND class:rx")
        sk_a = self.s.keygen(self.pk, self.mk, ["hosp:HA", "class:lab"])
        rk = self.s.rekeygen(self.pk, sk_a, "hosp:HA AND class:lab", "id:docB")
        with self.assertRaises(ABPREError):
            self.s.reencrypt(self.pk, rk, ct)

    def test_delegator_must_satisfy_source_policy(self):
        sk = self.s.keygen(self.pk, self.mk, ["hosp:HB"])
        with self.assertRaises(ABPREError):
            self.s.rekeygen(self.pk, sk, "hosp:HA", "id:docB")

    def test_serialization_roundtrip(self):
        k, ct = self.s.encapsulate(self.pk, "hosp:HA AND class:lab")
        ct2 = self.s.loads(self.s.dumps(ct))
        sk = self.s.keygen(self.pk, self.mk, ["hosp:HA", "class:lab"])
        self.assertEqual(self.s.decapsulate(self.pk, sk, ct2), k)
        self.assertEqual(self.s.dumps(ct), self.s.dumps(ct2))


class TestRBABPRE(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = CPABPRE("SS512")
        cls.kms = rb.KMS(cls.s, UNIVERSE)
        cls.did_b = "did:rb:docB"
        cls.key_b = sig.keygen()
        cls.sk_b = cls.kms.keygen(cls.did_b, cls.key_b.pk, ["role:physician", rb.id_attr(cls.did_b)])
        cls.kms.keygen_source("did:rb:HA", sig.keygen().pk, ["hosp:HA", "class:lab", "class:rx"])
        cls.p_a = "hosp:HA AND class:lab"
        cls.p_b = f"{rb.id_attr(cls.did_b)} AND role:physician"
        cls.chi = rb.Descriptor(os.urandom(32), os.urandom(32), 3, os.urandom(16), "lab", "treatment")

    def _rk(self):
        return self.kms.rekeygen("did:rb:HA", self.p_a, self.p_b, self.key_b.pk, self.chi)

    def test_full_path_with_payload(self):
        k_aes, ct_k = rb.enc(self.s, self.kms.pp, self.p_a)
        ad = H("PID*", "RID*", "phi", "hA", "ComC", 3)
        ct_m = aead.encrypt(k_aes, b"ECG 72 bpm, BP 120/80", ad)
        ct_kb = rb.reencrypt(self.s, self.kms.pp, self.kms.pk_kms, ct_k, self._rk(), self.chi)
        k2 = rb.dec(self.s, self.kms.pp, self.sk_b, ct_kb)
        self.assertEqual(k2, k_aes)
        self.assertEqual(aead.decrypt(k2, ct_m, ad), b"ECG 72 bpm, BP 120/80")
        with self.assertRaises(aead.AEADError):
            aead.decrypt(k2, ct_m, ad + b"x")

    def test_tampered_descriptor_rejected(self):
        _, ct_k = rb.enc(self.s, self.kms.pp, self.p_a)
        rk = dict(self._rk())
        rk["pk_b"] = sig.keygen().pk  # substitute another recipient key
        with self.assertRaises(rb.RBError):
            rb.reencrypt(self.s, self.kms.pp, self.kms.pk_kms, ct_k, rk, self.chi)

    def test_other_descriptor_rejected(self):
        _, ct_k = rb.enc(self.s, self.kms.pp, self.p_a)
        other = rb.Descriptor(self.chi.com_c, self.chi.ctx, self.chi.e + 1, self.chi.sid,
                              self.chi.scope, self.chi.purpose)
        with self.assertRaises(rb.RBError):
            rb.reencrypt(self.s, self.kms.pp, self.kms.pk_kms, ct_k, self._rk(), other)

    def test_other_source_policy_rejected(self):
        _, ct_k = rb.enc(self.s, self.kms.pp, "hosp:HA AND class:rx")
        with self.assertRaises(rb.RBError):
            rb.reencrypt(self.s, self.kms.pp, self.kms.pk_kms, ct_k, self._rk(), self.chi)

    def test_destination_policy_needs_id_attr(self):
        with self.assertRaises(rb.RBError):
            self.kms.rekeygen("did:rb:HA", self.p_a, "role:physician", self.key_b.pk, self.chi)

    def test_unregistered_recipient_rejected(self):
        with self.assertRaises(rb.RBError):
            self.kms.rekeygen("did:rb:HA", self.p_a, self.p_b, sig.keygen().pk, self.chi)


class TestPrimitives(unittest.TestCase):
    def test_encoding_unambiguous(self):
        self.assertNotEqual(encode("ab", "c"), encode("a", "bc"))
        self.assertNotEqual(H(1, 23), H(12, 3))

    def test_signature(self):
        k = sig.keygen()
        s = k.sign(b"m")
        self.assertTrue(sig.verify(k.pk, s, b"m"))
        self.assertFalse(sig.verify(k.pk, s, b"m2"))
        self.assertFalse(sig.verify(sig.keygen().pk, s, b"m"))

    def test_merkle(self):
        for n in range(1, 34):
            leaves = [H("flag", i) for i in range(n)]
            t = merkle.MerkleTree(leaves)
            for i in range(n):
                self.assertTrue(merkle.verify(leaves[i], t.proof(i), t.root), (n, i))
            self.assertFalse(merkle.verify(H("x"), t.proof(0), t.root))
        t = merkle.MerkleTree([H(0), H(1), H(2)])
        r = t.root
        t.append(H(3))
        self.assertNotEqual(r, t.root)
        self.assertTrue(merkle.verify(H(3), t.proof(3), t.root))


if __name__ == "__main__":
    unittest.main()
