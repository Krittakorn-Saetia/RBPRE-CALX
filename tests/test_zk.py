"""End-to-end tests of the holder-bound authorization proof through rbzk.

Mirrors Phase 3 Steps 1-3: the issuer signs VC_D over
H(Attr_D || DID_D || cid_D || t_VC) (Eq. 18), the gateway issues (n_G, t_G) and
h_ctx (Eq. 51), the doctor signs h_ctx with sk_D (Eq. 52) and proves R_auth
(Eq. 55-56); the gateway verifies the proof against x (Eq. 53).
"""

from __future__ import annotations

import os
import unittest

from rbpre.zk import ZK, ZKError, fe

M = 5


def statement(zk: ZK, sk_ci: str, pk_ci: str, sk_d: str, pk_d: str):
    attrs = [fe(f"attr:{i}") for i in range(M)]
    req = attrs[:M - 1] + [fe(0)]
    purp, scope = fe("purpose:treatment"), fe("scope:cardiology")
    t_start, t_end, t_g, t_vc, epoch = 1_700_000_000, 1_800_000_000, 1_750_000_000, 1_760_000_000, 3
    did, cid, pid = fe("did:rb:docD"), fe(os.urandom(32)), fe(os.urandom(32))
    n_g, cb = fe(os.urandom(32)), fe(os.urandom(32))
    h_a = zk.mimc(*req, purp, scope, fe(t_start), fe(t_end))
    vc = zk.sign(sk_ci, zk.mimc(*attrs, did, cid, fe(t_vc)))
    h_ctx = zk.mimc(did, cid, pid, purp, scope, fe(epoch), h_a, fe(t_g), n_g, cb)
    pub = dict(did=did, cid=cid, pid=pid, purpose=purp, scope=scope, epoch=epoch, tg=t_g,
               ng=n_g, hctx=h_ctx, ha=h_a, cb=cb, pk_ci=pk_ci, pk_d=pk_d)
    wit = dict(attr=attrs, tvc=t_vc, vc=vc, req=req, purp=purp, scope=scope, tstart=t_start,
               tend=t_end, sig_d=zk.sign(sk_d, h_ctx))
    return pub, wit


class TestHolderProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zk = ZK()
        cls.info = cls.zk.setup("holder", M)
        cls.sk_ci, cls.pk_ci = cls.zk.keygen()
        cls.sk_d, cls.pk_d = cls.zk.keygen()

    @classmethod
    def tearDownClass(cls):
        cls.zk.close()

    def test_honest_proof_verifies(self):
        pub, wit = statement(self.zk, self.sk_ci, self.pk_ci, self.sk_d, self.pk_d)
        p = self.zk.prove("holder", M, pub, wit)
        self.assertEqual(p["proof_bytes"], 192)
        self.assertTrue(self.zk.verify("holder", M, pub, p["proof"])["valid"])

    def test_replayed_proof_fails_new_challenge(self):
        pub, wit = statement(self.zk, self.sk_ci, self.pk_ci, self.sk_d, self.pk_d)
        p = self.zk.prove("holder", M, pub, wit)
        pub2 = dict(pub, ng=fe(os.urandom(32)))  # fresh gateway nonce
        self.assertFalse(self.zk.verify("holder", M, pub2, p["proof"])["valid"])

    def test_other_channel_binding_fails(self):
        pub, wit = statement(self.zk, self.sk_ci, self.pk_ci, self.sk_d, self.pk_d)
        p = self.zk.prove("holder", M, pub, wit)
        self.assertFalse(self.zk.verify("holder", M, dict(pub, cb=fe(os.urandom(32))), p["proof"])["valid"])

    def test_stolen_credential_without_holder_key(self):
        sk_x, _ = self.zk.keygen()
        pub, wit = statement(self.zk, self.sk_ci, self.pk_ci, sk_x, self.pk_d)
        with self.assertRaises(ZKError):
            self.zk.prove("holder", M, pub, wit)

    def test_forged_credential(self):
        sk_x, _ = self.zk.keygen()
        pub, wit = statement(self.zk, sk_x, self.pk_ci, self.sk_d, self.pk_d)
        with self.assertRaises(ZKError):
            self.zk.prove("holder", M, pub, wit)

    def test_signature_and_mimc(self):
        msg = fe(os.urandom(32))
        sig = self.zk.sign(self.sk_d, msg)
        self.assertTrue(self.zk.verify_sig(self.pk_d, msg, sig))
        self.assertFalse(self.zk.verify_sig(self.pk_ci, msg, sig))
        self.assertNotEqual(self.zk.mimc(fe(1), fe(2)), self.zk.mimc(fe(2), fe(1)))


if __name__ == "__main__":
    unittest.main()
