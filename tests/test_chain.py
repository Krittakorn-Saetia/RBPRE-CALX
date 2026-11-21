"""The chain client against the in-memory mirror and, when the test-network
is up, against the deployed chaincode. Both must behave the same."""

from __future__ import annotations

import os
import socket
import unittest

from rbpre.chain import FabricLedger, MemoryLedger


def _peer_up() -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", 7051)) == 0


class _Scenario:
    ledger = None

    def test_lifecycle(self):
        L = self.ledger
        u = os.urandom(6).hex()
        did, cid, com, hdel, eh = (f"{p}-{u}" for p in ("did", "cid", "com", "del", "eh"))
        L.register_dids([{"did": did, "pk": "ab" * 32, "domain": "did:rb:HB"}])
        L.register_credentials([{"id": cid, "owner": did, "t": 1_800_000_000}])
        L.register_consent(com, 1, 1_800_000_000)
        L.register_delegation(hdel, 1, 1_800_000_000)
        e, _ = L.advance_epoch(eh, "rev1")
        self.assertEqual(e, 1)
        recs = [{"id": f"rid{i}-{u}", "v": f"com{i}"} for i in range(5)]
        n, _, n_tx = L.anchor_records(recs)
        self.assertEqual((n, n_tx), (5, 1))
        L.anchor_flags([{"id": f"flag-{u}", "e": 1}])
        L.set_root(f"pid-{u}", "root1")
        st, _, _ = L.get_state({"did": [did], "cred": [cid], "cons": [com], "del": [hdel],
                                "epoch": [eh], "rec": [r["id"] for r in recs] + ["missing"],
                                "flag": [f"flag-{u}"], "root": [f"pid-{u}"]})
        self.assertEqual(st["did"][did]["pk"], "ab" * 32)
        self.assertEqual(st["cred"][cid]["owner"], did)
        self.assertEqual(st["cred"][cid]["status"], "active")
        self.assertEqual(st["cons"][com]["e"], 1)
        self.assertEqual(st["epoch"][eh]["e"], 1)
        self.assertEqual(st["rec"][recs[3]["id"]], "com3")
        self.assertNotIn("missing", st["rec"])
        self.assertEqual(st["flag"][f"flag-{u}"]["status"], "active")
        self.assertEqual(st["root"][f"pid-{u}"], "root1")

        # policy update supersedes the old consent; revocation flips status
        L.register_consent(com + "-2", 2, 1_800_000_000, com)
        L.set_status("cred", cid, "revoked")
        e2, _ = L.advance_epoch(eh, "rev2")
        st, _, _ = L.get_state({"cons": [com, com + "-2"], "cred": [cid], "epoch": [eh]})
        self.assertEqual(st["cons"][com]["status"], "superseded")
        self.assertEqual(st["cons"][com + "-2"]["status"], "active")
        self.assertEqual(st["cred"][cid]["status"], "revoked")
        self.assertEqual((e2, st["epoch"][eh]["e"]), (2, 2))


class TestMemoryLedger(_Scenario, unittest.TestCase):
    def setUp(self):
        self.ledger = MemoryLedger()

    def test_chunking(self):
        recs = [{"id": "r%05d" % i + "x" * 60, "v": "y" * 64} for i in range(3000)]
        n, _, n_tx = self.ledger.anchor_records(recs)
        self.assertEqual(n, 3000)
        self.assertGreater(n_tx, 1)
        st, _, n_q = self.ledger.get_state({"rec": [r["id"] for r in recs]})
        self.assertEqual(len(st["rec"]), 3000)
        self.assertGreater(n_q, 1)


@unittest.skipUnless(_peer_up(), "Fabric test-network not running")
class TestFabricLedger(_Scenario, unittest.TestCase):
    def setUp(self):
        self.ledger = FabricLedger()


if __name__ == "__main__":
    unittest.main()
