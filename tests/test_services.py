"""Integration tests for the off-chain services (Neo4j, MinIO, Redis).

They need `infra/services.sh up` and are skipped when a service is not
reachable. Each test only touches identifiers it creates.
"""

from __future__ import annotations

import os
import unittest


def _reachable(port: int) -> bool:
    import socket

    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


@unittest.skipUnless(_reachable(7687), "Neo4j not running")
class TestGraph(unittest.TestCase):
    def setUp(self):
        from rbpre.graph import RetrievalGraph

        self.g = RetrievalGraph()
        self.g.setup()
        self.p1, self.p1b, self.p2 = (os.urandom(8).hex() for _ in range(3))

    def tearDown(self):
        self.g.delete_patients([self.p1, self.p1b, self.p2, "renamed-" + self.p1])
        self.g.close()

    def test_candidates_over_historical_pseudonyms(self):
        rows = [
            dict(rid=os.urandom(8).hex(), pid=self.p1, phi="f1", ha="a1", uri="u1", hosp="did:rb:HA"),
            dict(rid=os.urandom(8).hex(), pid=self.p1b, phi="f2", ha="a1", uri="u2", hosp="did:rb:HB"),
            dict(rid=os.urandom(8).hex(), pid=self.p2, phi="f3", ha="a2", uri="u3", hosp="did:rb:HA"),
        ]
        self.g.add_records(rows)
        got = self.g.candidates([self.p1, self.p1b])  # two epochs of one patient
        self.assertEqual({r["rid"] for r in got}, {rows[0]["rid"], rows[1]["rid"]})
        self.assertEqual({r["hosp"] for r in got}, {"did:rb:HA", "did:rb:HB"})
        self.assertEqual(self.g.rename_patient(self.p1, "renamed-" + self.p1), 1)
        self.assertEqual(len(self.g.candidates([self.p1])), 0)
        self.assertEqual(len(self.g.candidates(["renamed-" + self.p1])), 1)
        new_rid = os.urandom(8).hex()
        self.assertEqual(self.g.rename_records([(rows[2]["rid"], new_rid)]), 1)
        self.assertEqual(self.g.candidates([self.p2])[0]["rid"], new_rid)


@unittest.skipUnless(_reachable(9000), "MinIO not running")
class TestStorage(unittest.TestCase):
    def test_roundtrip(self):
        from rbpre.storage import EHRStore

        s = EHRStore(bucket="ehr-test")
        s.setup()
        uri = s.put(b"ct_m bytes", b"ct_k bytes")
        self.assertEqual(s.get(uri), (b"ct_m bytes", b"ct_k bytes"))
        items = [(os.urandom(40), os.urandom(300)) for _ in range(20)]
        uris = s.put_many(items)
        self.assertEqual(s.get_many(uris), items)
        s.clear()


@unittest.skipUnless(_reachable(6379), "Redis not running")
class TestCache(unittest.TestCase):
    def setUp(self):
        from rbpre.cache import AuthCache

        self.c = AuthCache()

    def test_nonce_consumed_once(self):
        n = os.urandom(16)
        self.c.issue_nonce(n, 1234, lifetime_s=30)
        self.assertEqual(self.c.consume_nonce(n), 1234)
        self.assertIsNone(self.c.consume_nonce(n))  # replay
        self.assertIsNone(self.c.consume_nonce(os.urandom(16)))  # never issued

    def test_tag_invalidation(self):
        pid, other, doc = (os.urandom(8).hex() for _ in range(3))
        sid, kappa, sid2 = os.urandom(16), os.urandom(32), os.urandom(16)
        self.c.put_session(sid, b"session", 60, [pid, doc])
        self.c.put_rekey(kappa, b"rk-state", 60, [pid])
        self.c.put_session(sid2, b"other", 60, [other])
        self.assertEqual(self.c.get_rekey(kappa), b"rk-state")
        self.assertEqual(self.c.invalidate(pid), 2)
        self.assertIsNone(self.c.get_session(sid))
        self.assertIsNone(self.c.get_rekey(kappa))
        self.assertEqual(self.c.get_session(sid2), b"other")
        self.assertEqual(self.c.invalidate(doc), 0)  # already gone
        self.c.invalidate(other)


if __name__ == "__main__":
    unittest.main()
