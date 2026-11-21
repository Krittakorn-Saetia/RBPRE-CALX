"""End-to-end test of Phases 1-5 on the real off-chain services.

The ledger is the in-memory mirror by default; set RBPRE_FABRIC=1 to run the
same scenario on the Fabric test-network (each write then waits for commit).
Needs Neo4j, MinIO and Redis (infra/services.sh up) and the rbzk binary.
"""

from __future__ import annotations

import os
import socket
import unittest

from rbpre.protocol import Policy, RBPRESystem, Record, Rejected, now


def _up(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


SERVICES = all(_up(p) for p in (7687, 9000, 6379))


@unittest.skipUnless(SERVICES, "Neo4j, MinIO and Redis must be running")
class TestProtocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from rbpre.cache import AuthCache
        from rbpre.chain import MemoryLedger
        from rbpre.graph import RetrievalGraph
        from rbpre.storage import EHRStore
        from rbpre.zk import ZK

        from rbpre.chain import GatewayLedger

        ledger = GatewayLedger() if os.environ.get("RBPRE_FABRIC") == "1" else MemoryLedger()
        cls.graph = RetrievalGraph()
        cls.graph.setup()
        store = EHRStore(bucket="ehr-test")
        store.setup()
        cls.zk = ZK()
        s = cls.sys = RBPRESystem(ledger, cls.graph, store, AuthCache(), cls.zk, m=5)
        s.setup()
        cls.HA, cls.HB, cls.HC, cls.HD = (s.add_hospital(n + os.urandom(3).hex()).did
                                          for n in ("HA", "HB", "HC", "HD"))
        cls.doc, cls.doc_x = s.enroll_doctors([
            ("docD" + os.urandom(3).hex(), cls.HB, ["role:physician", "dept:cardiology"]),
            ("docX" + os.urandom(3).hex(), cls.HB, ["role:physician", "dept:dermatology"]),
        ])
        t0 = now()
        cls.policy = Policy(["role:physician", "dept:cardiology"], "treatment", "cardiology",
                            t0 - 365 * 86400, t0 + 365 * 86400)
        cls.p = s.enroll_patient("alice", cls.HA, cls.policy)
        for src in (cls.HA, cls.HC):
            s.issue_delegation(cls.p, src, cls.HB)
        recs = [
            Record(cls.HA, "lab-panel", "lab", t0 - 86400, [b"Hb 13.5", b"WBC 6.1"]),
            Record(cls.HA, "ecg-12lead", "ecg", t0 - 7200, [b"sinus rhythm 72 bpm"]),
            Record(cls.HA, "psych-note", "psych", t0 - 3600, [b"psych session"]),
            Record(cls.HC, "prescription", "rx", t0 - 600, [b"atorvastatin 20 mg"]),
            Record(cls.HC, "billing", "admin", t0 - 500, [b"invoice"]),
            Record(cls.HD, "lab-panel", "lab", t0 - 400, [b"no delegation from HD"]),
        ]
        cls.rids = s.ingest(cls.p, recs)
        cls.expected = {cls.rids[0]: b"Hb 13.5\nWBC 6.1", cls.rids[1]: b"sinus rhythm 72 bpm",
                        cls.rids[3]: b"atorvastatin 20 mg"}

    @classmethod
    def tearDownClass(cls):
        cls.graph.delete_patients(cls.sys.cs_pids.get(cls.p.pid, []))
        cls.graph.close()
        cls.zk.close()

    def test_1_retrieve_only_authorized_records(self):
        sess = self.sys.authorize(self.doc, self.p, "treatment", "cardiology")
        got = {r.rid: r.plaintext for r in self.sys.retrieve(sess)}
        self.assertEqual(got, self.expected)
        # second retrieval in the same session reuses the re-key states
        from rbpre.protocol import Timer
        t = Timer()
        got2 = {r.rid: r.plaintext for r in self.sys.retrieve(sess, t)}
        self.assertEqual(got2, self.expected)
        self.assertGreater(t.n.get("p5.rk_hit", 0), 0)
        self.assertEqual(t.n.get("p5.rk_miss", 0), 0)
        self.assertGreater(self.sys.flush_anchors(), 0)

    def test_2_requester_without_required_attribute(self):
        with self.assertRaises(Rejected):
            self.sys.authorize(self.doc_x, self.p, "treatment", "cardiology")

    def test_3_purpose_outside_consent(self):
        with self.assertRaises(Rejected):
            self.sys.authorize(self.doc, self.p, "research", "cardiology")

    def test_4_policy_update_keeps_history_and_invalidates_sessions(self):
        s = self.sys
        sess = s.authorize(self.doc, self.p, "treatment", "cardiology")
        s.update_policy(self.p, self.policy)       # new epoch, PID*, ComC
        with self.assertRaises(Rejected):          # old session is invalidated
            s.retrieve(sess)
        for src in (self.HA, self.HC):
            s.issue_delegation(self.p, src, self.HB)
        t0 = now()
        new = s.ingest(self.p, [Record(self.HA, "vitals", "vitals", t0, [b"BP 120/80"])])
        sess2 = s.authorize(self.doc, self.p, "treatment", "cardiology")
        got = {r.rid: r.plaintext for r in s.retrieve(sess2)}
        self.assertEqual(got, dict(self.expected, **{new[0]: b"BP 120/80"}))

    def test_5_credential_revocation(self):
        s = self.sys
        sess = s.authorize(self.doc, self.p, "treatment", "cardiology")
        s.revoke_credential(self.doc)
        with self.assertRaises(Rejected):
            s.retrieve(sess)
        with self.assertRaises(Rejected):
            s.authorize(self.doc, self.p, "treatment", "cardiology")


if __name__ == "__main__":
    unittest.main()
