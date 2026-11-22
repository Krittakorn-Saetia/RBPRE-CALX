#!/usr/bin/env python3
"""Revocation and consent-update cost (Phase 5 Step 5).

For a patient with N records and S live holder-bound sessions (each with its
cached re-key states), every run measures four events:

  policy update        new epoch (ComRev_{e+1}), new pseudonym PID*_{e+1} and
                       ComC^{e+1}, superseding the old consent; invalidation of
                       the patient's sessions and re-key states; then the
                       hospitals re-issue delegation tokens for the new epoch
  consent withdrawal   CRec_C -> revoked, epoch advance, invalidation
  delegation revocation  DRec_ctx -> revoked, epoch advance, invalidation
  credential revocation  CRec_D -> revoked, invalidation of the doctor's entries

For the policy update it also measures the first retrieval after the event
(new proof, new linkage entries for the new epoch, re-key cache misses)
against a steady-state retrieval before it. The steady-state retrieval is a
repeated request in a live session, measured after one untimed retrieval
under the current epoch, so its linkage entries already exist. It checks
that all records, including those of earlier epochs, are still retrieved, so
no stored record is re-pseudonymized. Each Fabric write waits for commit, so the event times
include finalization.

Compared schemes: [27] re-encrypts every affected ciphertext under the new
policy (T_P + (m+1) T_E + m T_M per record), [31] performs one state update
with consensus, and [25] blacklists at its authority (T_H).

Top-up runs (RBPRE_TOPUP set, see harness): --only limits the measured
points to tokens RBPRE-CALX:n:S (one run measures every RBPRE-CALX event at
that point) and <scheme>:n for the compared schemes, e.g. "[25]:1000". The
patient history still grows through every --n.

    python -m experiments.exp_revocation [--n 1000 5000 10000] [--sessions 1 10 50] [--runs 10]
"""

from __future__ import annotations

import argparse
import gc

from baselines.common import Prims
from baselines.schemes import Luo31, Wang25, Yan27
from experiments.exp234_retrieval import Series
from experiments.harness import save_machine, selected, services, write_rows
from experiments.workload import World
from rbpre.protocol import Timer


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, nargs="+", default=[1000, 5000, 10000])
    ap.add_argument("--sessions", type=int, nargs="+", default=[1, 10, 50])
    ap.add_argument("--hospitals", type=int, default=5)
    ap.add_argument("--ratio", type=float, default=0.10)
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--m", type=int, default=10)
    ap.add_argument("--only", nargs="*", help="measure only these points: RBPRE-CALX:n:S or <scheme>:n")
    args = ap.parse_args()
    save_machine()
    ledger, graph, store, cache = services(True, bucket="ehr-rev")
    w = World(ledger, graph, store, cache, hospitals=args.hospitals, m=args.m)
    s, doc = w.s, w.doc
    target = w.new_target()
    p = target.patient
    pr = Prims()
    y27, l31, w25 = Yan27(pr, ledger, m=args.m), Luo31(pr, ledger), Wang25(pr, ledger)
    rows, steps = [], []

    def record(event, n, sess_n, r, t: Timer, **kw):
        rows.append(dict(scheme="RBPRE-CALX", event=event, n=n, sessions=sess_n, run=r, ms=t.total(),
                         invalidated=t.n.get("rev.entries_invalidated", 0), **kw))
        steps.extend(dict(event=event, n=n, sessions=sess_n, run=r, step=k, ms=v) for k, v in t.ms.items())

    def redelegate(t: Timer | None = None):
        t = t or Timer()
        s.issue_delegations(p, w.hosp, doc.domain, t)    # every hospital re-issues its DelTok at once

    for n in args.n:
        w.grow(target, n, args.ratio)
        sess0 = s.authorize(doc, p, "treatment", "cardiology")
        ref = s.discover(sess0)
        prime = list({(c["hosp"], c["open"]["meta"]["cls"]): c for c in ref}.values())
        s.transform(sess0, ref)

        def populate(doctor, k):
            """k live sessions of `doctor`, each with its cached re-key states."""
            out = []
            for _ in range(k):
                se = s.authorize(doctor, p, "treatment", "cardiology")
                s.transform(se, [dict(c) for c in prime])
                out.append(se)
            s.pending_anchors.clear()
            return out

        for sess_n in args.sessions:
            if not selected(args.only, "RBPRE-CALX", n, sess_n):
                continue
            for r in range(args.runs):
                gc.collect()
                gc.disable()  # no collector pauses inside the timed events (re-enabled below)
                # ---- policy update, with steady-state and first retrieval around it
                live = populate(doc, sess_n)
                # Untimed retrieval first. The previous run ended with an epoch advance, so the
                # first retrieval of this run would anchor the new epoch's linkage entries.
                s.transform(live[0], s.discover(live[0]))
                s.pending_anchors.clear()
                t = Timer()
                s.transform(live[-1], s.discover(live[-1], t), t)
                record("steady-state retrieval", n, sess_n, r, t)
                t = Timer()
                s.update_policy(p, w.policy, t)
                record("policy update", n, sess_n, r, t)
                t = Timer()
                redelegate(t)
                record("re-delegation (all hospitals)", n, sess_n, r, t)
                t = Timer()
                se = s.authorize(doc, p, "treatment", "cardiology", t)
                ta = s.discover(se, t)
                s.transform(se, ta, t)
                assert {c["rid"] for c in ta} == target.authorized, "records lost after the epoch advance"
                record("first retrieval after update", n, sess_n, r, t, t_auth=len(ta))
                # ---- consent withdrawal (restored afterwards, untimed)
                populate(doc, sess_n)
                t = Timer()
                s.withdraw_consent(p, t)
                record("consent withdrawal", n, sess_n, r, t)
                s.update_policy(p, w.policy)
                redelegate()
                # ---- delegation revocation (restored afterwards, untimed)
                populate(doc, sess_n)
                t = Timer()
                s.revoke_delegation(p, p.home, doc.domain, t)
                record("delegation revocation", n, sess_n, r, t)
                s.update_policy(p, w.policy)
                redelegate()
                # ---- credential revocation of a second doctor with live sessions
                other, = s.enroll_doctors([(f"doc{w.tag}r{n}s{sess_n}x{r}", doc.domain, list(doc.attrs))])
                populate(other, sess_n)
                t = Timer()
                s.revoke_credential(other, t)
                record("credential revocation", n, sess_n, r, t)
                s.pending_anchors.clear()
                gc.enable()
            cur = [x for x in rows if x["n"] == n and x["sessions"] == sess_n]
            print(f"N={n:<6} S={sess_n:<4} " + "  ".join(
                f"{ev}: {sum(x['ms'] for x in cur if x['event'] == ev) / args.runs:7.0f}"
                for ev in dict.fromkeys(x["event"] for x in cur)))
            write_rows("erev_runs.csv", rows)
            write_rows("erev_steps.csv", steps)

        # compared schemes: cost of one policy update / revocation at this N
        ser = Series(args.runs, max(3, args.runs // 3), 60.0)
        pat = [e for e in w.index if e.owner == target.owner]
        for name, fn in (("[27]", lambda: y27.policy_update(pat)), ("[31]", l31.revoke), ("[25]", w25.revoke)):
            if not selected(args.only, name, n):
                continue
            for i, ms in enumerate(ser(fn)):
                rows.append(dict(scheme=name, event="policy update / revocation", n=n, sessions="", run=i, ms=ms))
        write_rows("erev_runs.csv", rows)
    w.close()
    store.clear()


if __name__ == "__main__":
    main()
