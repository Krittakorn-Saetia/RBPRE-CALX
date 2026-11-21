#!/usr/bin/env python3
"""Experiment 1: holder-bound authorization cost and scalability.

  (a) circuit cost: the original and the holder-bound R_auth for
      m in {5, 10, 15, 20, 25, 30}: R1CS constraints, setup, proving and
      verification time, proof and key sizes;
  (b) cumulative authorization latency for k requests: RBPRE-CALX Fresh (a new
      holder-bound proof per request) and Reuse (sessions of --session-size
      requests: one proof per session, ValidState for the others), and the
      authentication of [25], [27], [31];
  (c) freshness, replay and holder-binding checks: each attack once per run,
      with the outcome and the time to rejection.

    python -m experiments.exp1_authz [--parts abc] [--runs 30] [--offline]

Writes e1a_setup.csv, e1a_runs.csv, e1b_runs.csv, e1b_steps.csv, e1c_checks.csv.
"""

from __future__ import annotations

import argparse
import os
import threading
import time
from dataclasses import replace

from experiments.harness import save_machine, services, write_rows
from rbpre.protocol import Policy, RBPRESystem, Rejected, Timer, now
from rbpre.zk import ZK, fe


# ------------------------------------------------------------------ part (a)

def statement(zk: ZK, circuit: str, m: int, keys) -> tuple[dict, dict]:
    """A satisfying (x, w) for either circuit with m slots."""
    sk_ci, pk_ci, sk_d, pk_d = keys
    attrs = [fe(f"attr:{i}") for i in range(m)]
    req = attrs[:m - 1] + [fe(0)]
    purp, scope = fe("purpose:treatment"), fe("scope:cardiology")
    t0 = now()
    t_start, t_end, t_g, t_vc, e = t0 - 86400, t0 + 86400, t0, t0 + 3600, 1
    did, cid, pid = fe("did:rb:doc"), fe(os.urandom(32)), fe(os.urandom(32))
    h_a = zk.mimc(*req, purp, scope, fe(t_start), fe(t_end))
    wit = dict(attr=attrs, tvc=t_vc, req=req, purp=purp, scope=scope, tstart=t_start, tend=t_end)
    if circuit == "holder":
        n_g, cb = fe(os.urandom(32)), fe(os.urandom(32))
        wit["vc"] = zk.sign(sk_ci, zk.mimc(*attrs, did, cid, fe(t_vc)))
        h_ctx = zk.mimc(did, cid, pid, purp, scope, fe(e), h_a, fe(t_g), n_g, cb)
        wit["sig_d"] = zk.sign(sk_d, h_ctx)
        pub = dict(did=did, cid=cid, pid=pid, purpose=purp, scope=scope, epoch=e, tg=t_g, ng=n_g,
                   hctx=h_ctx, ha=h_a, cb=cb, pk_ci=pk_ci, pk_d=pk_d)
    else:
        wit["vc"] = zk.sign(sk_ci, zk.mimc(*attrs, did, fe(t_vc)))
        h_ctx = zk.mimc(did, pid, purp, scope, fe(e))
        pub = dict(did=did, pid=pid, purpose=purp, scope=scope, epoch=e, tnow=t_g, hctx=h_ctx, ha=h_a,
                   pk_ci=pk_ci)
    return pub, wit


def part_a(ms_list, runs) -> None:
    setup_rows, run_rows = [], []
    with ZK() as zk:
        keys = (*zk.keygen(), *zk.keygen())
        for m in ms_list:
            for circuit in ("original", "holder"):
                info = zk.setup(circuit, m)
                setup_rows.append(dict(circuit=circuit, m=m, constraints=info["constraints"],
                                       public_inputs=info["public"], compile_ms=info["compile_ms"],
                                       setup_ms=info["setup_ms"], pk_bytes=info["pk_bytes"],
                                       vk_bytes=info["vk_bytes"]))
                for r in range(runs):
                    pub, wit = statement(zk, circuit, m, keys)
                    p = zk.prove(circuit, m, pub, wit)
                    v = zk.verify(circuit, m, pub, p["proof"])
                    assert v["valid"], (circuit, m)
                    run_rows.append(dict(circuit=circuit, m=m, run=r, witness_ms=p["witness_ms"],
                                         prove_ms=p["prove_ms"], prove_rtt_ms=p["rtt_ms"],
                                         verify_ms=v["verify_ms"], verify_rtt_ms=v["rtt_ms"],
                                         proof_bytes=p["proof_bytes"]))
                print(f"  (a) {circuit:<8} m={m:<3} {info['constraints']:>7} constraints  "
                      f"prove {sum(x['prove_ms'] for x in run_rows[-runs:]) / runs:8.1f} ms")
    write_rows("e1a_setup.csv", setup_rows)
    write_rows("e1a_runs.csv", run_rows)


# ------------------------------------------------------------- shared world

def world(fabric: bool, m: int):
    ledger, graph, store, cache = services(fabric)
    zk = ZK()
    s = RBPRESystem(ledger, graph, store, cache, zk, m=m)
    s.setup()
    tag = os.urandom(3).hex()
    ha, hb = s.add_hospital("HA" + tag).did, s.add_hospital("HB" + tag).did
    attrs = ["role:physician", "dept:cardiology"] + [f"cert:{i}" for i in range(m - 2)]
    doc, = s.enroll_doctors([("doc" + tag, hb, attrs)])
    t0 = now()
    pol = Policy(attrs[:m - 1], "treatment", "cardiology", t0 - 365 * 86400, t0 + 365 * 86400)
    p = s.enroll_patient("pat" + tag, ha, pol)
    s.issue_delegation(p, ha, hb)
    return s, zk, doc, p, (ha, hb, pol)


# ------------------------------------------------------------------ part (b)

def part_b(s: RBPRESystem, doc, p, ks, runs, session_size, ledger) -> None:
    from baselines.common import Prims
    from baselines.schemes import Luo31, Wang25, Yan27

    pr = Prims()
    base = [Wang25(pr, ledger), Yan27(pr, ledger, m=s.m), Luo31(pr, ledger)]
    base[2].bind(doc.did)
    rows, steps = [], []
    for k in ks:
        for r in range(runs):
            # RBPRE-CALX Fresh: one holder-bound proof per request
            t = Timer()
            t0 = time.perf_counter_ns()
            for _ in range(k):
                s.authorize(doc, p, "treatment", "cardiology", t)
            rows.append(dict(scheme="RBPRE-CALX Fresh", k=k, run=r, total_ms=(time.perf_counter_ns() - t0) / 1e6,
                             proofs=k))
            steps += [dict(scheme="RBPRE-CALX Fresh", k=k, run=r, step=n_, ms=v) for n_, v in t.ms.items()]
            # RBPRE-CALX Reuse: one proof per session of `session_size` requests
            t = Timer()
            t0 = time.perf_counter_ns()
            sess, proofs = None, 0
            for i in range(k):
                if i % session_size == 0:
                    sess = s.authorize(doc, p, "treatment", "cardiology", t)
                    proofs += 1
                else:
                    s.valid_state(sess, t, "reuse.valid_state")
            rows.append(dict(scheme="RBPRE-CALX Reuse", k=k, run=r, total_ms=(time.perf_counter_ns() - t0) / 1e6,
                             proofs=proofs))
            steps += [dict(scheme="RBPRE-CALX Reuse", k=k, run=r, step=n_, ms=v) for n_, v in t.ms.items()]
            for b in base:
                t0 = time.perf_counter_ns()
                for _ in range(k):
                    b.auth_request()
                rows.append(dict(scheme=b.name, k=k, run=r, total_ms=(time.perf_counter_ns() - t0) / 1e6))
        last = [x for x in rows if x["k"] == k]
        print(f"  (b) k={k:<4} " + "  ".join(
            f"{sch}: {sum(x['total_ms'] for x in last if x['scheme'] == sch) / runs:9.1f} ms"
            for sch in dict.fromkeys(x["scheme"] for x in last)))
        s.pending_anchors.clear()
    write_rows("e1b_runs.csv", rows)
    write_rows("e1b_steps.csv", steps)


# ------------------------------------------------------------------ part (c)

def part_c(s: RBPRESystem, zk: ZK, doc, p, runs) -> None:
    from rbpre.protocol import AUTH_LIFETIME_S

    rows = []

    def attempt(name, fn, expect_reject):
        t0 = time.perf_counter_ns()
        try:
            fn()
            outcome, reason = "accepted", ""
        except Rejected as ex:
            outcome, reason = "rejected", str(ex).split(":")[0]
        ms = (time.perf_counter_ns() - t0) / 1e6
        rows.append(dict(check=name, run=r, outcome=outcome, expected="rejected" if expect_reject else "accepted",
                         ok=(outcome == "rejected") == expect_reject, reason=reason, ms=ms))

    for r in range(runs):
        purpose, scope = "treatment", "cardiology"
        # honest request
        ch = s.gw_challenge(doc, p, purpose, scope)
        proof = s.doc_prove(doc, p, ch)
        attempt("honest request", lambda: s.gw_authorize(doc, p, ch, proof), False)
        # replay of a used (challenge, proof)
        attempt("replayed proof and challenge", lambda: s.gw_authorize(doc, p, ch, proof), True)
        # the same proof under a fresh challenge
        ch2 = s.gw_challenge(doc, p, purpose, scope)
        attempt("proof reused under a new challenge", lambda: s.gw_authorize(doc, p, ch2, proof), True)
        # stale challenge (issued Delta_auth + 5 s ago)
        ch3 = s.gw_challenge(doc, p, purpose, scope, t_g=now() - AUTH_LIFETIME_S - 5)
        pr3 = s.doc_prove(doc, p, ch3)
        attempt("stale challenge", lambda: s.gw_authorize(doc, p, ch3, pr3), True)
        # proof made on another channel (different channel binding cb_D)
        ch4 = s.gw_challenge(doc, p, purpose, scope)
        pr4 = s.doc_prove(doc, p, ch4)
        other = dict(ch4.pub, cb=fe(os.urandom(32)))
        attempt("other channel binding", lambda: s.gw_authorize(doc, p, replace(ch4, pub=other), pr4), True)
        # stolen credential without the holder key
        thief_sk, _ = zk.keygen()
        ch5 = s.gw_challenge(doc, p, purpose, scope)
        attempt("stolen credential, no holder key",
                lambda: s.gw_authorize(doc, p, ch5, s.doc_prove(replace(doc, zk_sk=thief_sk), p, ch5)), True)
        # expired credential
        ch6 = s.gw_challenge(doc, p, purpose, scope)
        attempt("expired credential",
                lambda: s.gw_authorize(doc, p, ch6, s.doc_prove(replace(doc, t_vc=now() - 10), p, ch6)), True)
        # concurrent double submission: exactly one may succeed
        ch7 = s.gw_challenge(doc, p, purpose, scope)
        pr7 = s.doc_prove(doc, p, ch7)
        res = []

        def go():
            try:
                s.gw_authorize(doc, p, ch7, pr7)
                res.append("accepted")
            except Rejected:
                res.append("rejected")

        th = [threading.Thread(target=go) for _ in range(2)]
        for x in th:
            x.start()
        for x in th:
            x.join()
        rows.append(dict(check="concurrent double submission", run=r, outcome="/".join(sorted(res)),
                         expected="accepted/rejected", ok=sorted(res) == ["accepted", "rejected"], reason="", ms=0))
    # revoked credential last (it disables the doctor)
    r = runs
    s.revoke_credential(doc)
    attempt("revoked credential", lambda: s.authorize(doc, p, "treatment", "cardiology"), True)
    s.pending_anchors.clear()
    write_rows("e1c_checks.csv", rows)
    for name in dict.fromkeys(x["check"] for x in rows):
        xs = [x for x in rows if x["check"] == name]
        print(f"  (c) {name:<36} {'ok' if all(x['ok'] for x in xs) else 'FAILED'}  ({xs[0]['outcome']})")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parts", default="abc")
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--m", type=int, nargs="+", default=[5, 10, 15, 20, 25, 30])
    ap.add_argument("--m-default", type=int, default=10)
    ap.add_argument("--k", type=int, nargs="+", default=[1, 10, 25, 50, 100])
    ap.add_argument("--session-size", type=int, default=10)
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()
    save_machine()
    if "a" in args.parts:
        part_a(args.m, args.runs)
    if "b" in args.parts or "c" in args.parts:
        s, zk, doc, p, _ = world(not args.offline, args.m_default)
        if "b" in args.parts:
            part_b(s, doc, p, args.k, args.runs, args.session_size, s.ledger)
        if "c" in args.parts:
            part_c(s, zk, doc, p, max(1, min(args.runs, 5)))
        zk.close()
        s.graph.close()


if __name__ == "__main__":
    main()
