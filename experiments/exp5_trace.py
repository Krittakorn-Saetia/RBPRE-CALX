#!/usr/bin/env python3
"""Experiment 5: blockchain traceability overhead vs the number of audit events.

For E cross-domain sharing events, every scheme commits its audit evidence
to the same Fabric channel and the time until all of it is committed is
measured:

  RBPRE-CALX  ComShare_i = H(PID* || RID_i || DID_HA || DID_HB || h_chi || e)
              (Eq. 90), submitted in batched transactions off the retrieval
              path: O(k_a T_H) + T_Anchor(k_a)
  [25]        T_H per event, anchored in the same batched form (hash anchoring)
  [27], [31]  T_B^upd + T_con per event: one transaction per event, with
              --concurrency clients submitting in parallel

    python -m experiments.exp5_trace [--events 10 50 100 250 500 1000] [--runs 30]
"""

from __future__ import annotations

import argparse
import os
import time

from baselines.common import Prims
from baselines.schemes import Luo31, Yan27
from experiments.harness import save_machine, services, write_rows
from rbpre.encoding import H


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, nargs="+", default=[10, 50, 100, 250, 500, 1000])
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--concurrency", type=int, default=10)
    args = ap.parse_args()
    save_machine()
    ledger, graph, _, _ = services(True)
    graph.close()
    pr = Prims()
    per_event = [Yan27(pr, ledger), Luo31(pr, ledger)]
    rows = []
    h_chi, pid, ha, hb = (os.urandom(32) for _ in range(4))
    for e_n in args.events:
        for r in range(args.runs):
            # RBPRE-CALX: compact commitments, batched
            t0 = time.perf_counter_ns()
            coms = [H(pid, os.urandom(32), ha, hb, h_chi, 1).hex() for _ in range(e_n)]
            _, _, n_tx = ledger.anchor_shares(coms)
            rows.append(dict(scheme="RBPRE-CALX", events=e_n, run=r, txs=n_tx,
                             ms=(time.perf_counter_ns() - t0) / 1e6))
            # [25]: hash anchoring
            t0 = time.perf_counter_ns()
            hs = [pr.T_H(os.urandom(16)).hex() for _ in range(e_n)]
            _, _, n_tx = ledger.anchor_shares(hs)
            rows.append(dict(scheme="[25]", events=e_n, run=r, txs=n_tx,
                             ms=(time.perf_counter_ns() - t0) / 1e6))
            # [27], [31]: one transaction per event
            for b in per_event:
                t0 = time.perf_counter_ns()
                b.anchor(e_n, args.concurrency)
                rows.append(dict(scheme=b.name, events=e_n, run=r, txs=e_n,
                                 ms=(time.perf_counter_ns() - t0) / 1e6))
        last = [x for x in rows if x["events"] == e_n]
        print(f"E={e_n:<6} " + "  ".join(
            f"{sch}: {sum(x['ms'] for x in last if x['scheme'] == sch) / args.runs:9.0f} ms"
            for sch in dict.fromkeys(x["scheme"] for x in last)))
        write_rows("e5_runs.csv", rows)


if __name__ == "__main__":
    main()
