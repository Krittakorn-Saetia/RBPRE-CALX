#!/usr/bin/env python3
"""Primitive and building-block costs (the numbers behind Table IV).

    python -m experiments.micro [--n 200] [--n-svc 30] [--no-services]

Writes results/<run>/micro.csv: op, param, n, mean_ms, sd_ms, median_ms,
min_ms, and bytes where a size is meaningful.
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import statistics
import time
import warnings

from experiments.harness import save_machine, write_rows


def bench(rows, op, fn, n, param="", nbytes=None):
    fn()  # warm-up
    xs = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        xs.append((time.perf_counter_ns() - t0) / 1e6)
    row = dict(op=op, param=param, n=n, mean_ms=statistics.fmean(xs),
               sd_ms=statistics.stdev(xs) if n > 1 else 0.0, median_ms=statistics.median(xs), min_ms=min(xs))
    if nbytes is not None:
        row["bytes"] = nbytes
    rows.append(row)
    print(f"  {op:<28} {param:<10} {row['mean_ms']:10.4f} ms  (sd {row['sd_ms']:.4f})")


def up(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--n-svc", type=int, default=30)
    ap.add_argument("--no-services", action="store_true")
    args = ap.parse_args()
    n, rows = args.n, []
    save_machine()

    # ---------------------------------------------------- pairing group, P-256
    from charm.toolbox.pairinggroup import G1, GT, ZR, PairingGroup, pair

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        grp = PairingGroup("SS512")
    a, b, r = grp.random(G1), grp.random(G1), grp.random(ZR)
    gt = pair(a, b)
    print("pairing group SS512")
    bench(rows, "T_P pairing", lambda: pair(a, b), n, "SS512")
    bench(rows, "T_E G1 exp", lambda: a ** r, n, "SS512")
    bench(rows, "T_E GT exp", lambda: gt ** r, n, "SS512")
    bench(rows, "T_M G1 mult", lambda: a * b, n, "SS512")
    bench(rows, "hash to G1", lambda: grp.hash(os.urandom(32), G1), n, "SS512")

    from baselines.common import Prims

    pr = Prims()
    k, Q = pr.ec_scalar(), pr.T_sm(pr.P, pr.ec_scalar())
    print("P-256, symmetric, signatures")
    bench(rows, "T_sm scalar mult", lambda: pr.T_sm(pr.P, k), n, "P-256")
    bench(rows, "T_add point add", lambda: pr.T_add(pr.P, Q), n, "P-256")
    bench(rows, "T_H SHA-256", lambda: pr.T_H(os.urandom(64)), n, "64 B")
    bench(rows, "T_p PUF (HMAC)", lambda: pr.T_p(os.urandom(16)), n, "16 B")
    from rbpre import aead, sig

    key = aead.new_key()
    for size, label in ((1024, "1 KB"), (65536, "64 KB"), (1 << 20, "1 MB")):
        data = os.urandom(size)
        blob = aead.encrypt(key, data, b"ad")
        bench(rows, "T_sym AES-GCM enc", lambda: aead.encrypt(key, data, b"ad"), n, label)
        bench(rows, "T_sym AES-GCM dec", lambda: aead.decrypt(key, blob, b"ad"), n, label)
    sk = sig.keygen()
    s = sk.sign(b"m" * 32)
    bench(rows, "Ed25519 sign", lambda: sk.sign(b"m" * 32), n)
    bench(rows, "Ed25519 verify", lambda: sig.verify(sk.pk, s, b"m" * 32), n)
    ipk, isk = pr.ibs_keygen("alice")
    isig = pr.T_IBS_sign(isk, "msg")
    bench(rows, "T_IBS sign (Hess)", lambda: pr.T_IBS_sign(isk, "msg"), n, "SS512")
    bench(rows, "T_IBS verify (Hess)", lambda: pr.T_IBS_ver(ipk, "msg", isig), n, "SS512")

    # ------------------------------------------------------------ CP-ABPRE [41]
    from rbpre import rbabpre as rb
    from rbpre.abpre import CPABPRE

    sch = CPABPRE("SS512")
    print("CP-ABPRE (Ibraimi et al.), AND policy of m attributes -> (id AND role)")
    for m in (2, 5, 10, 20, 30):
        attrs = [f"a{i}" for i in range(m)]
        pk, mk = sch.setup(attrs + ["id:B", "role:r"])
        p1, p2 = " AND ".join(attrs), "id:B AND role:r"
        sk1 = sch.keygen(pk, mk, attrs)
        sk2 = sch.keygen(pk, mk, ["id:B", "role:r"])
        _, ct = sch.encapsulate(pk, p1)
        rk = sch.rekeygen(pk, sk1, p1, p2)
        ct2 = sch.reencrypt(pk, rk, ct)
        bench(rows, "ABPRE.KeyGen", lambda: sch.keygen(pk, mk, attrs), n, f"m={m}")
        bench(rows, "ABPRE.Enc (KEM)", lambda: sch.encapsulate(pk, p1), n, f"m={m}", len(sch.dumps(ct)))
        bench(rows, "ABPRE.ReKeyGen", lambda: sch.rekeygen(pk, sk1, p1, p2), n, f"m={m}", len(sch.dumps(rk)))
        bench(rows, "ABPRE.ReEnc", lambda: sch.reencrypt(pk, rk, ct), n, f"m={m}", len(sch.dumps(ct2)))
        bench(rows, "ABPRE.Dec original", lambda: sch.decapsulate(pk, sk1, ct), n, f"m={m}")
        bench(rows, "ABPRE.Dec re-encrypted", lambda: sch.decapsulate(pk, sk2, ct2), n, f"m={m}")

    print("RB-ABPRE layer (protocol policies: P_A = hosp AND class, P_B = id AND role)")
    kms = rb.KMS(sch, ["hosp:HA", "class:lab"])
    kms.keygen_source("did:rb:HA", sig.keygen().pk, ["hosp:HA", "class:lab"])
    rk_pk = sig.keygen().pk
    kms.keygen("did:rb:B", rk_pk, ["role:physician", rb.id_attr("did:rb:B")])
    chi = rb.Descriptor(os.urandom(32), os.urandom(32), 1, os.urandom(16), "cardiology", "treatment")
    pa, pb = "hosp:HA AND class:lab", f"{rb.id_attr('did:rb:B')} AND role:physician"
    _, ctk = rb.enc(sch, kms.pp, pa)
    st = kms.rekeygen("did:rb:HA", pa, pb, rk_pk, chi)
    bench(rows, "RB.ReKeyGen (+sigma_KMS)", lambda: kms.rekeygen("did:rb:HA", pa, pb, rk_pk, chi), n)
    bench(rows, "RB.ReEnc (+checks)", lambda: rb.reencrypt(sch, kms.pp, kms.pk_kms, ctk, st, chi), n)
    bench(rows, "ct_k serialize", lambda: sch.dumps(ctk), n, nbytes=len(sch.dumps(ctk)))
    blob = sch.dumps(ctk)
    bench(rows, "ct_k deserialize", lambda: sch.loads(blob), n)

    # ------------------------------------------------------------------ Merkle
    from rbpre import merkle
    from rbpre.encoding import H

    print("Merkle tree (SHA-256)")
    for size in (1000, 10000, 50000):
        leaves = [H("flag", i) for i in range(size)]
        reps = max(3, min(n, 20))
        bench(rows, "Merkle build", lambda: merkle.MerkleTree(leaves), reps, f"{size}")
        tree = merkle.MerkleTree(leaves)
        rnd = random.Random(size)
        bench(rows, "Merkle proof", lambda: tree.proof(rnd.randrange(size)), n, f"{size}")
        i = rnd.randrange(size)
        proof = tree.proof(i)
        bench(rows, "Merkle verify", lambda: merkle.verify(leaves[i], proof, tree.root), n, f"{size}")

    # --------------------------------------------------------------- ZK helper
    from rbpre.zk import ZK, fe

    print("rbzk (gnark, BLS12-381): times measured inside Go")
    with ZK() as zk:
        jsk, jpk = zk.keygen()
        msg = fe(os.urandom(32))
        jsig = zk.sign(jsk, msg)

        def go_bench(op, call, key, reps, param=""):
            xs = [call()[key] for _ in range(reps)]
            rows.append(dict(op=op, param=param, n=reps, mean_ms=statistics.fmean(xs),
                             sd_ms=statistics.stdev(xs) if reps > 1 else 0.0,
                             median_ms=statistics.median(xs), min_ms=min(xs)))
            print(f"  {op:<28} {param:<10} {rows[-1]['mean_ms']:10.4f} ms")

        go_bench("MiMC (2 inputs)", lambda: zk.call(op="mimc", inputs=[msg, msg]), "hash_ms", n)
        go_bench("Jubjub EdDSA sign", lambda: zk.call(op="sign", sk=jsk, msg=msg), "sign_ms", n)
        go_bench("Jubjub EdDSA verify", lambda: zk.call(op="verify_sig", pk=jpk, msg=msg, sig=jsig),
                 "verify_ms", n)
        go_bench("rbzk IPC round trip", lambda: zk.call(op="ping"), "rtt_ms", n)

    # ---------------------------------------------------------------- services
    if not args.no_services:
        ns = args.n_svc
        print("services")
        if up(6379):
            from rbpre.cache import AuthCache

            c = AuthCache()
            bench(rows, "Redis SET", lambda: c.r.set(b"bench", b"x" * 256, ex=60), ns)
            bench(rows, "Redis GET", lambda: c.r.get(b"bench"), ns)
        if up(9000):
            from rbpre.storage import EHRStore

            st_ = EHRStore(bucket="ehr-bench")
            st_.setup()
            uri = st_.put(os.urandom(1024), os.urandom(600))
            bench(rows, "MinIO PUT", lambda: st_.put(os.urandom(1024), os.urandom(600)), ns, "1.6 KB")
            bench(rows, "MinIO GET", lambda: st_.get(uri), ns, "1.6 KB")
            st_.clear()
        if up(7687):
            from rbpre.graph import RetrievalGraph

            g = RetrievalGraph()
            bench(rows, "Neo4j round trip", lambda: g._run("RETURN 1"), ns)
            g.close()
        if up(7051):
            from rbpre.chain import FabricLedger

            L = FabricLedger()
            bench(rows, "T_B^qry Fabric query", lambda: L.get_state({"did": ["none"]}), ns)
            bench(rows, "T_B^upd+T_con Fabric tx", lambda: L.anchor_shares([os.urandom(16).hex()]),
                  max(5, ns // 3))

    path = write_rows("micro.csv", rows)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
