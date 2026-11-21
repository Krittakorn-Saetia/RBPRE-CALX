"""rbpre.chain: client for the RBPRE-CALX chaincode (chaincode/rbpre).

FabricLedger talks to the running Hyperledger Fabric test-network through the
`peer` CLI. A write is timed from submit to commit (--waitForEvent), so its
latency includes endorsement, ordering (BatchTimeout 1 s) and validation; a
read is a `peer chaincode query`. Every call returns (result, elapsed_ms).

Batch operations are split into transactions that stay below the peer CLI's
single-argument limit; they return (result, elapsed_ms, n_transactions).

MemoryLedger mirrors the contract in a Python dict. It exists only so that the
protocol logic can be tested without Docker; it has no latency, and experiment
drivers must refuse it (require_real).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time

# Linux caps one command-line argument at 128 KiB (MAX_ARG_STRLEN).
MAX_ARG_BYTES = 120_000
STATUS = ("active", "revoked", "superseded")


def _j(o) -> str:
    return json.dumps(o, separators=(",", ":"))


def _chunks(items: list, max_bytes: int = MAX_ARG_BYTES):
    """Split items so that the JSON of each chunk stays below max_bytes."""
    chunk, size = [], 2
    for it in items:
        n = len(_j(it)) + 1
        if chunk and size + n > max_bytes:
            yield chunk
            chunk, size = [], 2
        chunk.append(it)
        size += n
    if chunk:
        yield chunk


class _LedgerAPI:
    is_real = False

    def invoke(self, fn: str, *args) -> tuple[str, float]:
        raise NotImplementedError

    def query(self, fn: str, *args) -> tuple[str, float]:
        raise NotImplementedError

    def _batch_invoke(self, fn: str, items: list):
        total, n_tx, count = 0.0, 0, 0
        for chunk in _chunks(items):
            out, ms = self.invoke(fn, _j(chunk))
            total += ms
            n_tx += 1
            count += len(chunk)
        return count, total, n_tx

    # ---- identity, credentials (Phase 1 Step 2, Eq. 19)
    def register_dids(self, recs: list[dict]):
        """recs: [{did, pk, domain}]"""
        return self._batch_invoke("RegisterDIDs", recs)

    def register_credentials(self, recs: list[dict]):
        """recs: [{id: cid, owner: DID_D, t: t_VC}]"""
        return self._batch_invoke("RegisterCredentials", recs)

    # ---- consent (CMC, Eq. 29) and delegation (Eq. 34)
    def register_consent(self, com_c: str, e: int, t_c: int, prev: str = ""):
        return self.invoke("RegisterConsent", com_c, e, t_c, prev)

    def register_delegation(self, h_del: str, e: int, t_del: int):
        return self.invoke("RegisterDelegation", h_del, e, t_del)

    def set_status(self, kind: str, ident: str, status: str):
        return self.invoke("SetStatus", kind, ident, status)

    # ---- revocation (Eq. 96-97)
    def advance_epoch(self, handle: str, com_rev: str) -> tuple[int, float]:
        out, ms = self.invoke("AdvanceEpoch", handle, com_rev)
        return _payload_int(out), ms

    # ---- records, linkage, anchors (Eq. 48, 65, 76-78, 90)
    def anchor_records(self, recs: list[dict]):
        """recs: [{id: RID*, v: ComR}]"""
        return self._batch_invoke("AnchorRecords", recs)

    def anchor_flags(self, recs: list[dict]):
        """recs: [{id: FlagID, e}]"""
        return self._batch_invoke("AnchorFlags", recs)

    def set_root(self, pid: str, root: str):
        return self.invoke("SetRoot", pid, root)

    def anchor_auth(self, com: str):
        return self.invoke("AnchorAuth", com)

    def anchor_shares(self, coms: list[str]):
        return self._batch_invoke("AnchorShares", coms)

    # ---- reads
    def get_state(self, req: dict[str, list[str]]):
        """Resolve many entries; returns ({kind: {id: value}}, ms, n_queries)."""
        flat = [(k, i) for k, ids in req.items() for i in ids]
        out: dict[str, dict] = {k: {} for k in req}
        total, n_q = 0.0, 0
        for chunk in _chunks(flat):
            sub: dict[str, list[str]] = {}
            for k, i in chunk:
                sub.setdefault(k, []).append(i)
            raw, ms = self.query("GetState", _j(sub))
            total += ms
            n_q += 1
            for k, m in json.loads(raw).items():
                out.setdefault(k, {}).update(m)
        return out, total, n_q


def _payload_int(out: str) -> int:
    m = re.search(r'payload:"?(-?\d+)"?', out)
    if not m:
        raise RuntimeError(f"no integer payload in: {out[-300:]}")
    return int(m.group(1))


class FabricLedger(_LedgerAPI):
    """Real Hyperledger Fabric back end (peer CLI, submit -> commit)."""

    is_real = True

    def __init__(self, infra: str | None = None, channel: str | None = None, cc: str | None = None):
        infra = infra or os.environ.get("FLEX_INFRA", os.path.expanduser("~/flex-diam"))
        tn = f"{infra}/fabric-samples/test-network"
        self.channel = channel or os.environ.get("RBPRE_CHANNEL", "rbpre")
        self.cc = cc or os.environ.get("RBPRE_CC", "rbpre")
        org = f"{tn}/organizations/peerOrganizations"
        orderer_ca = (f"{tn}/organizations/ordererOrganizations/example.com/orderers/"
                      "orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem")
        org1_ca = f"{org}/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
        org2_ca = f"{org}/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{tn}/../bin:" + os.environ.get("PATH", ""),
            "FABRIC_CFG_PATH": f"{tn}/../config/",
            "CORE_PEER_TLS_ENABLED": "true",
            "CORE_PEER_LOCALMSPID": "Org1MSP",
            "CORE_PEER_TLS_ROOTCERT_FILE": org1_ca,
            "CORE_PEER_MSPCONFIGPATH": f"{org}/org1.example.com/users/Admin@org1.example.com/msp",
            "CORE_PEER_ADDRESS": "localhost:7051",
        })
        self._invoke = [
            "peer", "chaincode", "invoke",
            "-o", "localhost:7050", "--ordererTLSHostnameOverride", "orderer.example.com",
            "--channelID", self.channel, "--name", self.cc, "--tls", "--cafile", orderer_ca,
            "--peerAddresses", "localhost:7051", "--tlsRootCertFiles", org1_ca,
            "--peerAddresses", "localhost:9051", "--tlsRootCertFiles", org2_ca,
            "--waitForEvent",
        ]
        self._query = ["peer", "chaincode", "query", "--channelID", self.channel, "--name", self.cc]

    @staticmethod
    def _ctor(fn: str, args) -> str:
        return _j({"function": fn, "Args": [str(a) for a in args]})

    def invoke(self, fn: str, *args):
        c_arg = self._ctor(fn, args)
        if len(c_arg.encode()) > MAX_ARG_BYTES + 1000:
            raise ValueError(f"{fn}: argument of {len(c_arg)} bytes exceeds the peer CLI limit")
        t0 = time.perf_counter_ns()
        r = subprocess.run(self._invoke + ["-c", c_arg], capture_output=True, text=True,
                           timeout=120, env=self.env)
        ms = (time.perf_counter_ns() - t0) / 1e6
        out = r.stdout + r.stderr
        if "status:200" not in out:
            raise RuntimeError(f"{fn} failed: {out[-600:]}")
        return out, ms

    def query(self, fn: str, *args):
        c_arg = self._ctor(fn, args)
        t0 = time.perf_counter_ns()
        r = subprocess.run(self._query + ["-c", c_arg], capture_output=True, text=True,
                           timeout=60, env=self.env)
        ms = (time.perf_counter_ns() - t0) / 1e6
        if r.returncode != 0:
            raise RuntimeError(f"{fn} query failed: {r.stderr[-600:]}")
        return r.stdout.strip(), ms


class MemoryLedger(_LedgerAPI):
    """In-process mirror of rbpre_contract.go for offline logic tests only."""

    is_real = False

    def __init__(self):
        self.kv: dict[str, object] = {}

    def invoke(self, fn: str, *args):
        kv = self.kv
        if fn == "RegisterDIDs":
            for r in json.loads(args[0]):
                kv["did|" + r["did"]] = r
            return "status:200", 0.0
        if fn == "RegisterCredentials":
            for r in json.loads(args[0]):
                kv["cred|" + r["id"]] = {"owner": r["owner"], "e": 0, "t": int(r["t"]), "status": "active"}
            return "status:200", 0.0
        if fn == "RegisterConsent":
            com_c, e, t_c, prev = args
            if prev:
                self.invoke("SetStatus", "cons", prev, "superseded")
            kv["cons|" + com_c] = {"e": int(e), "t": int(t_c), "status": "active"}
            return "status:200", 0.0
        if fn == "RegisterDelegation":
            h, e, t = args
            kv["del|" + h] = {"e": int(e), "t": int(t), "status": "active"}
            return "status:200", 0.0
        if fn == "SetStatus":
            kind, ident, status = args
            if status not in STATUS or ("%s|%s" % (kind, ident)) not in kv:
                raise RuntimeError(f"SetStatus failed: {kind} {ident} {status}")
            kv[f"{kind}|{ident}"] = dict(kv[f"{kind}|{ident}"], status=status)
            return "status:200", 0.0
        if fn == "AdvanceEpoch":
            handle, com_rev = args
            ep = kv.get("epoch|" + handle, {"e": 0, "com_rev": ""})
            ep = {"e": ep["e"] + 1, "com_rev": com_rev}
            kv["epoch|" + handle] = ep
            return f'status:200 payload:"{ep["e"]}"', 0.0
        if fn == "AnchorRecords":
            for r in json.loads(args[0]):
                kv["rec|" + r["id"]] = r["v"]
            return "status:200", 0.0
        if fn == "AnchorFlags":
            for r in json.loads(args[0]):
                kv["flag|" + r["id"]] = {"e": int(r["e"]), "t": 0, "status": "active"}
            return "status:200", 0.0
        if fn == "SetRoot":
            kv["root|" + args[0]] = args[1]
            return "status:200", 0.0
        if fn == "AnchorAuth":
            kv["auth|" + args[0]] = str(int(time.time()))
            return "status:200", 0.0
        if fn == "AnchorShares":
            for c in json.loads(args[0]):
                kv["share|" + c] = str(int(time.time()))
            return "status:200", 0.0
        raise RuntimeError(f"MemoryLedger: unknown invoke {fn}")

    def query(self, fn: str, *args):
        if fn != "GetState":
            raise RuntimeError(f"MemoryLedger: unknown query {fn}")
        out = {}
        for kind, ids in json.loads(args[0]).items():
            out[kind] = {i: self.kv[f"{kind}|{i}"] for i in ids if f"{kind}|{i}" in self.kv}
        return _j(out), 0.0


def require_real(ledger) -> None:
    """Experiment drivers call this: measurements must come from real Fabric."""
    if not getattr(ledger, "is_real", False):
        raise SystemExit("refusing to measure against MemoryLedger: a live Fabric network is required")
