"""Shared helpers for the experiment drivers: result files, statistics,
machine description and service construction.

Every driver writes raw per-run CSV rows to results/<run>/ (RBPRE_RUN, default
"dev"); plots are generated from those files only.

Top-up runs: with RBPRE_TOPUP=<label>, a driver adds its rows to the rows
already in each result file instead of replacing them. Every row carries a
`batch` column (0 for the original runs, <label> for the added ones), so the
plots and summaries average over all batches. Before a file is first
extended, a copy is kept as results/<run>/batches/<file>.before-<label>.csv.
"""

from __future__ import annotations

import contextlib
import csv
import gc
import json
import os
import platform
import shutil
import statistics
import subprocess
import time
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUN = os.environ.get("RBPRE_RUN", "dev")
OUT = ROOT / "results" / RUN
TOPUP = os.environ.get("RBPRE_TOPUP", "")
_base: dict[str, list[dict]] = {}


def out_path(name: str) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    return OUT / name


def selected(only: list[str] | None, *fields) -> bool:
    """True if `fields` match one of the colon-separated tokens in `only`
    (None or empty = everything). A token field "*" or a missing trailing field
    matches anything; other fields must be equal as strings. Example:
    selected(["e2:[25]:all:10000"], "e2", "[25]", "all", 10000)."""
    if not only:
        return True
    for tok in only:
        parts = tok.split(":")
        if all(i >= len(parts) or parts[i] == "*" or parts[i] == str(f) for i, f in enumerate(fields)):
            return True
    return False


def write_rows(name: str, rows: list[dict]) -> Path:
    path = out_path(name)
    if not rows:
        return path
    if TOPUP:
        if name not in _base:
            old: list[dict] = []
            if path.exists():
                with path.open(newline="") as f:
                    old = list(csv.DictReader(f))
                keep = OUT / "batches" / f"{path.stem}.before-{TOPUP}{path.suffix}"
                keep.parent.mkdir(exist_ok=True)
                if not keep.exists():
                    shutil.copyfile(path, keep)
            for r in old:
                if not r.get("batch"):
                    r["batch"] = "0"
            _base[name] = old
        rows = _base[name] + [dict(r, batch=TOPUP) for r in rows]
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def mean_sd(xs: list[float]) -> tuple[float, float]:
    if not xs:
        return float("nan"), float("nan")
    return statistics.fmean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0)


@contextlib.contextmanager
def quiet():
    """Measurement section without Python garbage-collector pauses: collect
    first, keep the cyclic collector off while timing, re-enable after."""
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        gc.enable()


def timed(fn, *a, **k) -> tuple[object, float]:
    t0 = time.perf_counter_ns()
    r = fn(*a, **k)
    return r, (time.perf_counter_ns() - t0) / 1e6


def _ver(pkg: str) -> str:
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return "?"


def machine() -> dict:
    """Hardware and software description, written next to the results."""
    info = {"chain_client": CHAIN, "python": platform.python_version(), "platform": platform.platform(),
            "charm": _ver("charm-crypto-framework"), "cryptography": _ver("cryptography"),
            "neo4j_driver": _ver("neo4j"), "redis_py": _ver("redis"), "minio_py": _ver("minio")}
    try:
        lscpu = subprocess.run(["lscpu"], capture_output=True, text=True).stdout
        for line in lscpu.splitlines():
            k, _, v = line.partition(":")
            if k.strip() in ("Model name", "CPU(s)", "Thread(s) per core"):
                info[k.strip()] = v.strip()
        mem = subprocess.run(["free", "-b"], capture_output=True, text=True).stdout.split("\n")[1].split()
        info["mem_total_gb"] = round(int(mem[1]) / 2**30, 1)
    except (OSError, IndexError, ValueError):
        pass
    return info


def save_machine() -> None:
    out_path(f"machine.{TOPUP}.json" if TOPUP else "machine.json").write_text(json.dumps(machine(), indent=2))


CHAIN = os.environ.get("RBPRE_CHAIN", "gateway")  # gateway | cli


def services(fabric: bool = True, bucket: str = "ehr"):
    """(ledger, graph, store, cache) on the real services. The chain client is
    the Fabric Gateway with its synchronized mirror (RBPRE_CHAIN=gateway, the
    default) or the peer CLI (RBPRE_CHAIN=cli); every scheme uses the same one."""
    from rbpre.cache import AuthCache
    from rbpre.chain import FabricLedger, GatewayLedger, MemoryLedger
    from rbpre.graph import RetrievalGraph
    from rbpre.storage import EHRStore

    graph = RetrievalGraph()
    graph.setup()
    store = EHRStore(bucket=bucket)
    store.setup()
    if not fabric:
        ledger = MemoryLedger()
    else:
        ledger = GatewayLedger() if CHAIN == "gateway" else FabricLedger()
    return ledger, graph, store, AuthCache()
