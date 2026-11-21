"""rbpre.zk: client for the Go helper zk/rbzk (gnark Groth16 on BLS12-381,
Jubjub EdDSA, MiMC).

One rbzk process is started per ZK instance and kept alive; requests and
responses are single JSON lines. Every response carries the in-process timing
measured by Go (prove_ms, verify_ms, ...) and `rtt_ms`, the Python-side round
trip, so the IPC overhead is visible.

Field elements are 64-character hex strings below the BLS12-381 scalar field
modulus. `fe()` maps identifiers, attributes and digests into the field: a
32-byte digest keeps its first 31 bytes; other values are first hashed with
SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from rbpre.encoding import encode

BINARY = Path(os.environ.get("RBPRE_RBZK", Path(__file__).resolve().parent.parent / "zk" / "rbzk"))
FIELD_BYTES = 31  # 248 bits < BLS12-381 scalar field modulus (~2^255)


class ZKError(Exception):
    pass


def fe(x) -> str:
    """Field element (hex) of an int, a 32-byte digest, or any other value."""
    if isinstance(x, bool):
        raise TypeError("bool is not a field element")
    if isinstance(x, int):
        if not 0 <= x < 1 << (8 * FIELD_BYTES):
            raise ValueError("integer out of range for a field element")
        return format(x, "064x")
    if isinstance(x, (bytes, bytearray)) and len(x) == 32:
        d = bytes(x)
    else:
        d = hashlib.sha256(encode(x)).digest()
    return format(int.from_bytes(d[:FIELD_BYTES], "big"), "064x")


class ZK:
    def __init__(self, binary: Path | str = BINARY):
        if not Path(binary).exists():
            raise ZKError(f"{binary} not found; build it with: cd zk && go build -o rbzk .")
        self._p = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   text=True, bufsize=1)

    def call(self, **req) -> dict:
        t0 = time.perf_counter()
        self._p.stdin.write(json.dumps(req, separators=(",", ":")) + "\n")
        self._p.stdin.flush()
        line = self._p.stdout.readline()
        rtt = (time.perf_counter() - t0) * 1e3
        if not line:
            raise ZKError("rbzk exited")
        resp = json.loads(line)
        if not resp.pop("ok"):
            raise ZKError(resp.get("error", "rbzk error"))
        resp["rtt_ms"] = rtt
        return resp

    def close(self) -> None:
        if self._p.poll() is None:
            self._p.stdin.close()
            self._p.wait(timeout=10)
        self._p.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------------------------------------------------------------- ops

    def setup(self, circuit: str, m: int) -> dict:
        return self.call(op="setup", circuit=circuit, m=m)

    def prove(self, circuit: str, m: int, pub: dict, wit: dict) -> dict:
        return self.call(op="prove", circuit=circuit, m=m, pub=pub, wit=wit)

    def verify(self, circuit: str, m: int, pub: dict, proof: str) -> dict:
        return self.call(op="verify", circuit=circuit, m=m, pub=pub, proof=proof)

    def keygen(self) -> tuple[str, str]:
        r = self.call(op="keygen")
        return r["sk"], r["pk"]

    def sign(self, sk: str, msg: str) -> str:
        return self.call(op="sign", sk=sk, msg=msg)["sig"]

    def verify_sig(self, pk: str, msg: str, sig: str) -> bool:
        return self.call(op="verify_sig", pk=pk, msg=msg, sig=sig)["valid"]

    def mimc(self, *inputs: str) -> str:
        return self.call(op="mimc", inputs=list(inputs))["digest"]
