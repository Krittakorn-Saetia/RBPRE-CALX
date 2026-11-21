"""rbpre.cache: Redis for challenge nonces, holder-bound sessions and the
context-bound re-encryption cache.

    Fresh(n_G, t_G, t_now) and Unused(n_G), then atomic consumption of n_G   (Eq. 61-62)
    Sess_auth = (AuthTok, sid, t_sess) with TTL                               (Eq. 66)
    Cache_RK  = (RK_AB, t_sess, TTL) under kappa_RK                           (Eq. 94-95)

Every session and re-key entry is tagged with the patient pseudonym and the
epoch it was created under, so that an epoch advance can invalidate all of
them independently of their TTL (Phase 5 Step 5).
"""

from __future__ import annotations

import redis

from rbpre import config


class AuthCache:
    def __init__(self, host: str = config.REDIS_HOST, port: int = config.REDIS_PORT,
                 password: str = config.REDIS_PASSWORD):
        self.r = redis.Redis(host=host, port=port, password=password, decode_responses=False)

    def clear(self) -> None:
        self.r.flushdb()

    # ------------------------------------------------- challenge nonces (Eq. 61)

    def issue_nonce(self, n_g: bytes, t_g: int, lifetime_s: int) -> None:
        self.r.set(b"nonce:" + n_g, str(t_g).encode(), ex=lifetime_s)

    def consume_nonce(self, n_g: bytes) -> int | None:
        """Atomically consume n_G; returns its issuance time t_G, or None if
        it was never issued, already used, or expired."""
        v = self.r.getdel(b"nonce:" + n_g)
        return int(v) if v is not None else None

    # ------------------------------------------------- tagged entries

    def _tag(self, pid: str) -> bytes:
        return b"pidx:" + pid.encode()

    def _put(self, kind: bytes, key: bytes, value: bytes, ttl_s: int, pid: str) -> None:
        k = kind + key
        pipe = self.r.pipeline()
        pipe.set(k, value, ex=ttl_s)
        pipe.sadd(self._tag(pid), k)
        pipe.execute()

    def put_session(self, sid: bytes, blob: bytes, ttl_s: int, pid: str) -> None:
        self._put(b"sess:", sid, blob, ttl_s, pid)

    def get_session(self, sid: bytes) -> bytes | None:
        return self.r.get(b"sess:" + sid)

    def put_rekey(self, kappa: bytes, blob: bytes, ttl_s: int, pid: str) -> None:
        self._put(b"rk:", kappa, blob, ttl_s, pid)

    def get_rekey(self, kappa: bytes) -> bytes | None:
        return self.r.get(b"rk:" + kappa)

    def invalidate_patient(self, pid: str) -> int:
        """Delete every session and re-key entry created for patient pseudonym
        `pid` (epoch advance). Returns the number of entries removed."""
        tag = self._tag(pid)
        keys = list(self.r.smembers(tag))
        if not keys:
            return 0
        pipe = self.r.pipeline()
        pipe.delete(*keys)
        pipe.delete(tag)
        removed, _ = pipe.execute()
        return int(removed)
