"""rbpre.cache: Redis for challenge nonces, holder-bound sessions and the
context-bound re-encryption cache.

    Fresh(n_G, t_G, t_now) and Unused(n_G), then atomic consumption of n_G   (Eq. 61-62)
    Sess_auth = (AuthTok, sid, t_sess) with TTL                               (Eq. 66)
    Cache_RK  = (RK_AB, t_sess, TTL) under kappa_RK                           (Eq. 94-95)

Sessions and re-key entries carry tags (the patient's epoch handle and the
requester's DID). A revocation invalidates every entry under a tag at once,
independently of its TTL (Phase 5 Step 5).
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

    def peek_nonce(self, n_g: bytes) -> int | None:
        v = self.r.get(b"nonce:" + n_g)
        return int(v) if v is not None else None

    def consume_nonce(self, n_g: bytes) -> int | None:
        """Atomically consume n_G; returns its issuance time t_G, or None if
        it was never issued, already used, or expired."""
        v = self.r.getdel(b"nonce:" + n_g)
        return int(v) if v is not None else None

    # ------------------------------------------------- tagged entries

    @staticmethod
    def _tag(tag: str) -> bytes:
        return b"tag:" + tag.encode()

    def _put(self, kind: bytes, key: bytes, value: bytes, ttl_s: int, tags) -> None:
        k = kind + key
        pipe = self.r.pipeline()
        pipe.set(k, value, ex=max(1, int(ttl_s)))
        for t in tags:
            pipe.sadd(self._tag(t), k)
        pipe.execute()

    def put_session(self, sid: bytes, blob: bytes, ttl_s: int, tags) -> None:
        self._put(b"sess:", sid, blob, ttl_s, tags)

    def get_session(self, sid: bytes) -> bytes | None:
        return self.r.get(b"sess:" + sid)

    def put_rekey(self, kappa: bytes, blob: bytes, ttl_s: int, tags) -> None:
        self._put(b"rk:", kappa, blob, ttl_s, tags)

    def get_rekey(self, kappa: bytes) -> bytes | None:
        return self.r.get(b"rk:" + kappa)

    def invalidate(self, tag: str) -> int:
        """Delete every entry under `tag`; returns the number of live entries removed."""
        t = self._tag(tag)
        keys = list(self.r.smembers(t))
        if not keys:
            self.r.delete(t)
            return 0
        pipe = self.r.pipeline()
        pipe.delete(*keys)
        pipe.delete(t)
        removed, _ = pipe.execute()
        return int(removed)
