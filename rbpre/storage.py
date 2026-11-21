"""rbpre.storage: encrypted EHR storage on MinIO (Eq. 44, URI = Store(CT_m, CT_k)).

One object per EHR package; its body is the canonical encoding of
(CT_m, CT_k) so that d = H(CT_m || CT_k) (Eq. 47) is recomputable from what
is fetched. The storage server sees only ciphertexts.
"""

from __future__ import annotations

import io
import os
from concurrent.futures import ThreadPoolExecutor

from minio import Minio

from rbpre import config


def _pack(ct_m: bytes, ct_k: bytes) -> bytes:
    return len(ct_m).to_bytes(4, "big") + ct_m + ct_k


def _unpack(blob: bytes) -> tuple[bytes, bytes]:
    n = int.from_bytes(blob[:4], "big")
    return blob[4:4 + n], blob[4 + n:]


class EHRStore:
    def __init__(self, endpoint: str = config.MINIO_ENDPOINT, user: str = config.MINIO_USER,
                 password: str = config.MINIO_PASSWORD, bucket: str = config.MINIO_BUCKET):
        self._c = Minio(endpoint, access_key=user, secret_key=password, secure=False)
        self.bucket = bucket

    def setup(self) -> None:
        if not self._c.bucket_exists(self.bucket):
            self._c.make_bucket(self.bucket)

    def clear(self) -> None:
        from minio.deleteobjects import DeleteObject

        objs = (DeleteObject(o.object_name) for o in self._c.list_objects(self.bucket, recursive=True))
        for err in self._c.remove_objects(self.bucket, objs):
            raise RuntimeError(f"delete failed: {err}")

    def put(self, ct_m: bytes, ct_k: bytes, uri: str | None = None) -> str:
        uri = uri or os.urandom(16).hex()
        body = _pack(ct_m, ct_k)
        self._c.put_object(self.bucket, uri, io.BytesIO(body), len(body))
        return uri

    def put_many(self, items: list[tuple[bytes, bytes]], workers: int = 16) -> list[str]:
        with ThreadPoolExecutor(workers) as ex:
            return list(ex.map(lambda it: self.put(*it), items))

    def get(self, uri: str) -> tuple[bytes, bytes]:
        resp = self._c.get_object(self.bucket, uri)
        try:
            return _unpack(resp.read())
        finally:
            resp.close()
            resp.release_conn()

    def get_many(self, uris: list[str], workers: int = 16) -> list[tuple[bytes, bytes]]:
        with ThreadPoolExecutor(workers) as ex:
            return list(ex.map(self.get, uris))
