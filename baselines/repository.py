"""The hospitals' EHR repositories as the compared schemes see them, in a database.

The compared schemes have no cross-domain linkage index, so a requester finds a
patient's records by querying the repository of every hospital. The entries
(owner tag, RID, hospital, class) are kept on the same Neo4j server as
RBPRE-CALX's retrieval graph, with an index on (owner, hospital), so a lookup is
one indexed database query per hospital. RBPRE-CALX's own discovery is one query
over its pseudonymized graph on that server, so both sides pay real database
round trips.
"""

from __future__ import annotations

import os

from neo4j import GraphDatabase, Result

from baselines.common import IndexEntry
from rbpre import config


class DBRepository:
    def __init__(self, uri: str = config.NEO4J_URI, user: str = config.NEO4J_USER,
                 password: str = config.NEO4J_PASSWORD):
        self._drv = GraphDatabase.driver(uri, auth=(user, password))
        self.tag = os.urandom(4).hex()      # this run's entries, for cleanup
        self.hospitals: list[str] = []
        self._synced = 0
        self._run("CREATE INDEX repo_owner_hosp IF NOT EXISTS FOR (r:RepoEntry) ON (r.owner, r.hosp)")
        self._run("CREATE INDEX repo_tag IF NOT EXISTS FOR (r:RepoEntry) ON (r.tag)")
        self._run("CALL db.awaitIndexes(300)")

    def _run(self, query: str, **params):
        records, _, _ = self._drv.execute_query(query, params, database_="neo4j")
        return records

    def sync(self, index: list[IndexEntry], batch: int = 5000) -> None:
        """Insert the entries appended to `index` since the last sync (the workload
        index only grows). Not part of any measurement."""
        new = index[self._synced:]
        rows = [dict(owner=e.owner.hex(), rid=e.rid, hosp=e.hosp, cls=e.cls, tag=self.tag) for e in new]
        q = ("UNWIND $rows AS row CREATE (:RepoEntry {owner: row.owner, rid: row.rid, hosp: row.hosp, "
             "cls: row.cls, tag: row.tag})")
        for i in range(0, len(rows), batch):
            self._run(q, rows=rows[i:i + batch])
        self.hospitals = sorted(set(self.hospitals) | {e.hosp for e in new})
        self._synced = len(index)

    def lookup(self, owner: bytes) -> list[IndexEntry]:
        """The owner's records: one indexed query per hospital repository, each
        returning its matches as one row with one list per field (the same query
        shape as RBPRE-CALX's candidate discovery, rbpre/graph.py)."""
        o = owner.hex()
        q = "MATCH (r:RepoEntry) WHERE r.owner = $o AND r.hosp = $h RETURN collect(r.rid), collect(r.cls)"
        out = []
        for h in self.hospitals:
            rows = self._drv.execute_query(q, {"o": o, "h": h}, database_="neo4j", result_transformer_=Result.values)
            rids, clss = rows[0]
            out += [IndexEntry(owner, r, h, c) for r, c in zip(rids, clss)]
        return out

    def clear(self) -> None:
        with self._drv.session(database="neo4j") as s:
            s.run("MATCH (r:RepoEntry {tag: $t}) CALL (r) { DELETE r } IN TRANSACTIONS OF 10000 ROWS",
                  t=self.tag).consume()

    def close(self) -> None:
        self._drv.close()
