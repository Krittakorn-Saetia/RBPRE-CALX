"""rbpre.graph: the pseudonymized retrieval graph G = (V, E) on Neo4j.

Each protected EHR object is a record reference (RID*, PID*, phi, H(A), URI)
(Eq. 45, 69) with relationships (PID*) -OWNS-> (RID*) -LOCATED_IN-> (H_j)
(Eq. 46). Candidate discovery returns every record reachable from the
authenticated set of historical patient pseudonyms P_PID (Eq. 71):

    T_D = { RID_i | exists p in P_PID : Path(p, RID_i) }

The graph server sees pseudonyms and topology only; it evaluates no policy.
All identifiers are stored as hex strings.
"""

from __future__ import annotations

from neo4j import GraphDatabase

from rbpre import config


class RetrievalGraph:
    def __init__(self, uri: str = config.NEO4J_URI, user: str = config.NEO4J_USER,
                 password: str = config.NEO4J_PASSWORD):
        self._drv = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self._drv.close()

    def _run(self, query: str, **params):
        records, _, _ = self._drv.execute_query(query, params, database_="neo4j")
        return records

    def setup(self) -> None:
        for label, prop in (("Patient", "pid"), ("Record", "rid"), ("Hospital", "hid")):
            self._run(f"CREATE CONSTRAINT {label.lower()}_{prop} IF NOT EXISTS "
                      f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE")

    def clear(self) -> None:
        # CALL ... IN TRANSACTIONS needs an auto-commit transaction
        with self._drv.session(database="neo4j") as s:
            s.run("MATCH (n) CALL { WITH n DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS").consume()

    def delete_patients(self, pids: list[str]) -> None:
        """Remove the given patients and all their records."""
        self._run("MATCH (p:Patient)-[:OWNS]->(r:Record) WHERE p.pid IN $pids DETACH DELETE r", pids=pids)
        self._run("MATCH (p:Patient) WHERE p.pid IN $pids DETACH DELETE p", pids=pids)

    def add_records(self, rows: list[dict], batch: int = 5000) -> None:
        """rows: dicts with rid, pid, phi, ha, uri, hosp (Eq. 45-46)."""
        q = ("UNWIND $rows AS row "
             "MERGE (p:Patient {pid: row.pid}) "
             "MERGE (h:Hospital {hid: row.hosp}) "
             "CREATE (r:Record {rid: row.rid, phi: row.phi, ha: row.ha, uri: row.uri}) "
             "CREATE (p)-[:OWNS]->(r) "
             "CREATE (r)-[:LOCATED_IN]->(h)")
        for i in range(0, len(rows), batch):
            self._run(q, rows=rows[i:i + batch])

    def candidates(self, pids: list[str]) -> list[dict]:
        """T_D for the historical pseudonyms P_PID (Eq. 71)."""
        q = ("MATCH (p:Patient)-[:OWNS]->(r:Record)-[:LOCATED_IN]->(h:Hospital) "
             "WHERE p.pid IN $pids "
             "RETURN r.rid AS rid, p.pid AS pid, r.phi AS phi, r.ha AS ha, r.uri AS uri, h.hid AS hosp")
        return [dict(r) for r in self._run(q, pids=pids)]

    def rename_patient(self, old_pid: str, new_pid: str) -> int:
        """Re-pseudonymize a patient node after an epoch advance."""
        rec = self._run("MATCH (p:Patient {pid: $old}) SET p.pid = $new RETURN count(p) AS n",
                        old=old_pid, new=new_pid)
        return rec[0]["n"]

    def rename_records(self, pairs: list[tuple[str, str]], batch: int = 5000) -> int:
        """Re-pseudonymize record nodes: pairs of (old RID*, new RID*)."""
        q = ("UNWIND $pairs AS pr MATCH (r:Record {rid: pr[0]}) SET r.rid = pr[1] "
             "RETURN count(r) AS n")
        n = 0
        for i in range(0, len(pairs), batch):
            n += self._run(q, pairs=[list(p) for p in pairs[i:i + batch]])[0]["n"]
        return n

    def count(self) -> dict:
        rec = self._run("MATCH (r:Record) WITH count(r) AS records "
                        "MATCH (p:Patient) RETURN records, count(p) AS patients")
        return dict(rec[0]) if rec else {"records": 0, "patients": 0}
