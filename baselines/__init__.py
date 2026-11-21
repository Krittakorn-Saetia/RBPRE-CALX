"""Compared schemes, re-implemented on the same primitives as RBPRE-CALX.

Each scheme executes, per request, record or event, the cost-dominant
operations of its own protocol as listed in the paper's computation cost
comparison (Table IV), on the same groups (Charm-Crypto SS512 pairing group,
NIST P-256), AES-256-GCM, SHA-256 and the same Fabric network. Where a scheme
has no retrieval index, it locates records by scanning the repository index.
Operations a scheme does not support are not run (n/a in the results).

    [25]  X. Wang et al., zero-trust anonymous continuous cross-domain
          authentication for UAVs (IEEE TNSE 2026)
    [27]  J. Yan et al., MediCrypt-DDT, cross-domain distributed dynamic
          threshold ABE (IEEE IoT-J 2026)
    [31]  D. Luo et al., blockchain-based cross-domain authentication with
          dynamic domain participation (IEEE IoT-J 2025)
    PRE   a conventional CP-ABPRE sharing pipeline over the same construction
          of Ibraimi et al. [41], without RBPRE-CALX's discovery, filtering and
          re-key reuse

Every retrieval-side method takes an optional `subset`: when given, the
per-record work runs only on those records (the filter-equalized variant, in
which the baseline is handed the same authorized set T_auth as RBPRE-CALX).
"""
