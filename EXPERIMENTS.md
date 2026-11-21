# Experiments

Each driver writes raw per-run rows to `results/<run>/` (`RBPRE_RUN`, default
`dev`) together with `machine.json`, a description of the hardware and software
the run used. Every configuration runs `--runs` times (default 30), and results
are reported as mean ± SD of absolute times. Plots are generated from the CSV
files only.

```bash
export RBPRE_RUN=final-<machine>
PY=~/.venvs/rbpre-calx/bin/python
$PY -m experiments.micro                  # primitive and building-block costs
$PY -m experiments.exp1_authz             # Experiment 1 (a)(b)(c)
```

## Compared schemes

`baselines/schemes.py` re-implements [25], [27] and [31] on the same primitives
as RBPRE-CALX: the Charm-Crypto SS512 pairing group, NIST P-256, AES-256-GCM,
SHA-256, Hess identity-based signatures, and the same Fabric network. Each one
executes the cost-dominant operations of its own protocol, per request, record
or event, as listed in the paper's computation cost comparison (Table IV).

| | [25] | [27] | [31] |
|---|---|---|---|
| Authentication | T_sm + T_p + T_H + T_sym + T_add | T_P + m T_E + m T_M | T_IBS^sign + T_IBS^ver + T_H + T_B^qry |
| Transformation, per record | n/a (symmetric re-wrap, as a reference) | T_P + t T_E + t T_M | T_IBS^ver + T_H, one T_B^qry per domain |
| Verification, per record | n/a | T_P + T_H | T_IBS^ver + T_H, one T_B^qry per domain |
| Traceability, per event | T_H + one anchoring transaction | T_B^upd + T_con | T_B^upd + T_con |

None of the three supports longitudinal retrieval (Table IV). In the
retrieval experiments, each locates the patient's records by scanning the
repository index, then runs its own per-record validation.

A fourth scheme, **PRE**, is a conventional CP-ABPRE sharing pipeline over the
same construction of Ibraimi et al. It scans for the patient's records,
transforms all of them, and generates a fresh re-encryption key per record.

**Filter-equalized variants.** Every retrieval-side baseline method accepts
`subset`. When it is set, the baseline does its per-record work only on the
authorized set T_auth that RBPRE-CALX computes. Comparing both variants
separates the effect of restricting work to T_auth, which any scheme could
get from a query filter, from the effect of RBPRE-CALX's own mechanisms.

## Microbenchmarks (`experiments.micro`)

This driver measures:

- pairing-group operations (SS512) and P-256 operations
- SHA-256, HMAC, AES-256-GCM (1 KB, 64 KB, 1 MB)
- Ed25519 and Hess IBS signatures
- every CP-ABPRE algorithm for AND policies of m ∈ {2, 5, 10, 20, 30} attributes, with sizes
- the RB-ABPRE layer
- Merkle trees of 1k, 10k and 50k leaves
- MiMC and Jubjub EdDSA (inside Go)
- round trips to Redis, MinIO, Neo4j and Fabric (query, and transaction to commit)

## Experiment 1: authorization (`experiments.exp1_authz`)

- **(a) Circuit cost.** The original relation of the first submission and
  the holder-bound R_auth, for m ∈ {5, 10, 15, 20, 25, 30}. It reports R1CS
  constraints, public inputs, compile and setup time (the one-time
  circuit-specific setup), witness, proving and verification times measured
  inside Go and end to end, and proof and key sizes.
- **(b) Cumulative authorization latency for k requests.**
  - **RBPRE-CALX Fresh** runs the full Phase 3 (challenge, holder signature,
    proof, consent attestation, chain state, verification, nonce consumption,
    AuthTok) per request.
  - **RBPRE-CALX Reuse** runs Phase 3 once per session of `--session-size`
    requests. Every other request in the session runs ValidState (Eq. 70):
    the holder-session binding, the chain state (credential, consent,
    delegation, epoch) and the AuthTok signature. Freshness is not reused:
    every new session needs a fresh challenge and proof.
  - The baselines run their authentication k times.
  - Requests are served one after another, and the result is their total
    latency.
- **(c) Freshness, replay and holder binding.**
  - It runs nine checks: an honest request, a replayed (challenge, proof), a
    proof presented under a new challenge, a stale challenge, another channel
    binding, a stolen credential without the holder key, an expired
    credential, a revoked credential, and two concurrent submissions of one
    proof.
  - It records the outcome and the time to rejection.
