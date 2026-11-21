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
$PY -m experiments.exp234_retrieval       # Experiments 2, 3, 4
$PY -m experiments.exp5_trace             # Experiment 5
$PY -m experiments.exp6_hospitals         # Experiment 6
$PY -m experiments.exp7_ablation          # Experiment 7
$PY -m experiments.exp_revocation         # revocation and consent-update cost
$PY -m experiments.plot                   # figures + summary tables (needs matplotlib)
```

Every driver has `--help`. `experiments/run_all.sh` runs them in order and is
resumable. `PROFILE=full` runs every experiment with the defaults. `PROFILE=quick`
runs the set the revision needs, with fewer points and runs:

- micro
- Exp 1 with 10 runs
- Exps 2–4 at 1k/5k/10k/25k/50k records with 10 runs
- revocation at 1k/10k records with 5 runs
- Exp 7 with 10 runs

**Measurement hygiene.**
- **Warm-up.** Each series starts with one warm-up run that is not recorded.
  A series is "heavy" when that first run already takes longer than
  `--heavy-s` (default 60 s). It then counts as the first measured run, and
  the series stops at `--runs-heavy` runs; the CSV keeps the actual run count
  of every mean.
- **No collector pauses.** Every timed run is measured with Python's cyclic
  garbage collector paused (`harness.quiet`).
- **Fixed workload.** The workload uses a fixed random seed.

**Chain client.** All schemes use the same Fabric Gateway client (`fabgw`,
`RBPRE_CHAIN=gateway`, the default). RBPRE-CALX's validity checks read the
gateway's synchronized mirror of the finalized state. `RBPRE_CHAIN=cli`
switches every scheme to the peer CLI.

## Workload (`experiments/workload.py`)

- **Records.** One requester at the first hospital. Each target patient has N
  records spread uniformly over H hospitals, with timestamps over two years.
- **Delegation.** Every hospital, including the requester's own, delegates to
  the requester's domain.
- **Authorized fraction.** A record is authorized with probability
  `--ratio`: its class is drawn from the classes the cardiology scope and
  treatment purpose permit. Otherwise its class is one the policy excludes
  (psych, genetic, admin).
- **Ground truth.** Every run checks that the T_auth RBPRE-CALX computes equals
  the generator's set of authorized records.
- **Background records.** Records of other patients (`--background` × N) go
  into the retrieval graph and the scan index only.
- **Payloads.** 256 random bytes per reading.

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
  - **RBPRE-CALX Reuse** runs Phase 3 once per session, for each value of
    `--session-sizes` (10, 50, and 0 = one session for all k requests). Every
    other request in the session runs ValidState (Eq. 70): the holder-session
    binding, the synchronized chain state (credential, consent, delegation,
    epoch) and the AuthTok signature. Freshness is not reused: every new
    session needs a fresh challenge and proof.
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

## Experiments 2–4 (`experiments.exp234_retrieval`)

These run on one patient history that grows through N ∈ {1k, 5k, 10k, 20k,
30k, 40k, 50k} (H = 5, ratio 10%). At each N, a first retrieval creates the
new linkage entries and is reported as `first`. Every run then uses a new
session.

- **Exp 2: retrieval latency.**
  - **RBPRE-CALX:** T_ret of Eq. 158, which covers admission,
    historical-pseudonym resolution and graph discovery, metadata-opening
    verification and record-level filtering. The verification part of Phase
    4 (Eq. 159) is Experiment 4. The whole of Phase 4 is also kept, as variant
    `with verification`.
  - **Baselines:** repository scan plus their per-record validation, on all
    of the patient's records and filter-equalized.
- **Exp 3: transformation.**
  - **RBPRE-CALX:** Phase 5 on T_auth, with a re-key cache miss (first use in
    the session) and a hit (second use).
  - **Baselines:** transformation of every patient record, and of T_auth only.
- **Exp 4: verification.**
  - **RBPRE-CALX:** the verification steps of Phase 4 (fetch, record
    commitments, linkage state, Merkle proofs).
  - **[27], [31] and PRE:** their per-record verification over the same |T_f|
    records.

## Experiment 5 (`experiments.exp5_trace`)

For E ∈ {10, 50, 100, 250, 500, 1000} audit events, the driver measures the
time until all evidence is committed on Fabric:

- **RBPRE-CALX and [25]:** batched commitments.
- **[27] and [31]:** one transaction per event, from `--concurrency` (10)
  parallel clients.

The per-event schemes need one Fabric transaction per event, so larger E
values take very long to run.

## Experiment 6 (`experiments.exp6_hospitals`)

N = 5,000 records over H ∈ {1, 2, 5, 10, 15, 20} hospitals.

- **RBPRE-CALX:** discovery plus selective transformation in a new session.
- **Baselines:** one authentication per hospital, scan, transformation and
  verification, on all records and filter-equalized.

## Experiment 7 (`experiments.exp7_ablation`)

N = 10,000 and |T_auth|/N ∈ {1, 5, 10, 25, 50, 75, 100}%, with five variants:

- the full framework (repeated request in a valid session)
- (i) a new proof and no re-key cache
- (ii) no early filter
- (iii) every candidate transformed
- (iv) (ii) and (iii) together

`e7_stages.csv` holds per-stage times for stacked bars. `plot` writes
`e7_welch.csv`, Welch's t-test between (iii) and (iv) at each ratio.

## Revocation and consent updates (`experiments.exp_revocation`)

For N ∈ {1k, 5k, 10k} records and S ∈ {1, 10, 50} live sessions with cached
re-key states, every run measures four events:

- a policy update (new epoch, pseudonym and consent; invalidation), then the
  hospitals' re-delegation and the first retrieval afterwards, against a
  steady-state retrieval
- consent withdrawal
- delegation revocation
- credential revocation

Each Fabric write waits for commit, so event times include finalization.

- **No re-pseudonymization.** The driver asserts that every record, including
  records from earlier epochs, is still retrieved after the epoch advance. No
  stored record is re-pseudonymized.
- **Compared schemes:**
  - [27] re-encrypts every affected ciphertext: T_P + (m+1) T_E + m T_M per
    record.
  - [31] runs one state update with consensus.
  - [25] blacklists with T_H.
