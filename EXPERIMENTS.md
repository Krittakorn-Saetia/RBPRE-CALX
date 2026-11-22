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

The figures follow the format of the manuscript's Figs. 2–8 (colours, markers,
log axes, legend, and the bar layout of Fig. 8); `experiments/plot.py`
describes it. Points are means with one-SD error bars, and every figure has a
`summary_<name>.csv` with mean, SD and run count per point.

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

**Stability and top-up runs.**
- `python -m experiments.stability --run <run>` lists every plotted point whose
  95% confidence interval of the mean is wider than ±5% of the mean, or whose
  mean breaks the rise of its curve, with the run count it needs (at most 30).
  It writes `stability.csv`.
- `python -m experiments.topup --run <run>` adds runs to exactly those points
  and repeats the check (two rounds by default; `--dry` prints the plan). The
  drivers then append to the existing files (`RBPRE_TOPUP`, see
  `harness.py`). Each row's `batch` column says which batch produced it, and
  means are taken over all batches. The workloads are rebuilt through the
  original sweep with the same seed, so the added runs measure the same
  records. A copy of each file before it was extended is kept in `batches/`.

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

`baselines/schemes.py` re-implements [25], [27] and [31] with the operations
each scheme's **own paper** specifies (checked against the papers in November
2026). They run on the same
libraries as RBPRE-CALX (Charm-Crypto, NIST P-256, AES-256-GCM, SHA-256, Hess
identity-based signatures on SS512) and the same Fabric network; [27] runs on
its own curve, MNT159.

| | [25] (TNSE 2026, Table V) | [27] (IoT-J 2026, Table II, MNT159) | [31] (IoT-J 2025, Sec. V-B) |
|---|---|---|---|
| Authentication, requester | 2 T_sm + 8 T_h | ShareDecrypt: 1 P | nothing (the device computes no cryptography) |
| Authentication, verifier | 1 T_sm + 10 T_h | ShareVerify: 2 P + (s+1) E + s M | 2 T_IBS^sign + 2 T_IBS^ver (request and response, both on the domains' servers); T_B^qry only for an unknown sender |
| Retrieval, per record (stand-in) | T_h (access token) | Decrypt: 2 P + n E | T_IBS^ver + T_H, one T_B^qry per domain |
| Transformation, per record (stand-in) | symmetric re-wrap (reference only) | Decrypt: 2 P + n E | T_IBS^ver + T_H, one T_B^qry per domain |
| Verification, per record | n/a | ValidCT: 2 P, plus T_H | T_IBS^ver + T_H, one T_B^qry per domain |
| Policy update, per affected record | n/a (T_h blacklist) | Encrypt: P + (s+3) E + 2m M | one state update with consensus |
| Traceability, per event | T_H + one anchoring transaction | T_B^upd + T_con | T_B^upd + T_con |

s = m = n = 10 (the policy size RBPRE-CALX uses) and t = 3. [27]'s
exponentiations are taken in G1, the cheapest MNT159 group, consistent with the
constant encryption time of about 3 ms that [27] reports. None of the three
supports proxy re-encryption or longitudinal retrieval, so the rows marked "stand-in" use the closest operation the scheme has.
`experiments/rerun_baselines.sh` re-measures the series these definitions changed.

None of the three supports longitudinal retrieval (Table IV). In the
retrieval experiments, each locates the patient's records in the hospitals'
repositories, then runs its own per-record validation. The repositories are
kept in the same Neo4j server as RBPRE-CALX's retrieval graph
(`baselines/repository.py`), indexed by patient and hospital. With no
cross-domain linkage, a compared scheme sends one indexed query per hospital,
while RBPRE-CALX sends one query over its pseudonymized graph. Both sides
therefore pay real database round trips (`--repo memory` restores the earlier
in-memory scan). Both use the same result shape, one row per hospital with one
list per field, and the same driver (the Neo4j Python driver with Neo4j's Rust
codec, `neo4j-rust-ext`). At 50k records this takes RBPRE-CALX's candidate query
from about 2.25 s to 0.17 s and the compared schemes' five lookups from about
1.6 s to 0.17 s.

**Requester and gateway side (Exp 1).** Every scheme's authorization is split
into the requester's operations (the doctor's device) and the gateway's or
verifier's operations, and both are timed:

| | Requester side | Gateway / verifier side |
|---|---|---|
| RBPRE-CALX | holder signature, Groth16 proof | challenge, consent attestation, chain state, proof verification, nonce consumption, AuthTok (or ValidState on reuse) |
| [25] | 2 T_sm + 8 T_h | 1 T_sm + 10 T_h |
| [27] | ShareDecrypt (1 P) | ShareVerify (2 P + (s+1) E + s M) |
| [31] | nothing | 2 T_IBS^sign + 2 T_IBS^ver, T_B^qry for an unknown sender |

`e1g_runs.csv` and the figure `e1g_gateway` report the gateway side: the load
a server carries when many requesters authorize at once, since each requester
computes its own proof or signature on its own device.

**Storage reads.** In Exps 3, 4 and 6 every scheme reads the ciphertexts it
transforms or verifies from the same MinIO store, with the same call
(`EHRStore.get_many`, 16 parallel reads) that RBPRE-CALX's proxy and verifier
use. RBPRE-CALX's verification (Phase 4) and its proxy (Phase 5) each read
the records they need, as the protocol has them as separate parties. The
proxy parses each fetched ciphertext inside its timed step and re-encrypts that
copy, so deserialization is in the measurement for every scheme.

A fourth scheme, **PRE**, is a conventional CP-ABPRE sharing pipeline over the
same construction of Ibraimi et al. It scans for the patient's records,
transforms all of them, and generates a fresh re-encryption key per record.
It uses the same ciphertexts as RBPRE-CALX, so the single-attribute source
policy src:H_j/c (one leaf pairing in ReEnc) shortens both equally.

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
    the session) and a hit (second use), timed by wall clock around the whole
    transformation. The proxy checks each re-key state once and every
    ciphertext's binding and source policy individually.
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
  steady-state retrieval (a repeated request in a live session, measured after
  one untimed retrieval under the current epoch)
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
