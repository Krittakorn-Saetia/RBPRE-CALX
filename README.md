# RBPRE-CALX

Prototype and measurement harness for **RBPRE-CALX: Retrieval-Bound Proxy
Re-Encryption for Consent-Aware Longitudinal Retrieval of Cross-Domain
IoMT-EHRs**.

RBPRE-CALX combines DID/verifiable-credential authorization with a
holder-bound Groth16 proof, consent-before-discovery over a pseudonymized
retrieval graph, authenticated record-level filtering, retrieval-bound
attribute-based proxy re-encryption (RB-ABPRE) over the CP-ABPRE of Ibraimi
et al., and blockchain-anchored record and linkage commitments.

**Status:** the prototype, the compared schemes and all experiment drivers
are implemented and smoke-tested. The final measurement runs are pending.

- [EXPERIMENTS.md](EXPERIMENTS.md): every experiment, how the compared
  schemes are modeled, and how to run them.

- [DESIGN.md](DESIGN.md): how each part of the construction is implemented,
  and every choice the paper leaves open.

## Layout

| Path | Content |
|---|---|
| `rbpre/encoding.py` | H(·) = SHA-256 over canonical length-prefixed encoding; HKDF |
| `rbpre/policy.py` | AND/OR policy parser, additive secret sharing, minimal satisfying sets |
| `rbpre/abpre.py` | CP-ABPRE of Ibraimi et al. (SECRYPT 2010) on Charm-Crypto SS512, with a KEM for the 256-bit data key |
| `rbpre/rbabpre.py` | RB-ABPRE interface (Eq. 1–15): KMS, authenticated re-key states, proxy re-encryption checks |
| `rbpre/aead.py`, `rbpre/sig.py`, `rbpre/merkle.py` | AES-256-GCM, Ed25519, patient Merkle tree |
| `rbpre/zk.py` | client for the `zk/rbzk` helper |
| `rbpre/graph.py`, `rbpre/storage.py`, `rbpre/cache.py` | Neo4j retrieval graph, MinIO EHR store, Redis nonces/sessions/re-key cache |
| `rbpre/chain.py` | Fabric clients: Gateway (default, with the synchronized state mirror) and peer CLI; an in-memory ledger for offline tests |
| `fabgw/` | Go helper: Fabric Gateway client that keeps a mirror of the finalized state from chaincode events |
| `rbpre/protocol.py` | Phases 1–5, one method per paper step, with per-step timers |
| `chaincode/` | Go chaincode (DID, credential, consent/CMC, delegation, epoch, record, linkage, anchors) and its ccaas deploy script |
| `smoke_protocol.py` | one end-to-end run with a per-step latency breakdown |
| `baselines/` | compared schemes [25], [27], [31] and a conventional CP-ABPRE pipeline |
| `experiments/` | workload generator, experiment drivers, microbenchmarks, plotting |
| `zk/` | Go helper: gnark Groth16 on BLS12-381 (holder-bound and original R_auth), Jubjub EdDSA, MiMC |
| `infra/` | Python environment, Docker Compose services, MinIO build |
| `tests/` | unit and integration tests |

## Setup (Ubuntu 22.04, native or WSL2, with Docker)

```bash
infra/setup_venv.sh                       # Python venv in ~/.venvs/rbpre-calx (Charm-Crypto 0.63)
(cd zk && go build -o rbzk .)             # Go 1.22+
(cd fabgw && go build -o fabgw .)         # Fabric Gateway client + state mirror
infra/build_minio.sh                      # MinIO from the official source, once
infra/services.sh up                      # Neo4j, Redis, MinIO on 127.0.0.1
infra/fabric.sh up                        # Fabric test-network + channel rbpre
chaincode/deploy_ccaas.sh                 # deploy the chaincode, once
~/.venvs/rbpre-calx/bin/python -m unittest discover -s tests -t . -v
RBPRE_FABRIC=1 ~/.venvs/rbpre-calx/bin/python -m unittest tests.test_protocol -v
(cd zk && go test ./...)
~/.venvs/rbpre-calx/bin/python smoke_protocol.py
```

The Fabric test-network comes from a FLEX-DIAM V3 machine setup
(`~/flex-diam/fabric-samples`, Fabric 2.5.9, BatchTimeout 1 s); set
`FLEX_INFRA` if it is elsewhere.
