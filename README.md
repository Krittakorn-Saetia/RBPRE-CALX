# RBPRE-CALX

Prototype and measurement harness for **RBPRE-CALX: Retrieval-Bound Proxy
Re-Encryption for Consent-Aware Longitudinal Retrieval of Cross-Domain
IoMT-EHRs**.

RBPRE-CALX combines DID/verifiable-credential authorization with a
holder-bound Groth16 proof, consent-before-discovery over a pseudonymized
retrieval graph, authenticated record-level filtering, retrieval-bound
attribute-based proxy re-encryption (RB-ABPRE) over the CP-ABPRE of Ibraimi
et al., and blockchain-anchored record and linkage commitments.

**Status: under construction.** Done so far:
- the crypto core
- the Groth16 authorization circuits
- the Neo4j, MinIO and Redis clients

Still to come: the Fabric chaincode, the five protocol phases, the compared
schemes and the experiment drivers.

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
| `zk/` | Go helper: gnark Groth16 on BLS12-381 (holder-bound and original R_auth), Jubjub EdDSA, MiMC |
| `infra/` | Python environment, Docker Compose services, MinIO build |
| `tests/` | unit and integration tests |

## Setup (Ubuntu 22.04, native or WSL2, with Docker)

```bash
infra/setup_venv.sh                       # Python venv in ~/.venvs/rbpre-calx (Charm-Crypto 0.63)
(cd zk && go build -o rbzk .)             # Go 1.22+
infra/build_minio.sh                      # MinIO from the official source, once
infra/services.sh up                      # Neo4j, Redis, MinIO on 127.0.0.1
~/.venvs/rbpre-calx/bin/python -m unittest discover -s tests -t . -v
(cd zk && go test ./...)
```
