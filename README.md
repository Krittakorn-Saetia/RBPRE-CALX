# RBPRE-CALX

Prototype and measurement harness for **RBPRE-CALX: Retrieval-Bound Proxy
Re-Encryption for Consent-Aware Longitudinal Retrieval of Cross-Domain
IoMT-EHRs**.

RBPRE-CALX combines DID/verifiable-credential authorization with a
holder-bound Groth16 proof, consent-before-discovery over a pseudonymized
retrieval graph, authenticated record-level filtering, retrieval-bound
attribute-based proxy re-encryption (RB-ABPRE) over the CP-ABPRE of Ibraimi
et al., and blockchain-anchored record and linkage commitments.

**Status: under construction.** The crypto core is implemented and tested. The
ZKP circuit, chaincode, storage/graph/cache services, the five protocol phases,
the compared schemes and the experiment drivers follow.

- [DESIGN.md](DESIGN.md): how each part of the construction is implemented,
  and every choice the paper leaves open.

## Layout

| Path | Content |
|---|---|
| `rbpre/encoding.py` | H(·) = SHA-256 over canonical length-prefixed encoding; HKDF |
| `rbpre/policy.py` | AND/OR policy parser, additive secret sharing, minimal satisfying sets |
| `rbpre/abpre.py` | CP-ABPRE of Ibraimi et al. (SECRYPT 2010) on Charm-Crypto SS512, with a KEM for the 256-bit data key |
| `rbpre/rbabpre.py` | RB-ABPRE interface (Eq. 1–15): KMS, authenticated re-key states, proxy re-encryption checks |
| `rbpre/aead.py` | AES-256-GCM |
| `rbpre/sig.py` | Ed25519 protocol signatures |
| `rbpre/merkle.py` | Patient-specific Merkle tree (Eq. 78, 80) |
| `tests/` | unit tests |

## Running the tests

The code runs on Ubuntu 22.04 (native or WSL2) with Python 3.10+ and
Charm-Crypto 0.63. On a machine set up for FLEX-DIAM V3, the existing virtual
environment already has both:

```bash
cd rbpre-calx
~/flex-diam/venv/bin/python -m unittest discover -s tests -t . -v
```
