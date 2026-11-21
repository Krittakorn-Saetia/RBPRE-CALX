# RBPRE-CALX prototype: design

This file fixes how each part of the RBPRE-CALX construction (Section III of the
paper) is implemented, and records every choice the paper leaves open. Equation
numbers refer to the revised manuscript.

## Components

| Paper component | Implementation |
|---|---|
| RB-ABPRE (Sec. III-C, Eq. 1–15) over the CP-ABPRE of Ibraimi et al. [41] | `rbpre/abpre.py` (the CP-ABPRE) and `rbpre/rbabpre.py` (the retrieval-bound interface), Charm-Crypto 0.63, curve SS512 |
| AEAD for IoMT data and EHR payloads (Eq. 31, 42) | AES-256-GCM, `rbpre/aead.py` (`cryptography`) |
| H(·) and canonical encoding | SHA-256 over length-prefixed components, `rbpre/encoding.py` |
| Service signatures: patient consent, delegation token, consent service, gateway, KMS (Eq. 10, 26, 33, 60, 64, 85) | Ed25519, `rbpre/sig.py` |
| Credential and holder signatures verified in the circuit (Eq. 18, 52) | EdDSA on Jubjub (the twisted Edwards curve embedded in BLS12-381) with MiMC, in the Go helper `zk/` |
| Groth16 authorization proof R_auth (Eq. 53–56) | gnark, BLS12-381, in the Go helper `zk/` |
| Patient-specific Merkle root (Eq. 78, 80) | SHA-256 binary Merkle tree, `rbpre/merkle.py` |
| Consortium blockchain and smart contracts (DID, credential, consent/CMC, delegation, revocation, record commitments, linkage roots, ComAuth, ComShare) | Hyperledger Fabric 2.5.9, Go chaincode in `chaincode/rbpre/`, deployed as a service (same pattern as FLEX-DIAM V3) |
| Retrieval graph (Eq. 45–46, 71) | Neo4j 5 (Docker), `rbpre/graph.py` |
| Encrypted storage (Eq. 44) | MinIO (Docker), `rbpre/storage.py` |
| Authorization and re-key cache (Eq. 94–95) | Redis 7 (Docker), `rbpre/cache.py` |
| Phases 1–5 | `rbpre/protocol.py`, one method per paper step |
| Compared schemes [25], [27], [31] | `baselines/`, ported from the earlier implementations onto the same primitives |

## The CP-ABPRE of Ibraimi et al. [41]

Symmetric pairing e: G0 × G0 → GT of prime order p (Charm `SS512`). Policies
are monotone AND/OR formulas; the secret is shared additively (AND: random
shares summing to the parent value; OR: every child gets the parent value).

| Algorithm | Output |
|---|---|
| Setup | PK = (g, e(g,g)^(α+β), g^f, {T_j = g^(x_j)}), MK = (α, β, f, {x_j}) |
| KeyGen(MK, ω) | SK = (D1 = g^(α−r), {D2_j = g^((r+β)/x_j)} for a_j ∈ ω) |
| Enc(m, P, PK), m ∈ GT | C1 = g^s, C2 = m·e(g,g)^((α+β)s), C3 = g^(fs), {C4_j = T_j^(s_j)} over the leaves of P |
| RKGen(SK, P1, P2, PK) | D^1 = D1·g^l, D^2 = Enc'(g^(x−l), P2), D^3 = g^(x'), {D^4_j = D2_j} for a minimal satisfying set ω' of P1 |
| ReEnc(CT, rk) | C^1 = C1, C^2 = e(C3, D^3) · C2 / (e(C1, D^1) · Π e(D^4_j, C4_j)) = m·e(g,g)^(s(x−l)), C^3 = D^2 |
| Dec (original) | m = C2 / (e(D1, C1) · Π e(D2_j, C4_j)) |
| Dec (re-encrypted) | g^(x−l) ← Dec'(C^3); m = C^2 / e(C^1, g^(x−l)) |

Enc' encrypts a G0 element with the mask H1(e(g,g)^((α+β)z)), H1: GT → G0.

Choices the paper of [41] leaves open, and how they are resolved here:

1. **The value x.** RKGen uses g^x without defining x. The delegator picks
   x' at random, sets D^3 = g^(x'), and computes g^x = (g^f)^(x'). So x = f·x',
   and the delegator never needs f.
2. **H1: GT → G0** is Charm's hash-to-group on the serialized GT element.
3. **Each attribute appears at most once per policy.** The scheme indexes key
   components by attribute only, so a repeated attribute could not be matched to
   its leaf. Policies are checked for this when they are parsed.
4. **The 256-bit data key** is carried as a KEM: Enc encrypts a random R ∈ GT
   and K_AES = SHA-256(serialize(R)). The data key M of Eq. 7 is therefore R,
   and only CT_k is ever re-encrypted.

The delegator of [41] (the holder of a key satisfying P1) is the KMS holding
sk_{A,S_A}, which matches Eq. 8: rk_{A→B} ← ABPRE.ReKeyGen(PP, sk_{A,S_A}, P_A, P_B).

Security level: SS512 gives about 80-bit security (Charm 0.63 warns about this).
Charm 0.63 does not support BLS12-381, and [41] needs a symmetric pairing. The
paper's Table V must state this.

## Retrieval-bound layer (Eq. 2–15)

- χ = (ComC, ctx, e, sid, Scope, Purpose), h_χ = H(χ) (Eq. 2–3, 67–68).
- ReKeyGen returns RK_{A→B} = (rk, h_χ, pk_B, P_A, P_B, σ_KMS), with
  σ_KMS = Sign_skKMS(D_RK) and D_RK = (H(rk), h_χ, pk_B, H(P_A), H(P_B)) (Eq. 8–11).
- ReEnc rebuilds D_RK, checks σ_KMS, checks H(χ) = h_χ, and checks the caller's
  authorization and membership evidence before running ABPRE.ReEnc (Eq. 12–13).
  This is protocol-level enforcement by an honest proxy, as the paper's security
  model states; it is not an algebraic binding.

## Hashes inside and outside the circuit

Values that the Groth16 circuit recomputes use MiMC over the BLS12-381 scalar
field: the credential message H(Attr_D ∥ DID_D ∥ cid_D ∥ t_VC) (Eq. 18), the policy
digest h_A = H(A), and the request-context digest h_ctx (Eq. 51). Every other
H(·) is SHA-256 with canonical encoding. Identifiers and attributes enter the
field as the first 31 bytes of their SHA-256 digest.

## Process layout

- One Python process runs the protocol roles. Every external service is real
  (Fabric, Neo4j, MinIO, Redis), and each call is timed around the real network
  request.
- The Go helper `zk/rbzk` runs gnark (setup, prove, verify) and the Jubjub
  EdDSA/MiMC operations. Python starts it once and talks to it over
  stdin/stdout, one JSON request per line. Prove and verify times are measured
  inside Go and also end-to-end, so the IPC overhead is visible separately.

## Versions (this development machine)

| Software | Version |
|---|---|
| Python | 3.10.12 (WSL Ubuntu 22.04) |
| Charm-Crypto | 0.63 |
| Go | 1.22.5 |
| Hyperledger Fabric | 2.5.9 |

The paper's setup section must list the versions and the machine used for the
final measurement run.
