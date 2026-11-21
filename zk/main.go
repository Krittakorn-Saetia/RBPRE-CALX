// rbzk: Groth16 (gnark, BLS12-381), Jubjub EdDSA and MiMC for RBPRE-CALX.
//
// The Python protocol starts one rbzk process and sends one JSON request per
// line on stdin; each response is one JSON line on stdout. Every timing is
// measured inside this process with time.Now(), so IPC overhead is excluded
// here and measured separately on the Python side.
//
// Requests ("op"):
//
//	setup      {circuit: "holder"|"original", m}      compile + circuit-specific Groth16 setup
//	prove      {circuit, m, pub, wit}                 -> proof (hex)
//	verify     {circuit, m, pub, proof}               -> valid
//	keygen     {}                                     -> Jubjub EdDSA key pair
//	sign       {sk, msg}                              -> signature over one field element
//	verify_sig {pk, msg, sig}                         -> valid
//	mimc       {inputs: [field elements]}             -> MiMC digest
//
// Field elements are hex big-endian integers below the BLS12-381 scalar field
// modulus; points and signatures are hex of gnark-crypto's compressed encoding.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	frmimc "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	jubjub "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
)

type PubIn struct {
	DID     string `json:"did"`
	Cid     string `json:"cid"`
	PID     string `json:"pid"`
	Purpose string `json:"purpose"`
	Scope   string `json:"scope"`
	Epoch   int64  `json:"epoch"`
	TG      int64  `json:"tg"`
	TNow    int64  `json:"tnow"`
	NG      string `json:"ng"`
	HCtx    string `json:"hctx"`
	HA      string `json:"ha"`
	CB      string `json:"cb"`
	PkCI    string `json:"pk_ci"`
	PkD     string `json:"pk_d"`
}

type WitIn struct {
	Attr   []string `json:"attr"`
	TVC    int64    `json:"tvc"`
	VC     string   `json:"vc"`
	Req    []string `json:"req"`
	Purp   string   `json:"purp"`
	Scope  string   `json:"scope"`
	TStart int64    `json:"tstart"`
	TEnd   int64    `json:"tend"`
	SigD   string   `json:"sig_d"`
}

type Request struct {
	Op      string   `json:"op"`
	Circuit string   `json:"circuit"`
	M       int      `json:"m"`
	Pub     PubIn    `json:"pub"`
	Wit     WitIn    `json:"wit"`
	Proof   string   `json:"proof"`
	SK      string   `json:"sk"`
	PK      string   `json:"pk"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Inputs  []string `json:"inputs"`
}

type entry struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
}

var circuits = map[string]*entry{}

func key(circuit string, m int) string { return fmt.Sprintf("%s/%d", circuit, m) }

func ms(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }

// ---------------------------------------------------------------- encoding

func fieldOf(s string) (*big.Int, error) {
	if s == "" {
		return big.NewInt(0), nil
	}
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("bad field element %q", s)
	}
	if v.Sign() < 0 || v.Cmp(fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("field element out of range")
	}
	return v, nil
}

func fieldBytes(v *big.Int) []byte {
	b := make([]byte, fr.Bytes)
	return v.FillBytes(b)
}

func mustHex(s string) ([]byte, error) { return hex.DecodeString(s) }

func mimcOf(vals []*big.Int) *big.Int {
	h := frmimc.NewMiMC()
	for _, v := range vals {
		h.Write(fieldBytes(v))
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

func fieldsOf(hexes []string) ([]*big.Int, error) {
	out := make([]*big.Int, len(hexes))
	for i, s := range hexes {
		v, err := fieldOf(s)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// ------------------------------------------------------------- assignments

type parsed struct {
	f    map[string]*big.Int
	attr []*big.Int
	req  []*big.Int
}

func parseIn(m int, p PubIn, w WitIn, needWitness bool) (*parsed, error) {
	out := &parsed{f: map[string]*big.Int{}}
	named := map[string]string{"did": p.DID, "cid": p.Cid, "pid": p.PID, "purpose": p.Purpose,
		"scope": p.Scope, "ng": p.NG, "hctx": p.HCtx, "ha": p.HA, "cb": p.CB,
		"purp": w.Purp, "pscope": w.Scope}
	for k, s := range named {
		v, err := fieldOf(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out.f[k] = v
	}
	if needWitness {
		if len(w.Attr) != m || len(w.Req) != m {
			return nil, fmt.Errorf("attr and req must have exactly m=%d slots", m)
		}
		var err error
		if out.attr, err = fieldsOf(w.Attr); err != nil {
			return nil, err
		}
		if out.req, err = fieldsOf(w.Req); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func assignPolicy(a *Policy, ps *parsed, w WitIn) {
	for i, v := range ps.req {
		a.Req[i] = v
	}
	a.Purp, a.Scope, a.TStart, a.TEnd = ps.f["purp"], ps.f["pscope"], w.TStart, w.TEnd
}

func assignHolder(m int, p PubIn, w WitIn, needWitness bool) (*HolderCircuit, error) {
	ps, err := parseIn(m, p, w, needWitness)
	if err != nil {
		return nil, err
	}
	c := NewHolderCircuit(m)
	c.DID, c.Cid, c.PID, c.Purpose, c.Scope = ps.f["did"], ps.f["cid"], ps.f["pid"], ps.f["purpose"], ps.f["scope"]
	c.Epoch, c.TG, c.NG, c.HCtx, c.HA, c.CB = p.Epoch, p.TG, ps.f["ng"], ps.f["hctx"], ps.f["ha"], ps.f["cb"]
	pkCI, err := mustHex(p.PkCI)
	if err != nil {
		return nil, err
	}
	pkD, err := mustHex(p.PkD)
	if err != nil {
		return nil, err
	}
	c.PkCI.Assign(tedwards.BLS12_381, pkCI)
	c.PkD.Assign(tedwards.BLS12_381, pkD)
	if needWitness {
		for i, v := range ps.attr {
			c.Attr[i] = v
		}
		c.TVC = w.TVC
		assignPolicy(&c.A, ps, w)
		vc, err := mustHex(w.VC)
		if err != nil {
			return nil, err
		}
		sigD, err := mustHex(w.SigD)
		if err != nil {
			return nil, err
		}
		c.VC.Assign(tedwards.BLS12_381, vc)
		c.SigD.Assign(tedwards.BLS12_381, sigD)
	}
	return c, nil
}

func assignOriginal(m int, p PubIn, w WitIn, needWitness bool) (*OriginalCircuit, error) {
	ps, err := parseIn(m, p, w, needWitness)
	if err != nil {
		return nil, err
	}
	c := NewOriginalCircuit(m)
	c.DID, c.PID, c.Purpose, c.Scope = ps.f["did"], ps.f["pid"], ps.f["purpose"], ps.f["scope"]
	c.Epoch, c.TNow, c.HCtx, c.HA = p.Epoch, p.TNow, ps.f["hctx"], ps.f["ha"]
	pkCI, err := mustHex(p.PkCI)
	if err != nil {
		return nil, err
	}
	c.PkCI.Assign(tedwards.BLS12_381, pkCI)
	if needWitness {
		for i, v := range ps.attr {
			c.Attr[i] = v
		}
		c.TVC = w.TVC
		assignPolicy(&c.A, ps, w)
		vc, err := mustHex(w.VC)
		if err != nil {
			return nil, err
		}
		c.VC.Assign(tedwards.BLS12_381, vc)
	}
	return c, nil
}

func assignment(r *Request, needWitness bool) (frontend.Circuit, error) {
	switch r.Circuit {
	case "holder":
		return assignHolder(r.M, r.Pub, r.Wit, needWitness)
	case "original":
		return assignOriginal(r.M, r.Pub, r.Wit, needWitness)
	}
	return nil, fmt.Errorf("unknown circuit %q", r.Circuit)
}

func blank(circuit string, m int) (frontend.Circuit, error) {
	if m < 1 || m > 256 {
		return nil, fmt.Errorf("m out of range")
	}
	switch circuit {
	case "holder":
		return NewHolderCircuit(m), nil
	case "original":
		return NewOriginalCircuit(m), nil
	}
	return nil, fmt.Errorf("unknown circuit %q", circuit)
}

// ------------------------------------------------------------------ proofs

// Compressed Groth16 proof (A, B, C) = 48 + 96 + 48 = 192 bytes when the
// circuit has no commitments; otherwise gnark's full encoding is used.
func encodeProof(p groth16.Proof) []byte {
	bp := p.(*groth16bls.Proof)
	if len(bp.Commitments) == 0 {
		a, b, c := bp.Ar.Bytes(), bp.Bs.Bytes(), bp.Krs.Bytes()
		out := append(append(a[:], b[:]...), c[:]...)
		return out
	}
	var buf bytes.Buffer
	p.WriteTo(&buf)
	return buf.Bytes()
}

func decodeProof(data []byte) (groth16.Proof, error) {
	bp := new(groth16bls.Proof)
	if len(data) == 192 {
		if _, err := bp.Ar.SetBytes(data[:48]); err != nil {
			return nil, err
		}
		if _, err := bp.Bs.SetBytes(data[48:144]); err != nil {
			return nil, err
		}
		if _, err := bp.Krs.SetBytes(data[144:]); err != nil {
			return nil, err
		}
		return bp, nil
	}
	_, err := bp.ReadFrom(bytes.NewReader(data))
	return bp, err
}

func setup(circuit string, m int) (map[string]any, error) {
	c, err := blank(circuit, m)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return nil, err
	}
	t1 := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	t2 := time.Now()
	circuits[key(circuit, m)] = &entry{ccs, pk, vk}
	var pkb, vkb bytes.Buffer
	pk.WriteTo(&pkb)
	vk.WriteTo(&vkb)
	return map[string]any{
		"constraints": ccs.GetNbConstraints(), "public": ccs.GetNbPublicVariables() - 1,
		"secret": ccs.GetNbSecretVariables(), "compile_ms": ms(t1.Sub(t0)), "setup_ms": ms(t2.Sub(t1)),
		"pk_bytes": pkb.Len(), "vk_bytes": vkb.Len(),
	}, nil
}

func lookup(circuit string, m int) (*entry, error) {
	e, ok := circuits[key(circuit, m)]
	if !ok {
		return nil, fmt.Errorf("circuit %s not set up", key(circuit, m))
	}
	return e, nil
}

func prove(r *Request) (map[string]any, error) {
	e, err := lookup(r.Circuit, r.M)
	if err != nil {
		return nil, err
	}
	a, err := assignment(r, true)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	w, err := frontend.NewWitness(a, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, err
	}
	t1 := time.Now()
	proof, err := groth16.Prove(e.ccs, e.pk, w)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	t2 := time.Now()
	enc := encodeProof(proof)
	return map[string]any{"proof": hex.EncodeToString(enc), "proof_bytes": len(enc),
		"witness_ms": ms(t1.Sub(t0)), "prove_ms": ms(t2.Sub(t1))}, nil
}

func verify(r *Request) (map[string]any, error) {
	e, err := lookup(r.Circuit, r.M)
	if err != nil {
		return nil, err
	}
	a, err := assignment(r, false)
	if err != nil {
		return nil, err
	}
	raw, err := mustHex(r.Proof)
	if err != nil {
		return nil, err
	}
	proof, err := decodeProof(raw)
	if err != nil {
		return map[string]any{"valid": false, "reason": err.Error()}, nil
	}
	t0 := time.Now()
	pw, err := frontend.NewWitness(a, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, err
	}
	verr := groth16.Verify(proof, e.vk, pw)
	t1 := time.Now()
	out := map[string]any{"valid": verr == nil, "verify_ms": ms(t1.Sub(t0))}
	if verr != nil {
		out["reason"] = verr.Error()
	}
	return out, nil
}

// --------------------------------------------------------------- signatures

func keygen() (map[string]any, error) {
	sk, err := jubjub.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return map[string]any{"sk": hex.EncodeToString(sk.Bytes()), "pk": hex.EncodeToString(sk.PublicKey.Bytes())}, nil
}

func sign(r *Request) (map[string]any, error) {
	raw, err := mustHex(r.SK)
	if err != nil {
		return nil, err
	}
	sk := new(jubjub.PrivateKey)
	if _, err := sk.SetBytes(raw); err != nil {
		return nil, err
	}
	msg, err := fieldOf(r.Msg)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	sig, err := sk.Sign(fieldBytes(msg), hash.MIMC_BLS12_381.New())
	if err != nil {
		return nil, err
	}
	return map[string]any{"sig": hex.EncodeToString(sig), "sign_ms": ms(time.Since(t0))}, nil
}

func verifySigOp(r *Request) (map[string]any, error) {
	raw, err := mustHex(r.PK)
	if err != nil {
		return nil, err
	}
	pk := new(jubjub.PublicKey)
	if _, err := pk.SetBytes(raw); err != nil {
		return map[string]any{"valid": false}, nil
	}
	msg, err := fieldOf(r.Msg)
	if err != nil {
		return nil, err
	}
	sig, err := mustHex(r.Sig)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	ok, err := pk.Verify(sig, fieldBytes(msg), hash.MIMC_BLS12_381.New())
	return map[string]any{"valid": ok && err == nil, "verify_ms": ms(time.Since(t0))}, nil
}

func mimcOp(r *Request) (map[string]any, error) {
	vals, err := fieldsOf(r.Inputs)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	d := mimcOf(vals)
	return map[string]any{"digest": fmt.Sprintf("%064x", d), "hash_ms": ms(time.Since(t0))}, nil
}

// --------------------------------------------------------------------- main

func handle(r *Request) (map[string]any, error) {
	switch r.Op {
	case "ping":
		return map[string]any{"pong": true}, nil
	case "setup":
		return setup(r.Circuit, r.M)
	case "prove":
		return prove(r)
	case "verify":
		return verify(r)
	case "keygen":
		return keygen()
	case "sign":
		return sign(r)
	case "verify_sig":
		return verifySigOp(r)
	case "mimc":
		return mimcOp(r)
	}
	return nil, errors.New("unknown op " + r.Op)
}

func main() {
	logger.Disable() // gnark logs to stdout by default; stdout carries the protocol
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)
	for in.Scan() {
		var req Request
		var resp map[string]any
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			resp = map[string]any{"ok": false, "error": "bad request: " + err.Error()}
		} else if res, err := handle(&req); err != nil {
			resp = map[string]any{"ok": false, "error": err.Error()}
		} else {
			res["ok"] = true
			resp = res
		}
		enc.Encode(resp)
		out.Flush()
	}
}
