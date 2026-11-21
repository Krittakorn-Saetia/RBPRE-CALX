package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func rnd() *big.Int {
	b := make([]byte, 31)
	rand.Read(b)
	return new(big.Int).SetBytes(b)
}

func hx(v *big.Int) string { return fmt.Sprintf("%064x", v) }

func mustKey(t *testing.T) (string, string) {
	k, err := keygen()
	if err != nil {
		t.Fatal(err)
	}
	return k["sk"].(string), k["pk"].(string)
}

func mustSign(t *testing.T, sk string, msg *big.Int) string {
	s, err := sign(&Request{SK: sk, Msg: hx(msg)})
	if err != nil {
		t.Fatal(err)
	}
	return s["sig"].(string)
}

// inputs builds a satisfying statement and witness for m slots.
func inputs(t *testing.T, circuit string, m int) (PubIn, WitIn, string) {
	attr := make([]*big.Int, m)
	for i := range attr {
		attr[i] = rnd()
	}
	req := make([]*big.Int, m)
	for i := 0; i < m-1; i++ {
		req[i] = attr[i]
	}
	req[m-1] = big.NewInt(0) // empty slot
	purp, scope := rnd(), rnd()
	did, cid, pid, ng, cb := rnd(), rnd(), rnd(), rnd(), rnd()
	const tStart, tEnd, tG, tVC, epoch = 1000, 5000, 2000, 4000, 7
	ha := mimcOf(append(append([]*big.Int{}, req...), purp, scope, big.NewInt(tStart), big.NewInt(tEnd)))
	skCI, pkCI := mustKey(t)
	skD, pkD := mustKey(t)

	w := WitIn{TVC: tVC, Purp: hx(purp), Scope: hx(scope), TStart: tStart, TEnd: tEnd}
	for i := 0; i < m; i++ {
		w.Attr = append(w.Attr, hx(attr[i]))
		w.Req = append(w.Req, hx(req[i]))
	}
	p := PubIn{DID: hx(did), PID: hx(pid), Purpose: hx(purp), Scope: hx(scope), Epoch: epoch,
		HA: hx(ha), PkCI: pkCI}
	if circuit == "holder" {
		vcMsg := mimcOf(append(append([]*big.Int{}, attr...), did, cid, big.NewInt(tVC)))
		w.VC = mustSign(t, skCI, vcMsg)
		hctx := mimcOf([]*big.Int{did, cid, pid, purp, scope, big.NewInt(epoch), ha, big.NewInt(tG), ng, cb})
		w.SigD = mustSign(t, skD, hctx)
		p.Cid, p.TG, p.NG, p.CB, p.HCtx, p.PkD = hx(cid), tG, hx(ng), hx(cb), hx(hctx), pkD
	} else {
		vcMsg := mimcOf(append(append([]*big.Int{}, attr...), did, big.NewInt(tVC)))
		w.VC = mustSign(t, skCI, vcMsg)
		hctx := mimcOf([]*big.Int{did, pid, purp, scope, big.NewInt(epoch)})
		p.TNow, p.HCtx = tG, hx(hctx)
	}
	return p, w, skD
}

func TestCircuits(t *testing.T) {
	const m = 5
	for _, circuit := range []string{"original", "holder"} {
		st, err := setup(circuit, m)
		if err != nil {
			t.Fatal(circuit, err)
		}
		t.Logf("%s m=%d: %v constraints, setup %.0f ms", circuit, m, st["constraints"], st["setup_ms"])
		p, w, _ := inputs(t, circuit, m)

		res, err := prove(&Request{Circuit: circuit, M: m, Pub: p, Wit: w})
		if err != nil {
			t.Fatal(circuit, "honest prove:", err)
		}
		t.Logf("%s proof %v bytes, prove %.1f ms", circuit, res["proof_bytes"], res["prove_ms"])
		v, err := verify(&Request{Circuit: circuit, M: m, Pub: p, Proof: res["proof"].(string)})
		if err != nil || !v["valid"].(bool) {
			t.Fatal(circuit, "honest proof rejected:", err, v)
		}

		// a different public context must not verify
		p2 := p
		p2.Epoch++
		v, _ = verify(&Request{Circuit: circuit, M: m, Pub: p2, Proof: res["proof"].(string)})
		if v["valid"].(bool) {
			t.Fatal(circuit, "proof verified under another epoch")
		}

		// a credential that lacks a required attribute cannot produce a proof
		w2 := w
		w2.Attr = append([]string{}, w.Attr...)
		w2.Attr[0] = hx(rnd())
		if _, err := prove(&Request{Circuit: circuit, M: m, Pub: p, Wit: w2}); err == nil {
			t.Fatal(circuit, "proved with a missing attribute")
		}

		// an expired credential (t > t_VC) cannot produce a proof
		w3 := w
		w3.TVC = 1500
		if _, err := prove(&Request{Circuit: circuit, M: m, Pub: p, Wit: w3}); err == nil {
			t.Fatal(circuit, "proved with an expired credential")
		}
	}

	// holder binding: a stolen credential without sk_D cannot prove
	p, w, _ := inputs(t, "holder", m)
	skX, _ := mustKey(t)
	hctx, _ := fieldOf(p.HCtx)
	w.SigD = mustSign(t, skX, hctx)
	if _, err := prove(&Request{Circuit: "holder", M: m, Pub: p, Wit: w}); err == nil {
		t.Fatal("proved with a holder signature from another key")
	}
}

func TestSignatureAndMimc(t *testing.T) {
	sk, pk := mustKey(t)
	msg := rnd()
	sig := mustSign(t, sk, msg)
	v, _ := verifySigOp(&Request{PK: pk, Msg: hx(msg), Sig: sig})
	if !v["valid"].(bool) {
		t.Fatal("valid signature rejected")
	}
	v, _ = verifySigOp(&Request{PK: pk, Msg: hx(rnd()), Sig: sig})
	if v["valid"].(bool) {
		t.Fatal("signature verified on another message")
	}
	a, b := rnd(), rnd()
	if mimcOf([]*big.Int{a, b}).Cmp(mimcOf([]*big.Int{b, a})) == 0 {
		t.Fatal("mimc ignores order")
	}
}
