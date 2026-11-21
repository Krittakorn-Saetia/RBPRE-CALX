// Groth16 circuits for the authorization relation R_auth over BLS12-381.
//
// HolderCircuit is R_auth of the revised construction (Eq. 53-55):
//
//	x = (Req, tG, nG, h_ctx, h_A, cb_D, pk_CI, pk_D),  Req = (DID_D, cid_D, PID*, Purpose, Scope, e)
//	w = (Attr_D, VC_D, t_VC, A, sigma_D)
//	R_auth(x, w) = 1  iff
//	  Verify_pkCI(VC_D, H(Attr_D || DID_D || cid_D || t_VC)) = 1      credential authenticity (Eq. 18)
//	  Verify_pkD(sigma_D, h_ctx) = 1                                  holder possession (Eq. 52)
//	  H(A) = h_A                                                      committed policy
//	  A(Attr_D, Purpose, Scope, tG) = 1                               policy satisfaction
//	  tG <= t_VC                                                      credential validity
//	  h_ctx = H(Req || h_A || tG || nG || cb_D)                       request-context binding (Eq. 51)
//
// OriginalCircuit is the relation of the first submission (v1 Eq. 49-51),
// with the same committed policy h_A so that both circuits are compared under
// identical policy configurations:
//
//	x = (DID_D, PID*, Purpose, Scope, e, t_now, h_ctx, h_A, pk_CI),  w = (Attr_D, VC_D, t_VC, A)
//	Verify_pkCI(VC_D, H(Attr_D || DID_D || t_VC)) = 1, H(A) = h_A, A(Attr_D, Purpose, Scope, t_now) = 1,
//	t_now <= t_VC, h_ctx = H(DID_D || PID* || Purpose || Scope || e)
//
// Instantiation: H is MiMC over the BLS12-381 scalar field; signatures are
// EdDSA on Jubjub (the twisted Edwards curve whose base field is that scalar
// field) with MiMC. The policy A has m required-attribute slots (0 = empty
// slot), one permitted purpose, one permitted scope and a validity window
// [t_start, t_end]; the credential carries m attribute slots.
package main

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// TimeBits bounds every timestamp; a <= b is enforced as b - a in [0, 2^TimeBits).
const TimeBits = 64

// Policy is the bounded representation of the consent policy A (Eq. 25).
type Policy struct {
	Req    []frontend.Variable // required attributes, 0 = empty slot
	Purp   frontend.Variable   // permitted purpose
	Scope  frontend.Variable   // permitted scope
	TStart frontend.Variable
	TEnd   frontend.Variable
}

type HolderCircuit struct {
	DID     frontend.Variable `gnark:",public"`
	Cid     frontend.Variable `gnark:",public"`
	PID     frontend.Variable `gnark:",public"`
	Purpose frontend.Variable `gnark:",public"`
	Scope   frontend.Variable `gnark:",public"`
	Epoch   frontend.Variable `gnark:",public"`
	TG      frontend.Variable `gnark:",public"`
	NG      frontend.Variable `gnark:",public"`
	HCtx    frontend.Variable `gnark:",public"`
	HA      frontend.Variable `gnark:",public"`
	CB      frontend.Variable `gnark:",public"`
	PkCI    eddsa.PublicKey   `gnark:",public"`
	PkD     eddsa.PublicKey   `gnark:",public"`

	Attr []frontend.Variable
	TVC  frontend.Variable
	VC   eddsa.Signature
	A    Policy
	SigD eddsa.Signature
}

type OriginalCircuit struct {
	DID     frontend.Variable `gnark:",public"`
	PID     frontend.Variable `gnark:",public"`
	Purpose frontend.Variable `gnark:",public"`
	Scope   frontend.Variable `gnark:",public"`
	Epoch   frontend.Variable `gnark:",public"`
	TNow    frontend.Variable `gnark:",public"`
	HCtx    frontend.Variable `gnark:",public"`
	HA      frontend.Variable `gnark:",public"`
	PkCI    eddsa.PublicKey   `gnark:",public"`

	Attr []frontend.Variable
	TVC  frontend.Variable
	VC   eddsa.Signature
	A    Policy
}

func newPolicy(m int) Policy { return Policy{Req: make([]frontend.Variable, m)} }

// NewHolderCircuit allocates a circuit with m policy and credential slots.
func NewHolderCircuit(m int) *HolderCircuit {
	return &HolderCircuit{Attr: make([]frontend.Variable, m), A: newPolicy(m)}
}

func NewOriginalCircuit(m int) *OriginalCircuit {
	return &OriginalCircuit{Attr: make([]frontend.Variable, m), A: newPolicy(m)}
}

func hashOf(api frontend.API, vals ...frontend.Variable) (frontend.Variable, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, err
	}
	h.Write(vals...)
	return h.Sum(), nil
}

func verifySig(api frontend.API, curve twistededwards.Curve, sig eddsa.Signature,
	msg frontend.Variable, pk eddsa.PublicKey) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	return eddsa.Verify(curve, sig, msg, pk, &h)
}

func assertLeq(api frontend.API, a, b frontend.Variable) {
	api.ToBinary(api.Sub(b, a), TimeBits)
}

// policyAndCredential enforces H(A) = h_A, A(Attr, Purpose, Scope, t) = 1 and t <= t_VC.
func policyAndCredential(api frontend.API, a Policy, attr []frontend.Variable,
	hA, purpose, scope, t, tVC frontend.Variable) error {
	pol := append(append([]frontend.Variable{}, a.Req...), a.Purp, a.Scope, a.TStart, a.TEnd)
	ha, err := hashOf(api, pol...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(ha, hA)
	for _, r := range a.Req { // r = 0 or r in Attr
		prod := r
		for _, x := range attr {
			prod = api.Mul(prod, api.Sub(r, x))
		}
		api.AssertIsEqual(prod, 0)
	}
	api.AssertIsEqual(purpose, a.Purp)
	api.AssertIsEqual(scope, a.Scope)
	assertLeq(api, a.TStart, t)
	assertLeq(api, t, a.TEnd)
	assertLeq(api, t, tVC)
	return nil
}

func (c *HolderCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BLS12_381)
	if err != nil {
		return err
	}
	vcMsg, err := hashOf(api, append(append([]frontend.Variable{}, c.Attr...), c.DID, c.Cid, c.TVC)...)
	if err != nil {
		return err
	}
	if err := verifySig(api, curve, c.VC, vcMsg, c.PkCI); err != nil {
		return err
	}
	if err := verifySig(api, curve, c.SigD, c.HCtx, c.PkD); err != nil {
		return err
	}
	if err := policyAndCredential(api, c.A, c.Attr, c.HA, c.Purpose, c.Scope, c.TG, c.TVC); err != nil {
		return err
	}
	hctx, err := hashOf(api, c.DID, c.Cid, c.PID, c.Purpose, c.Scope, c.Epoch, c.HA, c.TG, c.NG, c.CB)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hctx, c.HCtx)
	return nil
}

func (c *OriginalCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BLS12_381)
	if err != nil {
		return err
	}
	vcMsg, err := hashOf(api, append(append([]frontend.Variable{}, c.Attr...), c.DID, c.TVC)...)
	if err != nil {
		return err
	}
	if err := verifySig(api, curve, c.VC, vcMsg, c.PkCI); err != nil {
		return err
	}
	if err := policyAndCredential(api, c.A, c.Attr, c.HA, c.Purpose, c.Scope, c.TNow, c.TVC); err != nil {
		return err
	}
	hctx, err := hashOf(api, c.DID, c.PID, c.Purpose, c.Scope, c.Epoch)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hctx, c.HCtx)
	return nil
}
