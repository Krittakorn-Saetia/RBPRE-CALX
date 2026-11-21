// Package main: RBPRE-CALX chaincode (Hyperledger Fabric 2.5, contract API).
//
// On-chain state S (Phase 1 Step 6). Only compact commitments, lifecycle
// states and linkage identifiers are stored; ciphertexts, credential
// attributes, metadata openings and consent openings stay off-chain.
//
//	did|<DID>        public key and domain of a registered DID           (Phase 1 Step 2)
//	cred|<cid>       CRec_D = (DID_D, cid_D, t_VC, status)                (Eq. 19)
//	cons|<ComC>      CRec_C = (ComC, e, t_C, status)  (the CMC)           (Eq. 29)
//	del|<H(DelTok)>  DRec_ctx = (H(DelTok_ctx), e, t_del, status)         (Eq. 34)
//	epoch|<handle>   current authorization epoch and ComRev_e            (Eq. 96-97)
//	rec|<RID*>       record commitment ComR                              (Eq. 48)
//	flag|<FlagID>    linkage state (FlagID, e, status)                   (Eq. 76-77)
//	root|<PID*>      patient-specific Merkle root Root_PID*              (Eq. 78)
//	auth|<ComAuth>   authorization commitment                            (Eq. 65)
//	share|<ComShare> sharing commitment                                  (Eq. 90)
//
// Lifecycle states take values in {active, revoked, superseded}. All batch
// arguments are JSON arrays so that one transaction can carry many entries.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type RBPREContract struct {
	contractapi.Contract
}

const (
	pDID   = "did|"
	pCred  = "cred|"
	pCons  = "cons|"
	pDel   = "del|"
	pEpoch = "epoch|"
	pRec   = "rec|"
	pFlag  = "flag|"
	pRoot  = "root|"
	pAuth  = "auth|"
	pShare = "share|"
)

type DIDRec struct {
	DID    string `json:"did"`
	PK     string `json:"pk"`
	Domain string `json:"domain"`
}

// Lifecycle is the shared shape of credential, consent, delegation and
// linkage records: an epoch (consent, delegation, linkage), an expiry time
// (t_VC, t_C, t_del) and a status.
type Lifecycle struct {
	Owner  string `json:"owner,omitempty"` // DID_D for credentials
	E      int    `json:"e"`
	T      int64  `json:"t"`
	Status string `json:"status"`
}

type EpochRec struct {
	E      int    `json:"e"`
	ComRev string `json:"com_rev"`
}

var statusOK = map[string]bool{"active": true, "revoked": true, "superseded": true}

func putJSON(ctx contractapi.TransactionContextInterface, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, b)
}

func txTime(ctx contractapi.TransactionContextInterface) int64 {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0
	}
	return ts.Seconds
}

// ------------------------------------------------------------------ identity

// RegisterDIDs registers [{did, pk, domain}] (Phase 1 Step 2).
func (c *RBPREContract) RegisterDIDs(ctx contractapi.TransactionContextInterface, recsJSON string) (int, error) {
	var recs []DIDRec
	if err := json.Unmarshal([]byte(recsJSON), &recs); err != nil {
		return 0, err
	}
	for _, r := range recs {
		if r.DID == "" || r.PK == "" {
			return 0, fmt.Errorf("did and pk are required")
		}
		if err := putJSON(ctx, pDID+r.DID, r); err != nil {
			return 0, err
		}
	}
	return len(recs), nil
}

// RegisterCredentials registers [{owner, id (cid), t (t_VC)}] as active (Eq. 19).
func (c *RBPREContract) RegisterCredentials(ctx contractapi.TransactionContextInterface, recsJSON string) (int, error) {
	var recs []struct {
		ID    string `json:"id"`
		Owner string `json:"owner"`
		T     int64  `json:"t"`
	}
	if err := json.Unmarshal([]byte(recsJSON), &recs); err != nil {
		return 0, err
	}
	for _, r := range recs {
		if err := putJSON(ctx, pCred+r.ID, Lifecycle{Owner: r.Owner, T: r.T, Status: "active"}); err != nil {
			return 0, err
		}
	}
	return len(recs), nil
}

// ------------------------------------------------------- consent, delegation

// RegisterConsent stores CRec_C = (ComC, e, t_C, active) (Eq. 29). If prev is
// non-empty, the previous consent state is marked superseded (policy update).
func (c *RBPREContract) RegisterConsent(ctx contractapi.TransactionContextInterface, comC string, e int, tC int64, prev string) error {
	if prev != "" {
		if err := c.SetStatus(ctx, "cons", prev, "superseded"); err != nil {
			return err
		}
	}
	return putJSON(ctx, pCons+comC, Lifecycle{E: e, T: tC, Status: "active"})
}

// RegisterDelegation stores DRec_ctx = (H(DelTok), e, t_del, active) (Eq. 34).
func (c *RBPREContract) RegisterDelegation(ctx contractapi.TransactionContextInterface, hDel string, e int, tDel int64) error {
	return putJSON(ctx, pDel+hDel, Lifecycle{E: e, T: tDel, Status: "active"})
}

// SetStatus changes the lifecycle status of a credential, consent,
// delegation or linkage record: kind in {cred, cons, del, flag}.
func (c *RBPREContract) SetStatus(ctx contractapi.TransactionContextInterface, kind, id, status string) error {
	if !statusOK[status] {
		return fmt.Errorf("bad status %q", status)
	}
	prefix := map[string]string{"cred": pCred, "cons": pCons, "del": pDel, "flag": pFlag}[kind]
	if prefix == "" {
		return fmt.Errorf("bad kind %q", kind)
	}
	b, err := ctx.GetStub().GetState(prefix + id)
	if err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("%s %s not found", kind, id)
	}
	var l Lifecycle
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	l.Status = status
	return putJSON(ctx, prefix+id, l)
}

// ---------------------------------------------------------------- revocation

// AdvanceEpoch finalizes ComRev_{e+1} = H(RevState_{e+1}) for an epoch handle
// and returns the new epoch (Eq. 96-97).
func (c *RBPREContract) AdvanceEpoch(ctx contractapi.TransactionContextInterface, handle, comRev string) (int, error) {
	var ep EpochRec
	b, err := ctx.GetStub().GetState(pEpoch + handle)
	if err != nil {
		return 0, err
	}
	if b != nil {
		if err := json.Unmarshal(b, &ep); err != nil {
			return 0, err
		}
	}
	ep.E++
	ep.ComRev = comRev
	return ep.E, putJSON(ctx, pEpoch+handle, ep)
}

// ------------------------------------------------------- records and linkage

// AnchorRecords stores [{id: RID*, v: ComR}] (Eq. 48).
func (c *RBPREContract) AnchorRecords(ctx contractapi.TransactionContextInterface, recsJSON string) (int, error) {
	var recs []struct {
		ID string `json:"id"`
		V  string `json:"v"`
	}
	if err := json.Unmarshal([]byte(recsJSON), &recs); err != nil {
		return 0, err
	}
	for _, r := range recs {
		if err := ctx.GetStub().PutState(pRec+r.ID, []byte(r.V)); err != nil {
			return 0, err
		}
	}
	return len(recs), nil
}

// AnchorFlags activates [{id: FlagID, e}] (Eq. 76-77).
func (c *RBPREContract) AnchorFlags(ctx contractapi.TransactionContextInterface, recsJSON string) (int, error) {
	var recs []struct {
		ID string `json:"id"`
		E  int    `json:"e"`
	}
	if err := json.Unmarshal([]byte(recsJSON), &recs); err != nil {
		return 0, err
	}
	for _, r := range recs {
		if err := putJSON(ctx, pFlag+r.ID, Lifecycle{E: r.E, Status: "active"}); err != nil {
			return 0, err
		}
	}
	return len(recs), nil
}

// SetRoot anchors Root_PID* = H_Merkle(M_PID*) (Eq. 78).
func (c *RBPREContract) SetRoot(ctx contractapi.TransactionContextInterface, pid, root string) error {
	return ctx.GetStub().PutState(pRoot+pid, []byte(root))
}

// AnchorAuth anchors ComAuth (Eq. 65) with the transaction time.
func (c *RBPREContract) AnchorAuth(ctx contractapi.TransactionContextInterface, com string) error {
	return ctx.GetStub().PutState(pAuth+com, []byte(fmt.Sprint(txTime(ctx))))
}

// AnchorShares anchors [ComShare_i] (Eq. 90), submitted asynchronously.
func (c *RBPREContract) AnchorShares(ctx contractapi.TransactionContextInterface, comsJSON string) (int, error) {
	var coms []string
	if err := json.Unmarshal([]byte(comsJSON), &coms); err != nil {
		return 0, err
	}
	t := []byte(fmt.Sprint(txTime(ctx)))
	for _, com := range coms {
		if err := ctx.GetStub().PutState(pShare+com, t); err != nil {
			return 0, err
		}
	}
	return len(coms), nil
}

// --------------------------------------------------------------------- reads

// GetState resolves many state entries in one query. The request is
// {"did": [...], "cred": [...], "cons": [...], "del": [...], "epoch": [...],
// "rec": [...], "flag": [...], "root": [...]}; the response maps each kind to
// {id: value} and omits absent entries.
func (c *RBPREContract) GetState(ctx contractapi.TransactionContextInterface, reqJSON string) (string, error) {
	var req map[string][]string
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return "", err
	}
	prefixes := map[string]string{"did": pDID, "cred": pCred, "cons": pCons, "del": pDel,
		"epoch": pEpoch, "rec": pRec, "flag": pFlag, "root": pRoot, "auth": pAuth, "share": pShare}
	out := map[string]map[string]json.RawMessage{}
	for kind, ids := range req {
		prefix, ok := prefixes[kind]
		if !ok {
			return "", fmt.Errorf("bad kind %q", kind)
		}
		m := map[string]json.RawMessage{}
		for _, id := range ids {
			b, err := ctx.GetStub().GetState(prefix + id)
			if err != nil {
				return "", err
			}
			if b == nil {
				continue
			}
			if json.Valid(b) && (b[0] == '{' || b[0] == '[') {
				m[id] = json.RawMessage(b)
			} else {
				q, _ := json.Marshal(string(b))
				m[id] = json.RawMessage(q)
			}
		}
		out[kind] = m
	}
	b, err := json.Marshal(out)
	return string(b), err
}
