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
//
// State synchronization: every transaction that writes state emits one
// chaincode event "state" whose payload is {kind: {id: value}}, in the same
// shape as GetState returns. Gateways and proxies keep a synchronized mirror
// of the finalized state by following these events from block 0.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type RBPREContract struct {
	contractapi.Contract
}

// RBContext is the per-invocation transaction context; it collects the
// state changes of one transaction for the "state" event.
type RBContext struct {
	contractapi.TransactionContext
	changes map[string]map[string]json.RawMessage
}

func (c *RBContext) record(kind, id string, v []byte) {
	if c.changes == nil {
		c.changes = map[string]map[string]json.RawMessage{}
	}
	if c.changes[kind] == nil {
		c.changes[kind] = map[string]json.RawMessage{}
	}
	c.changes[kind][id] = rawValue(v)
}

// emitChanges is the contract's AfterTransaction hook.
func emitChanges(ctx contractapi.TransactionContextInterface) error {
	rc, ok := ctx.(*RBContext)
	if !ok || len(rc.changes) == 0 {
		return nil
	}
	b, err := json.Marshal(rc.changes)
	if err != nil {
		return err
	}
	return ctx.GetStub().SetEvent("state", b)
}

var prefixes = map[string]string{"did": "did|", "cred": "cred|", "cons": "cons|", "del": "del|",
	"epoch": "epoch|", "rec": "rec|", "flag": "flag|", "root": "root|", "auth": "auth|", "share": "share|"}

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

// rawValue renders a stored value as JSON: objects as they are, anything
// else as a JSON string.
func rawValue(b []byte) json.RawMessage {
	if len(b) > 0 && (b[0] == '{' || b[0] == '[') && json.Valid(b) {
		return json.RawMessage(b)
	}
	q, _ := json.Marshal(string(b))
	return json.RawMessage(q)
}

// put writes kind|id and records the change for the state event.
func put(ctx contractapi.TransactionContextInterface, kind, id string, v any) error {
	var b []byte
	switch x := v.(type) {
	case []byte:
		b = x
	case string:
		b = []byte(x)
	default:
		var err error
		if b, err = json.Marshal(v); err != nil {
			return err
		}
	}
	if err := ctx.GetStub().PutState(prefixes[kind]+id, b); err != nil {
		return err
	}
	if rc, ok := ctx.(*RBContext); ok {
		rc.record(kind, id, b)
	}
	return nil
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
		if err := put(ctx, "did", r.DID, r); err != nil {
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
		if err := put(ctx, "cred", r.ID, Lifecycle{Owner: r.Owner, T: r.T, Status: "active"}); err != nil {
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
	return put(ctx, "cons", comC, Lifecycle{E: e, T: tC, Status: "active"})
}

// RegisterDelegation stores DRec_ctx = (H(DelTok), e, t_del, active) (Eq. 34).
func (c *RBPREContract) RegisterDelegation(ctx contractapi.TransactionContextInterface, hDel string, e int, tDel int64) error {
	return put(ctx, "del", hDel, Lifecycle{E: e, T: tDel, Status: "active"})
}

// SetStatus changes the lifecycle status of a credential, consent,
// delegation or linkage record: kind in {cred, cons, del, flag}.
func (c *RBPREContract) SetStatus(ctx contractapi.TransactionContextInterface, kind, id, status string) error {
	if !statusOK[status] {
		return fmt.Errorf("bad status %q", status)
	}
	if kind != "cred" && kind != "cons" && kind != "del" && kind != "flag" {
		return fmt.Errorf("bad kind %q", kind)
	}
	b, err := ctx.GetStub().GetState(prefixes[kind] + id)
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
	return put(ctx, kind, id, l)
}

// ---------------------------------------------------------------- revocation

// AdvanceEpoch finalizes ComRev_{e+1} = H(RevState_{e+1}) for an epoch handle
// and returns the new epoch (Eq. 96-97).
func (c *RBPREContract) AdvanceEpoch(ctx contractapi.TransactionContextInterface, handle, comRev string) (int, error) {
	var ep EpochRec
	b, err := ctx.GetStub().GetState(prefixes["epoch"] + handle)
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
	return ep.E, put(ctx, "epoch", handle, ep)
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
		if err := put(ctx, "rec", r.ID, r.V); err != nil {
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
		if err := put(ctx, "flag", r.ID, Lifecycle{E: r.E, Status: "active"}); err != nil {
			return 0, err
		}
	}
	return len(recs), nil
}

// SetRoot anchors Root_PID* = H_Merkle(M_PID*) (Eq. 78).
func (c *RBPREContract) SetRoot(ctx contractapi.TransactionContextInterface, pid, root string) error {
	return put(ctx, "root", pid, root)
}

// AnchorAuth anchors ComAuth (Eq. 65) with the transaction time.
func (c *RBPREContract) AnchorAuth(ctx contractapi.TransactionContextInterface, com string) error {
	return put(ctx, "auth", com, fmt.Sprint(txTime(ctx)))
}

// AnchorShares anchors [ComShare_i] (Eq. 90), submitted asynchronously.
func (c *RBPREContract) AnchorShares(ctx contractapi.TransactionContextInterface, comsJSON string) (int, error) {
	var coms []string
	if err := json.Unmarshal([]byte(comsJSON), &coms); err != nil {
		return 0, err
	}
	t := fmt.Sprint(txTime(ctx))
	for _, com := range coms {
		if err := put(ctx, "share", com, t); err != nil {
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
			m[id] = rawValue(b)
		}
		out[kind] = m
	}
	b, err := json.Marshal(out)
	return string(b), err
}
