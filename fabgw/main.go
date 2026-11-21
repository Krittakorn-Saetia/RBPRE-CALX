// fabgw: Fabric Gateway client and synchronized state mirror for RBPRE-CALX.
//
// One process holds a persistent gRPC connection to the peer's Gateway
// service (Fabric 2.4+), so queries and submissions do not pay a process
// start per call as the peer CLI does. It also follows the chaincode's
// "state" events from block 0 and keeps a mirror of the finalized state:
// the "latest synchronized finalized state" that the gateway, KMS and proxy
// check against (Phase 4 Step 2, Phase 5 Steps 1-2).
//
// Protocol: one JSON request per line on stdin, one JSON response per line
// on stdout, matched by "id"; requests are served concurrently.
//
//	ping
//	evaluate    {fn, args}  -> result                      (query on the endorsing peer)
//	submit      {fn, args}  -> result, tx, block, commit_ms, sync_ms
//	            (endorse, order, wait for commit, then wait until the mirror applied the tx)
//	mirror_get  {req: {kind: [ids]}} -> state {kind: {id: value}}, block
//	barrier     submit a marker transaction and wait until the mirror applied it
//	status      -> block, events, entries
//
// Configuration (environment): FABGW_TN (test-network directory), FABGW_CHANNEL
// (default rbpre), FABGW_CC (default rbpre), FABGW_PEER (localhost:7051).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Request struct {
	ID   int64               `json:"id"`
	Op   string              `json:"op"`
	Fn   string              `json:"fn"`
	Args []string            `json:"args"`
	Req  map[string][]string `json:"req"`
}

// ------------------------------------------------------------------ mirror

type Mirror struct {
	mu      sync.Mutex
	cond    *sync.Cond
	state   map[string]map[string]json.RawMessage
	applied map[string]bool
	block   uint64
	events  int64
	entries int64
}

func newMirror() *Mirror {
	m := &Mirror{state: map[string]map[string]json.RawMessage{}, applied: map[string]bool{}}
	m.cond = sync.NewCond(&m.mu)
	return m
}

func (m *Mirror) apply(ev *client.ChaincodeEvent) {
	var ch map[string]map[string]json.RawMessage
	if ev.EventName == "state" {
		if err := json.Unmarshal(ev.Payload, &ch); err != nil {
			fmt.Fprintln(os.Stderr, "bad event payload:", err)
		}
	}
	m.mu.Lock()
	for kind, kv := range ch {
		if m.state[kind] == nil {
			m.state[kind] = map[string]json.RawMessage{}
		}
		for id, v := range kv {
			if _, ok := m.state[kind][id]; !ok {
				m.entries++
			}
			m.state[kind][id] = v
		}
	}
	m.applied[ev.TransactionID] = true
	m.block = ev.BlockNumber
	m.events++
	m.cond.Broadcast()
	m.mu.Unlock()
}

func (m *Mirror) waitTx(tx string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	timer := time.AfterFunc(timeout, func() { m.mu.Lock(); m.cond.Broadcast(); m.mu.Unlock() })
	defer timer.Stop()
	m.mu.Lock()
	defer m.mu.Unlock()
	for !m.applied[tx] {
		if time.Now().After(deadline) {
			return fmt.Errorf("mirror did not apply %s within %v", tx, timeout)
		}
		m.cond.Wait()
	}
	return nil
}

func (m *Mirror) get(req map[string][]string) (map[string]map[string]json.RawMessage, uint64) {
	out := map[string]map[string]json.RawMessage{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for kind, ids := range req {
		o := map[string]json.RawMessage{}
		for _, id := range ids {
			if v, ok := m.state[kind][id]; ok {
				o[id] = v
			}
		}
		out[kind] = o
	}
	return out, m.block
}

// follow streams chaincode events from block 0 and re-subscribes from the
// checkpoint after any stream error.
func follow(network *client.Network, cc string, m *Mirror) {
	cp := new(client.InMemoryCheckpointer)
	for {
		ctx, cancel := context.WithCancel(context.Background())
		events, err := network.ChaincodeEvents(ctx, cc, client.WithStartBlock(0), client.WithCheckpoint(cp))
		if err != nil {
			cancel()
			fmt.Fprintln(os.Stderr, "event subscription:", err)
			time.Sleep(time.Second)
			continue
		}
		for ev := range events {
			m.apply(ev)
			cp.CheckpointChaincodeEvent(ev)
		}
		cancel()
		time.Sleep(200 * time.Millisecond)
	}
}

// ------------------------------------------------------------------ gateway

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func connect() (*client.Gateway, error) {
	tn := env("FABGW_TN", filepath.Join(os.Getenv("HOME"), "flex-diam/fabric-samples/test-network"))
	org := filepath.Join(tn, "organizations/peerOrganizations/org1.example.com")
	certPEM, err := os.ReadFile(filepath.Join(org, "users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem"))
	if err != nil {
		return nil, err
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, err
	}
	id, err := identity.NewX509Identity("Org1MSP", cert)
	if err != nil {
		return nil, err
	}
	keys, _ := filepath.Glob(filepath.Join(org, "users/Admin@org1.example.com/msp/keystore/*"))
	if len(keys) == 0 {
		return nil, errors.New("no admin private key found")
	}
	keyPEM, err := os.ReadFile(keys[0])
	if err != nil {
		return nil, err
	}
	pk, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	sign, err := identity.NewPrivateKeySign(pk)
	if err != nil {
		return nil, err
	}
	tlsPEM, err := os.ReadFile(filepath.Join(org, "peers/peer0.org1.example.com/tls/ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(tlsPEM)
	conn, err := grpc.NewClient(env("FABGW_PEER", "localhost:7051"),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, "peer0.org1.example.com")))
	if err != nil {
		return nil, err
	}
	return client.Connect(id, client.WithSign(sign), client.WithClientConnection(conn),
		client.WithEvaluateTimeout(30*time.Second), client.WithEndorseTimeout(60*time.Second),
		client.WithSubmitTimeout(60*time.Second), client.WithCommitStatusTimeout(120*time.Second))
}

func ms(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }

type server struct {
	contract *client.Contract
	mirror   *Mirror
}

func (s *server) submit(fn string, args []string) (map[string]any, error) {
	t0 := time.Now()
	res, commit, err := s.contract.SubmitAsync(fn, client.WithArguments(args...))
	if err != nil {
		return nil, err
	}
	status, err := commit.Status()
	if err != nil {
		return nil, err
	}
	if !status.Successful {
		return nil, fmt.Errorf("transaction %s invalid: %v", status.TransactionID, status.Code)
	}
	t1 := time.Now()
	if err := s.mirror.waitTx(status.TransactionID, 60*time.Second); err != nil {
		return nil, err
	}
	t2 := time.Now()
	return map[string]any{"result": string(res), "tx": status.TransactionID, "block": status.BlockNumber,
		"commit_ms": ms(t1.Sub(t0)), "sync_ms": ms(t2.Sub(t1)), "ms": ms(t2.Sub(t0))}, nil
}

func (s *server) handle(r *Request) (map[string]any, error) {
	switch r.Op {
	case "ping":
		return map[string]any{"pong": true}, nil
	case "evaluate":
		t0 := time.Now()
		res, err := s.contract.EvaluateTransaction(r.Fn, r.Args...)
		if err != nil {
			return nil, err
		}
		return map[string]any{"result": string(res), "ms": ms(time.Since(t0))}, nil
	case "submit":
		return s.submit(r.Fn, r.Args)
	case "mirror_get":
		t0 := time.Now()
		st, block := s.mirror.get(r.Req)
		return map[string]any{"state": st, "block": block, "ms": ms(time.Since(t0))}, nil
	case "barrier":
		b := make([]byte, 16)
		rand.Read(b)
		marker, _ := json.Marshal([]string{"barrier-" + hex.EncodeToString(b)})
		return s.submit("AnchorShares", []string{string(marker)})
	case "status":
		s.mirror.mu.Lock()
		defer s.mirror.mu.Unlock()
		return map[string]any{"block": s.mirror.block, "events": s.mirror.events, "entries": s.mirror.entries}, nil
	}
	return nil, errors.New("unknown op " + r.Op)
}

func main() {
	gw, err := connect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer gw.Close()
	network := gw.GetNetwork(env("FABGW_CHANNEL", "rbpre"))
	cc := env("FABGW_CC", "rbpre")
	s := &server{contract: network.GetContract(cc), mirror: newMirror()}
	go follow(network, cc, s.mirror)

	var outMu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	reply := func(v map[string]any) {
		outMu.Lock()
		enc.Encode(v)
		outMu.Unlock()
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 256<<20)
	var wg sync.WaitGroup
	for in.Scan() {
		var r Request
		if err := json.Unmarshal(in.Bytes(), &r); err != nil {
			reply(map[string]any{"id": -1, "ok": false, "error": "bad request: " + err.Error()})
			continue
		}
		wg.Add(1)
		go func(r Request) {
			defer wg.Done()
			res, err := s.handle(&r)
			if err != nil {
				reply(map[string]any{"id": r.ID, "ok": false, "error": err.Error()})
				return
			}
			res["id"], res["ok"] = r.ID, true
			reply(res)
		}(r)
	}
	wg.Wait()
}
