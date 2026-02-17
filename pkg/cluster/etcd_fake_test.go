package cluster

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type inMemoryEtcdWatch struct {
	key    string
	prefix bool
	ch     chan clientv3.WatchResponse
}

type inMemoryEtcdClient struct {
	mu        sync.Mutex
	store     map[string][]byte
	watchers  map[int]inMemoryEtcdWatch
	nextID    int
	nextLease int64
}

func newInMemoryEtcdClient() *inMemoryEtcdClient {
	return &inMemoryEtcdClient{
		store:    make(map[string][]byte),
		watchers: make(map[int]inMemoryEtcdWatch),
	}
}

func (c *inMemoryEtcdClient) Grant(ctx context.Context, ttl int64) (*clientv3.LeaseGrantResponse, error) {
	_ = ctx
	_ = ttl
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextLease++
	return &clientv3.LeaseGrantResponse{ID: clientv3.LeaseID(c.nextLease)}, nil
}

func (c *inMemoryEtcdClient) Put(ctx context.Context, key, val string, opts ...clientv3.OpOption) (*clientv3.PutResponse, error) {
	_ = ctx
	_ = opts
	c.mu.Lock()
	c.store[key] = []byte(val)
	c.notifyLocked(clientv3.EventTypePut, key, []byte(val))
	c.mu.Unlock()
	return &clientv3.PutResponse{}, nil
}

func (c *inMemoryEtcdClient) Delete(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.DeleteResponse, error) {
	_ = ctx
	_ = opts
	c.mu.Lock()
	_, existed := c.store[key]
	delete(c.store, key)
	if existed {
		c.notifyLocked(clientv3.EventTypeDelete, key, nil)
	}
	c.mu.Unlock()
	return &clientv3.DeleteResponse{}, nil
}

func (c *inMemoryEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	_ = ctx
	op := clientv3.OpGet(key, opts...)
	prefix := op.IsOptsWithPrefix()

	c.mu.Lock()
	defer c.mu.Unlock()

	keys := make([]string, 0)
	if prefix {
		for k := range c.store {
			if strings.HasPrefix(k, key) {
				keys = append(keys, k)
			}
		}
	} else {
		if _, ok := c.store[key]; ok {
			keys = append(keys, key)
		}
	}

	sortDescending := strings.Contains(key, "/revisions/")
	if sortDescending {
		for i := 0; i < len(keys)-1; i++ {
			for j := i + 1; j < len(keys); j++ {
				if keys[j] > keys[i] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
	} else {
		for i := 0; i < len(keys)-1; i++ {
			for j := i + 1; j < len(keys); j++ {
				if keys[j] < keys[i] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
	}

	kvs := make([]*mvccpb.KeyValue, 0, len(keys))
	for _, k := range keys {
		v := c.store[k]
		kvs = append(kvs, &mvccpb.KeyValue{Key: []byte(k), Value: append([]byte(nil), v...)})
	}

	return &clientv3.GetResponse{Kvs: kvs, Count: int64(len(kvs))}, nil
}

func (c *inMemoryEtcdClient) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	op := clientv3.OpGet(key, opts...)
	prefix := op.IsOptsWithPrefix()
	ch := make(chan clientv3.WatchResponse, 16)

	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.watchers[id] = inMemoryEtcdWatch{key: key, prefix: prefix, ch: ch}
	c.mu.Unlock()

	go func() {
		<-ctx.Done()
		c.mu.Lock()
		delete(c.watchers, id)
		c.mu.Unlock()
		close(ch)
	}()

	return ch
}

func (c *inMemoryEtcdClient) Txn(ctx context.Context) clientv3.Txn {
	_ = ctx
	return &inMemoryEtcdTxn{client: c}
}

func (c *inMemoryEtcdClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, w := range c.watchers {
		delete(c.watchers, id)
		close(w.ch)
	}
	return nil
}

func (c *inMemoryEtcdClient) notifyLocked(eventType mvccpb.Event_EventType, key string, val []byte) {
	event := &clientv3.Event{Type: eventType, Kv: &mvccpb.KeyValue{Key: []byte(key), Value: append([]byte(nil), val...)}}
	resp := clientv3.WatchResponse{Events: []*clientv3.Event{event}}
	for _, watcher := range c.watchers {
		if watcher.prefix {
			if !strings.HasPrefix(key, watcher.key) {
				continue
			}
		} else if key != watcher.key {
			continue
		}
		select {
		case watcher.ch <- resp:
		default:
		}
	}
}

type inMemoryEtcdTxn struct {
	client  *inMemoryEtcdClient
	thenOps []clientv3.Op
	elseOps []clientv3.Op
	useElse bool
}

func (t *inMemoryEtcdTxn) If(cs ...clientv3.Cmp) clientv3.Txn {
	_ = cs
	t.useElse = false
	return t
}

func (t *inMemoryEtcdTxn) Then(ops ...clientv3.Op) clientv3.Txn {
	t.thenOps = append(t.thenOps, ops...)
	return t
}

func (t *inMemoryEtcdTxn) Else(ops ...clientv3.Op) clientv3.Txn {
	t.elseOps = append(t.elseOps, ops...)
	return t
}

func (t *inMemoryEtcdTxn) Commit() (*clientv3.TxnResponse, error) {
	ops := t.thenOps
	if t.useElse {
		ops = t.elseOps
	}
	for _, op := range ops {
		key := string(op.KeyBytes())
		switch {
		case op.IsPut():
			if _, err := t.client.Put(context.Background(), key, string(op.ValueBytes())); err != nil {
				return nil, err
			}
		case op.IsDelete():
			if _, err := t.client.Delete(context.Background(), key); err != nil {
				return nil, err
			}
		}
	}
	return &clientv3.TxnResponse{}, nil
}

type fakeLeaderElection struct {
	leaderResp *clientv3.GetResponse
	err        error
}

func (f *fakeLeaderElection) Campaign(ctx context.Context, val string) error {
	_ = ctx
	_ = val
	return nil
}

func (f *fakeLeaderElection) Resign(ctx context.Context) error {
	_ = ctx
	return nil
}

func (f *fakeLeaderElection) Leader(ctx context.Context) (*clientv3.GetResponse, error) {
	_ = ctx
	return f.leaderResp, f.err
}

func TestEtcdElectionWithFakeClient_RegisterAndDeregisterNode(t *testing.T) {
	fake := newInMemoryEtcdClient()
	election, err := NewEtcdElectionWithClient(
		LeaderElectionConfig{NodeID: "node-a", NodeAddress: "127.0.0.1:9090"},
		&EtcdConfig{Endpoints: []string{"localhost:2379"}, KeyPrefix: "/ztap-test-fake"},
		fake,
	)
	if err != nil {
		t.Fatalf("NewEtcdElectionWithClient: %v", err)
	}

	node := &Node{ID: "node-b", Address: "127.0.0.1:9091", State: StateHealthy}
	if err := election.RegisterNode(node); err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}

	registeredKey := "/ztap-test-fake/nodes/node-b"
	getResp, err := fake.Get(context.Background(), registeredKey)
	if err != nil {
		t.Fatalf("fake Get: %v", err)
	}
	if len(getResp.Kvs) != 1 {
		t.Fatalf("expected registered node key to exist")
	}

	if err := election.DeregisterNode("node-b"); err != nil {
		t.Fatalf("DeregisterNode: %v", err)
	}

	getResp, err = fake.Get(context.Background(), registeredKey)
	if err != nil {
		t.Fatalf("fake Get after delete: %v", err)
	}
	if len(getResp.Kvs) != 0 {
		t.Fatalf("expected registered node key to be deleted")
	}
}

func TestEtcdElectionWithFakeClient_GetLeaderFromElection(t *testing.T) {
	fake := newInMemoryEtcdClient()
	election, err := NewEtcdElectionWithClient(
		LeaderElectionConfig{NodeID: "node-a", NodeAddress: "127.0.0.1:9090"},
		&EtcdConfig{Endpoints: []string{"localhost:2379"}, KeyPrefix: "/ztap-test-fake"},
		fake,
	)
	if err != nil {
		t.Fatalf("NewEtcdElectionWithClient: %v", err)
	}

	leader := Node{ID: "leader-1", Address: "127.0.0.1:9099", State: StateHealthy}
	leaderBytes, err := json.Marshal(leader)
	if err != nil {
		t.Fatalf("marshal leader: %v", err)
	}
	election.election = &fakeLeaderElection{
		leaderResp: &clientv3.GetResponse{Kvs: []*mvccpb.KeyValue{{Value: leaderBytes}}},
	}

	got := election.GetLeader()
	if got == nil {
		t.Fatalf("GetLeader returned nil")
	}
	if got.ID != "leader-1" {
		t.Fatalf("expected leader-1, got %s", got.ID)
	}
}

func TestEtcdPolicySyncWithFakeClient_Lifecycle(t *testing.T) {
	fake := newInMemoryEtcdClient()
	ps, err := NewEtcdPolicySyncWithClient(
		&EtcdConfig{Endpoints: []string{"localhost:2379"}, KeyPrefix: "/ztap-test-sync"},
		"node-a",
		fake,
	)
	if err != nil {
		t.Fatalf("NewEtcdPolicySyncWithClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	updateCh := ps.SubscribePolicies(ctx)

	policyYAML := []byte("apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: web\nspec:\n  podSelector:\n    matchLabels:\n      app: web\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n")

	rev, err := ps.UpsertPolicy(ctx, "default/web", policyYAML, "initial")
	if err != nil {
		t.Fatalf("UpsertPolicy: %v", err)
	}
	if rev.Version != 1 {
		t.Fatalf("expected version 1, got %d", rev.Version)
	}

	select {
	case update := <-updateCh:
		if update.Version != 1 {
			t.Fatalf("expected update version 1, got %d", update.Version)
		}
		if update.PolicyKeyString() != "default/web" {
			t.Fatalf("expected update key default/web, got %s", update.PolicyKeyString())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for policy update")
	}

	version, err := ps.GetPolicyVersion("default/web")
	if err != nil {
		t.Fatalf("GetPolicyVersion: %v", err)
	}
	if version != 1 {
		t.Fatalf("expected version 1, got %d", version)
	}

	revs, err := ps.ListPolicyRevisions("default/web", 0)
	if err != nil {
		t.Fatalf("ListPolicyRevisions: %v", err)
	}
	if len(revs) != 1 {
		t.Fatalf("expected 1 revision, got %d", len(revs))
	}

	del, err := ps.DeletePolicy(ctx, "default/web", "cleanup")
	if err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if !del.Deleted {
		t.Fatalf("expected deleted revision")
	}

	current, err := ps.GetPolicy("default/web")
	if err != nil {
		t.Fatalf("GetPolicy after delete: %v", err)
	}
	if current != nil {
		t.Fatalf("expected nil policy after delete")
	}
}
