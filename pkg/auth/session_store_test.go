package auth

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSessionStoresContract(t *testing.T) {
	t.Parallel()

	mkStores := func(t *testing.T) map[string]SessionStore {
		t.Helper()

		stores := map[string]SessionStore{
			"memory": NewInMemorySessionStore(),
		}
		sqliteStore, err := NewSQLiteSessionStore(SQLiteSessionStoreOptions{Path: filepath.Join(t.TempDir(), "sessions.db")})
		if err != nil {
			t.Fatalf("NewSQLiteSessionStore: %v", err)
		}
		stores["sqlite"] = sqliteStore
		return stores
	}

	for name, store := range mkStores(t) {
		store := store
		t.Run(name, func(t *testing.T) {
			defer func() { _ = store.Close() }()

			ctx := context.Background()
			now := time.Now()

			sess := &Session{Token: "t", Username: "alice", Role: RoleAdmin, CreatedAt: now, ExpiresAt: now.Add(1 * time.Hour)}
			if err := store.Put(ctx, sess.Token, sess); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got, err := store.Get(ctx, sess.Token)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.Username != "alice" {
				t.Fatalf("unexpected username: %s", got.Username)
			}

			if err := store.Delete(ctx, sess.Token); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := store.Get(ctx, sess.Token); err == nil {
				t.Fatalf("expected error for missing session")
			}

			expired := &Session{Token: "t2", Username: "bob", Role: RoleViewer, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-1 * time.Hour)}
			if err := store.Put(ctx, expired.Token, expired); err != nil {
				t.Fatalf("Put expired: %v", err)
			}
			deleted, err := store.DeleteExpired(ctx, now)
			if err != nil {
				t.Fatalf("DeleteExpired: %v", err)
			}
			if deleted == 0 {
				t.Fatalf("expected at least one deleted expired session")
			}

			// Concurrency smoke test.
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					tok := "tok-" + string(rune('a'+i))
					_ = store.Put(ctx, tok, &Session{Token: tok, Username: "u", Role: RoleOperator, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
					_, _ = store.Get(ctx, tok)
					_ = store.Delete(ctx, tok)
				}(i)
			}
			wg.Wait()
		})
	}
}
