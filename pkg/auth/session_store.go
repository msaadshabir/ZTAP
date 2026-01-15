package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type SessionStore interface {
	Put(ctx context.Context, token string, sess *Session) error
	Get(ctx context.Context, token string) (*Session, error)
	Delete(ctx context.Context, token string) error
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
	Close() error
}

type SessionStoreUserRevoker interface {
	DeleteByUsername(ctx context.Context, username string) (int, error)
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
