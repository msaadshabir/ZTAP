package auth

import (
	"context"
	"sync"
	"time"
)

type InMemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{sessions: make(map[string]*Session)}
}

func (s *InMemorySessionStore) Put(_ context.Context, token string, sess *Session) error {
	key := tokenHash(token)
	copy := *sess

	s.mu.Lock()
	s.sessions[key] = &copy
	s.mu.Unlock()
	return nil
}

func (s *InMemorySessionStore) Get(_ context.Context, token string) (*Session, error) {
	key := tokenHash(token)

	s.mu.RLock()
	sess, ok := s.sessions[key]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrSessionNotFound
	}
	copy := *sess
	return &copy, nil
}

func (s *InMemorySessionStore) Delete(_ context.Context, token string) error {
	key := tokenHash(token)

	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()
	return nil
}

func (s *InMemorySessionStore) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	deleted := 0

	s.mu.Lock()
	for k, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(s.sessions, k)
			deleted++
		}
	}
	s.mu.Unlock()
	return deleted, nil
}

func (s *InMemorySessionStore) DeleteByUsername(_ context.Context, username string) (int, error) {
	deleted := 0

	s.mu.Lock()
	for k, sess := range s.sessions {
		if sess.Username == username {
			delete(s.sessions, k)
			deleted++
		}
	}
	s.mu.Unlock()
	return deleted, nil
}

func (s *InMemorySessionStore) Close() error { return nil }
