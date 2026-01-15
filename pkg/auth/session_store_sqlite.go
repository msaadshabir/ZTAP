package auth

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteSessionStore struct {
	db *sql.DB
}

type SQLiteSessionStoreOptions struct {
	Path string
}

func NewSQLiteSessionStore(opts SQLiteSessionStoreOptions) (*SQLiteSessionStore, error) {
	path := filepath.Clean(opts.Path)
	if path == "." || path == "" {
		return nil, fmt.Errorf("invalid sqlite path")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("creating sessions db dir: %w", err)
	}
	if err := touchFile0600(path); err != nil {
		return nil, err
	}

	dsn := "file:" + path
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite sessions db: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &SQLiteSessionStore{db: db}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func touchFile0600(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("creating sessions db file: %w", err)
	}
	_ = f.Close()
	_ = os.Chmod(path, 0600)
	return nil
}

func (s *SQLiteSessionStore) init() error {
	var mode string
	_ = s.db.QueryRow("PRAGMA journal_mode=WAL;").Scan(&mode)
	_, _ = s.db.Exec("PRAGMA busy_timeout=5000;")

	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	username TEXT NOT NULL,
	role TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
`)
	if err != nil {
		return fmt.Errorf("initializing sessions schema: %w", err)
	}
	return nil
}

func (s *SQLiteSessionStore) Put(ctx context.Context, token string, sess *Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, username, role, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(token_hash) DO UPDATE SET
           username=excluded.username,
           role=excluded.role,
           created_at=excluded.created_at,
           expires_at=excluded.expires_at`,
		tokenHash(token),
		sess.Username,
		string(sess.Role),
		sess.CreatedAt.UnixNano(),
		sess.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("storing session: %w", err)
	}
	return nil
}

func (s *SQLiteSessionStore) Get(ctx context.Context, token string) (*Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT username, role, created_at, expires_at FROM sessions WHERE token_hash = ?`,
		tokenHash(token),
	)
	var username, role string
	var createdAtNanos, expiresAtNanos int64
	if err := row.Scan(&username, &role, &createdAtNanos, &expiresAtNanos); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("getting session: %w", err)
	}
	return &Session{
		Token:     token,
		Username:  username,
		Role:      Role(role),
		CreatedAt: time.Unix(0, createdAtNanos),
		ExpiresAt: time.Unix(0, expiresAtNanos),
	}, nil
}

func (s *SQLiteSessionStore) Delete(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash(token))
	if err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}

func (s *SQLiteSessionStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("deleting expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLiteSessionStore) DeleteByUsername(ctx context.Context, username string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE username = ?`, username)
	if err != nil {
		return 0, fmt.Errorf("deleting sessions by username: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLiteSessionStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}
