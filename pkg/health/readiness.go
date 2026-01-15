package health

import (
	"context"
	"errors"
	"time"

	"ztap/pkg/audit"
	"ztap/pkg/auth"
)

type Result struct {
	Ready  bool              `json:"ready"`
	Checks map[string]string `json:"checks,omitempty"`
	Error  string            `json:"error,omitempty"`
}

type Checker struct {
	AuthEnabled bool
	Auth        *auth.AuthManager
	Audit       *audit.AuditLogger

	Timeout time.Duration
}

func (c *Checker) Check(ctx context.Context) Result {
	checks := map[string]string{}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}

	var failed error

	// Auth readiness: only required when auth is enabled.
	if c.AuthEnabled {
		if c.Auth == nil {
			failed = errors.New("auth manager is nil")
			checks["auth"] = failed.Error()
		} else {
			checkCtx, cancel := context.WithTimeout(ctx, timeout)
			err := c.Auth.Ready(checkCtx)
			cancel()
			if err != nil {
				failed = err
				checks["auth"] = err.Error()
			} else {
				checks["auth"] = "ok"
			}
		}
	} else {
		checks["auth"] = "skipped"
	}

	// Audit readiness: always required (audit is used by API/enforcer paths).
	if failed == nil {
		if c.Audit == nil {
			failed = errors.New("audit logger is nil")
			checks["audit"] = failed.Error()
		} else {
			checkCtx, cancel := context.WithTimeout(ctx, timeout)
			err := c.Audit.Ready(checkCtx)
			cancel()
			if err != nil {
				failed = err
				checks["audit"] = err.Error()
			} else {
				checks["audit"] = "ok"
			}
		}
	}

	res := Result{
		Ready:  failed == nil,
		Checks: checks,
	}
	if failed != nil {
		res.Error = failed.Error()
	}
	return res
}
