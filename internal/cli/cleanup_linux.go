//go:build linux

package cli

import (
	"context"
	"errors"

	"github.com/saadshabir/ZTAP/internal/enforcer"
)

func cleanupNativeEnforcement(ctx context.Context, bpffsRoot, runDir string) (resultErr error) {
	if ctx == nil {
		return errors.New("cleanup context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	unlock, err := acquireNativeAgentLock(runDir)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	return enforcer.RemoveEnforcement(ctx, bpffsRoot)
}
