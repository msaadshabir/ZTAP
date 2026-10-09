//go:build !linux

package cli

import (
	"context"
	"errors"
)

func cleanupNativeEnforcement(context.Context, string, string) error {
	return errors.New("enforcement cleanup requires Linux")
}
