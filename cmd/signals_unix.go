//go:build !windows

package cmd

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyStopSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}

func stopStopSignals(ch chan<- os.Signal) {
	signal.Stop(ch)
}
