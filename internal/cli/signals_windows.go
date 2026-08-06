//go:build windows

package cli

import (
	"os"
	"os/signal"
)

func notifyStopSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

func stopStopSignals(ch chan<- os.Signal) {
	signal.Stop(ch)
}
