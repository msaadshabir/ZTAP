//go:build windows

package cmd

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
