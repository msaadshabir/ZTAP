package main

import "ztap/cmd"

// Version is set at build time via -ldflags "-X main.Version=<value>".
var Version = "dev"

func main() {
	cmd.Version = Version
	cmd.Execute()
}
