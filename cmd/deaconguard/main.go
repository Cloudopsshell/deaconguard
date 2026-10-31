package main

import (
	"os"

	"deaconguard/internal/cli"
	"deaconguard/internal/memlimit"
)

func main() {
	memlimit.Apply()
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
