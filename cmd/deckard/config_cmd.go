package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/chainseer-xyz/deckard/internal/config"
)

func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(stderr, "usage: deckard config validate [--config path]")
		return 2
	}
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", os.Getenv("DECKARD_CONFIG"), "YAML config file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if _, err := config.Load(*path, os.Environ()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "config OK")
	return 0
}
