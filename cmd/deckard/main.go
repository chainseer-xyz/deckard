// Command deckard is a continuous external attack-surface monitor.
package main

import (
	"fmt"
	"io"
	"os"
)

// Set at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `deckard - continuous external attack-surface monitor

Usage:
  deckard <command> [flags]

Commands:
  serve             run the API, scheduler and workers
  migrate           apply database migrations and exit
  config validate   load and validate the configuration
  sync              run one inventory sync and exit
  scan [--no-update] run one scan pass and exit (refreshes nuclei templates and reference data first; --no-update skips)
  findings          print current findings (--min-severity, --status, --format table|json)
  version           print version information

Common flags:
  --config <path>   YAML config file (env: DECKARD_CONFIG)
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "deckard %s (%s)\n", version, commit)
		return 0
	case "help", "--help", "-h":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "migrate":
		return runMigrate(args[1:], stdout, stderr)
	case "sync":
		return runSync(args[1:], stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "findings":
		return runFindings(args[1:], stdout, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "deckard: unknown command %q\n\n%s", args[0], usage)
	return 2
}
