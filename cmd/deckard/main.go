// Command deckard is a continuous external attack-surface monitor.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/chainseer-xyz/deckard/internal/plugin"
)

// Set at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	if handled, err := plugin.RunSandboxHelper(os.Args[1:]); handled {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
  ingest            post an external scanner's output (prowler, kubescape, trufflehog, gitleaks,
                    s3scanner, sarif, trivy, cyclonedx, falco, tetragon) to a deckard API
                    (ingest prowler-app pulls the findings of a running Prowler App instead)
  discovery ingest  import native BBOT discovery into a configured remote-only source
  runtime collect   collect a bounded, incomplete Tetragon event window
  images collect    scan immutable images from an explicit Kubernetes inventory
  assessment        execute or upload an isolated assessment job report
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
	case "ingest":
		return runIngest(args[1:], stdout, stderr)
	case "discovery":
		return runDiscovery(args[1:], stdout, stderr)
	case "runtime":
		return runRuntime(args[1:], stdout, stderr)
	case "assessment":
		return runAssessment(args[1:], stdout, stderr)
	case "images":
		return runImages(args[1:], stdout, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "deckard: unknown command %q\n\n%s", args[0], usage)
	return 2
}
