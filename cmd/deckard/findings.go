package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

const findingsUsage = "usage: deckard findings [--config path] [--min-severity info|low|medium|high|critical] [--status open|acknowledged|suppressed|false_positive|resolved|all] [--format table|json]"

// runFindings prints the current findings straight from the database through
// the store. It is read-only: it never migrates or writes.
func runFindings(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", os.Getenv("DECKARD_CONFIG"), "YAML config file")
	minSev := fs.String("min-severity", "", "only findings at or above this severity")
	status := fs.String("status", string(model.StatusOpen), "finding status, or \"all\"")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	filter := store.FindingFilter{}
	if *minSev != "" {
		sev := model.Severity(*minSev)
		if !sev.Valid() {
			_, _ = fmt.Fprintf(stderr, "deckard: invalid --min-severity %q\n%s\n", *minSev, findingsUsage)
			return 2
		}
		filter.MinSeverity = sev
	}
	switch model.FindingStatus(*status) {
	case model.StatusOpen, model.StatusAcknowledged, model.StatusSuppressed, model.StatusFalsePositive, model.StatusResolved:
		filter.Statuses = []model.FindingStatus{model.FindingStatus(*status)}
	default:
		if *status != "all" {
			_, _ = fmt.Fprintf(stderr, "deckard: invalid --status %q\n%s\n", *status, findingsUsage)
			return 2
		}
	}
	if *format != "table" && *format != "json" {
		_, _ = fmt.Fprintf(stderr, "deckard: invalid --format %q\n%s\n", *format, findingsUsage)
		return 2
	}

	cfg, err := config.Load(*path, os.Environ())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if cfg.Database.URL == "" {
		_, _ = fmt.Fprintln(stderr, "deckard: database.url is required (or DECKARD_DATABASE__URL)")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := postgres.New(ctx, cfg.Database.URL, 2)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "deckard:", err)
		return 1
	}
	defer st.Close()
	fs2, _, err := st.ListFindings(ctx, filter)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "deckard:", err)
		return 1
	}
	sortFindings(fs2)
	if *format == "json" {
		if fs2 == nil {
			fs2 = []model.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(fs2); err != nil {
			_, _ = fmt.Fprintln(stderr, "deckard:", err)
			return 1
		}
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SEVERITY\tCHECK\tASSET\tTITLE\tFIRST_SEEN")
	for _, f := range fs2 {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Check, f.AssetKey, f.Title, f.FirstSeen.UTC().Format("2006-01-02 15:04"))
	}
	if err := tw.Flush(); err != nil {
		_, _ = fmt.Fprintln(stderr, "deckard:", err)
		return 1
	}
	return 0
}

// sortFindings orders by severity (highest first), then age (oldest first).
func sortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if ri, rj := fs[i].Severity.Rank(), fs[j].Severity.Rank(); ri != rj {
			return ri > rj
		}
		if !fs[i].FirstSeen.Equal(fs[j].FirstSeen) {
			return fs[i].FirstSeen.Before(fs[j].FirstSeen)
		}
		return fs[i].ID < fs[j].ID
	})
}
