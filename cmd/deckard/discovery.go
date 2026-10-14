package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/discoveryimport"
	"github.com/chainseer-xyz/deckard/internal/source/bbot"
)

func runDiscovery(args []string, stdout, stderr io.Writer) int {
	const usage = "usage: deckard discovery ingest --source <remote BBOT source> --file <report> --url <Deckard URL> --token-env <VAR> [--dry-run] [--timeout 2m]\n"
	if len(args) == 0 || args[0] != "ingest" {
		_, _ = fmt.Fprint(stderr, usage)
		return 1
	}
	fs := flag.NewFlagSet("discovery ingest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var source, file, base, tokenEnv string
	var dry bool
	var duration time.Duration
	fs.StringVar(&source, "source", "", "configured remote BBOT source")
	fs.StringVar(&file, "file", "", "native BBOT NDJSON report (default stdin)")
	fs.StringVar(&base, "url", "", "Deckard URL")
	fs.StringVar(&tokenEnv, "token-env", "", "scoped producer token environment variable")
	fs.BoolVar(&dry, "dry-run", false, "validate without posting")
	fs.DurationVar(&duration, "timeout", 2*time.Minute, "overall request timeout")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(stdout, usage)
			return 0
		}
		_, _ = fmt.Fprint(stderr, usage)
		return 1
	}
	token := os.Getenv(tokenEnv)
	out, errw := &scrubber{w: stdout, secret: token}, &scrubber{w: stderr, secret: token}
	fail := func(message string) int { _, _ = fmt.Fprintln(errw, "deckard discovery: "+message); return 1 }
	if fs.NArg() != 0 || source == "" || len(source) > 200 || strings.TrimSpace(source) != source || strings.ContainsAny(source, "/\\?#\n\r\t") || strings.HasPrefix(source, "ingest:") || duration <= 0 {
		return fail(usage)
	}
	raw, _, err := readIngestInput(file, discoveryimport.MaxBodyBytes)
	if err != nil {
		return fail(err.Error())
	}
	d, err := bbot.Parse(context.Background(), strings.NewReader(string(raw)), source)
	if err != nil {
		return fail(err.Error())
	}
	if dry {
		_, _ = fmt.Fprintf(out, "deckard discovery: source=%s assets=%d partial=true (not posted)\n", source, len(d.Assets))
		return 0
	}
	endpoint, err := ingestEndpoint(base)
	if err != nil {
		return fail(err.Error())
	}
	if tokenEnv == "" || token == "" {
		return fail("--token-env must name a nonempty producer credential")
	}
	endpoint = strings.TrimSuffix(endpoint, "/ingest") + "/discovery/" + url.PathEscape(source)
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	status, response, err := postWithRetry(ctx, endpoint, token, raw, duration, false, errw)
	if err != nil {
		return fail("could not reach Deckard")
	}
	if status != 200 {
		_, _ = fmt.Fprintf(errw, "deckard discovery: HTTP %d; report was not accepted\n", status)
		return 2
	}
	var receipt discoveryimport.Receipt
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.DisallowUnknownFields()
	if len(response) > 4096 || decoder.Decode(&receipt) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || receipt.Source != source || !receipt.Partial || receipt.Status != "accepted" || receipt.Added < 0 || receipt.Changed < 0 || receipt.Revived < 0 || receipt.Ignored < 0 {
		return fail("invalid source-bound delivery receipt; acceptance was not confirmed")
	}
	_, _ = fmt.Fprintf(out, "deckard discovery: source=%s assets=%d partial=true (accepted)\n", source, len(d.Assets))
	return 0
}
