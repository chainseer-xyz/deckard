package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/runtimeevent"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var runtimeKubeClient = func(path string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error
	if path == "" {
		cfg, err = rest.InClusterConfig()
	} else {
		cfg, err = clientcmd.BuildConfigFromFlags("", path)
	}
	if err != nil {
		return nil, errors.New("kubernetes credentials are unavailable; use the collector service account or explicit --kubeconfig")
	}
	return kubernetes.NewForConfig(cfg)
}

func runRuntime(args []string, stdout, stderr io.Writer) int {
	const usage = "usage: deckard runtime collect --provider tetragon --namespace <sensor namespace> --selector <labels> --container export-stdout --cluster-scope k8s:uid:<cluster UID> [--output <fresh file> | --url <Deckard URL> --token-env <VAR> | --dry-run] [--lookback 6m] [--kubeconfig <file>]\n       deckard runtime upload --file <sanitized envelope> --cluster-scope k8s:uid:<cluster UID> --url <Deckard URL> --token-env <VAR>\n"
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 1
	}
	if args[0] != "collect" && args[0] != "upload" {
		_, _ = fmt.Fprint(stderr, usage)
		return 1
	}
	mode := args[0]
	fs := flag.NewFlagSet("runtime "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var provider, path, base, tokenEnv, output, file string
	var settings runtimeevent.Settings
	var duration time.Duration
	var dry bool
	provider = "tetragon"
	if mode == "collect" {
		fs.StringVar(&provider, "provider", "tetragon", "runtime provider")
		fs.StringVar(&path, "kubeconfig", "", "explicit kubeconfig (default in-cluster service account)")
		fs.StringVar(&settings.Namespace, "namespace", "", "sensor namespace")
		fs.StringVar(&settings.Selector, "selector", "", "sensor pod selector")
		fs.StringVar(&settings.Container, "container", "export-stdout", "export container")
		fs.DurationVar(&settings.Lookback, "lookback", 6*time.Minute, "bounded event overlap window")
		fs.DurationVar(&settings.Timeout, "collect-timeout", time.Minute, "sensor collection timeout")
		fs.StringVar(&output, "output", "", "publish one fresh sanitized report without an ingest credential")
		fs.BoolVar(&dry, "dry-run", false, "print sanitized incomplete envelope without uploading")
	} else {
		fs.StringVar(&file, "file", "", "fresh sanitized collector envelope")
	}
	fs.StringVar(&settings.ClusterScope, "cluster-scope", "", "immutable cluster identity")
	fs.DurationVar(&duration, "timeout", 2*time.Minute, "overall collection and upload timeout")
	fs.StringVar(&base, "url", "", "Deckard URL")
	fs.StringVar(&tokenEnv, "token-env", "", "scoped producer credential")
	if err := fs.Parse(args[1:]); err != nil { // #nosec G602 -- len(args)==0 returns before any indexing or slicing
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(stdout, usage)
			return 0
		}
		_, _ = fmt.Fprint(stderr, usage)
		return 1
	}
	token := os.Getenv(tokenEnv)
	out, errw := &scrubber{w: stdout, secret: token}, &scrubber{w: stderr, secret: token}
	fail := func(message string) int { _, _ = fmt.Fprintln(errw, "deckard runtime: "+message); return 1 }
	if fs.NArg() != 0 || provider != "tetragon" || duration <= 0 || duration > 5*time.Minute {
		return fail(usage)
	}
	if output != "" && (dry || base != "" || tokenEnv != "") {
		return fail("--output cannot combine with --dry-run or upload credentials")
	}
	var endpoint string
	var err error
	if !dry && output == "" {
		endpoint, err = ingestEndpoint(base)
		if err != nil {
			return fail(err.Error())
		}
		if tokenEnv == "" || token == "" {
			return fail("--token-env must name a nonempty producer credential")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	if mode == "upload" {
		if file == "" || file == "-" {
			return fail("--file must name a fresh sanitized report")
		}
		raw, _, err := readCollectorEnvelope(file)
		if err != nil {
			return fail("cannot read bounded sanitized collector report")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var report ingest.Request
		if decoder.Decode(&report) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || report.Tool != "tetragon" || report.Scope != settings.ClusterScope || report.Complete || report.ObservedAt == nil || time.Since(*report.ObservedAt) > time.Hour {
			return fail("collector envelope must be fresh, incomplete and match exact producer/scope")
		}
		if problems := ingest.Validate(&report, ingest.Options{Now: time.Now()}); len(problems) > 0 {
			return fail("invalid sanitized collector envelope")
		}
		return postIngest(ctx, endpoint, token, raw, ingestFlags{tool: report.Tool, scope: report.Scope, incomplete: true, timeout: duration}, out, errw)
	}
	client, err := runtimeKubeClient(path)
	if err != nil {
		return fail(err.Error())
	}
	collector, err := runtimeevent.New(client, settings)
	if err != nil {
		return fail(err.Error())
	}
	report, err := collector.Collect(ctx)
	if err != nil {
		return fail(err.Error())
	}
	body, err := json.Marshal(report)
	if err != nil {
		return fail("cannot encode sanitized events")
	}
	if dry {
		_, _ = out.Write(append(body, '\n'))
		return 0
	}
	if output != "" {
		if err := writeImagesReport(output, body); err != nil {
			return fail("cannot publish fresh sanitized report")
		}
		_, _ = fmt.Fprintf(out, "deckard runtime: wrote %d sanitized incidents; complete=false\n", len(report.Findings))
		return 0
	}
	return postIngest(ctx, endpoint, token, body, ingestFlags{tool: report.Tool, scope: report.Scope, incomplete: true, timeout: duration}, out, errw)
}
