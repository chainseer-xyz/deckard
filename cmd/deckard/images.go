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
	"path/filepath"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/imagecollector"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const imagesUsage = `usage: deckard images collect (--namespaces <csv> | --all-namespaces)
                       --cluster-scope k8s:uid:<UID>:runtime-images
                       [--output /report/request.json | --dry-run | --url <base> --token-env <VAR>]
                       [--registry-auth-dir /registry] [--timeout 45m]
       deckard images upload --file /report/request.json --cluster-scope <same scope>
                       --url <base> --token-env <VAR> [--timeout 2m]

Collects immutable runtime images using read-only in-cluster Pods/Nodes metadata.
Scans each digest/platform once with the pinned Trivy binary. No host Docker,
mutable-tag guesses, cloud credential inheritance or partial uploads on failure.
Bounds: 10000 Pods, 1000 Nodes, 64 images/platforms, 2m per image, 45m total,
5000 findings/artifacts and a 10MiB aggregate request. Start/end inventories must
match. Only explicit --all-namespaces can certify absence; namespace filters always
produce complete=false. Any scan or identity failure produces no output or POST.

For scheduled jobs, collect --output without an ingest token; mount the fresh
report read-only in a separate uploader holding the producer-specific token.
`

func runImages(args []string, stdout, stderr io.Writer) int {
	return runImagesWith(args, stdout, stderr, func() (imagecollector.Inventory, error) {
		configuration, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("read-only in-cluster Kubernetes authentication is unavailable")
		}
		configuration.Timeout = 30 * time.Second
		return typedcore.NewForConfig(configuration)
	})
}

func runImagesWith(args []string, stdout, stderr io.Writer, load func() (imagecollector.Inventory, error)) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		_, _ = fmt.Fprint(stdout, imagesUsage)
		if len(args) == 0 {
			return ingestExitUsage
		}
		return ingestExitOK
	}
	mode := args[0]
	if mode != "collect" && mode != "upload" {
		_, _ = fmt.Fprint(stderr, imagesUsage)
		return ingestExitUsage
	}
	var scope, namespaces, file, output, url, tokenEnv, authDir string
	var all, dryRun bool
	timeout := imagecollector.MaxDuration
	if mode == "upload" {
		timeout = 2 * time.Minute
	}
	fs := flag.NewFlagSet("images "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&scope, "cluster-scope", "", "immutable Kubernetes cluster reconciliation scope")
	fs.StringVar(&url, "url", "", "Deckard base URL")
	fs.StringVar(&tokenEnv, "token-env", "", "environment variable holding the producer credential")
	fs.DurationVar(&timeout, "timeout", timeout, "overall deadline")
	if mode == "collect" {
		fs.StringVar(&namespaces, "namespaces", "", "explicit comma-separated namespaces")
		fs.BoolVar(&all, "all-namespaces", false, "explicitly include all namespaces")
		fs.BoolVar(&dryRun, "dry-run", false, "print the normalized envelope without posting")
		fs.StringVar(&output, "output", "", "write one fresh validated report file without a credential")
		fs.StringVar(&authDir, "registry-auth-dir", "", "explicit read-only Docker config directory")
	} else {
		fs.StringVar(&file, "file", "", "fresh normalized collector report")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(stdout, imagesUsage)
			return ingestExitOK
		}
		_, _ = fmt.Fprintf(stderr, "deckard images: invalid flags\n%s", imagesUsage)
		return ingestExitUsage
	}
	if fs.NArg() != 0 || timeout <= 0 || timeout > imagecollector.MaxDuration {
		_, _ = fmt.Fprintln(stderr, "deckard images: invalid arguments or timeout (maximum 45m)")
		return ingestExitUsage
	}
	token := os.Getenv(tokenEnv)
	out := &scrubber{w: stdout, secret: token}
	errw := &scrubber{w: stderr, secret: token}
	fail := func(message string) int {
		_, _ = fmt.Fprintln(errw, "deckard images: "+message)
		return ingestExitUsage
	}
	options := imagecollector.Options{AllNamespaces: all, ClusterScope: scope, RegistryAuthDir: authDir}
	if namespaces != "" {
		options.Namespaces = strings.Split(namespaces, ",")
	}
	if mode == "upload" {
		options.AllNamespaces = true
	}
	if err := imagecollector.ValidateOptions(options); err != nil {
		return fail(err.Error())
	}
	if output != "" && (dryRun || url != "" || tokenEnv != "") {
		return fail("--output cannot receive upload credentials or combine with --dry-run")
	}
	var endpoint string
	if !dryRun && output == "" {
		var err error
		endpoint, err = ingestEndpoint(url)
		if err != nil {
			return fail(err.Error())
		}
		if tokenEnv == "" || token == "" {
			return fail("--token-env must name a nonempty producer credential")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var request *ingest.Request
	if mode == "collect" {
		inventory, err := load()
		if err != nil {
			return fail("read-only Kubernetes inventory is unavailable")
		}
		request, err = imagecollector.Collect(ctx, inventory, options)
		if err != nil {
			return fail(err.Error())
		}
	} else {
		if file == "" {
			return fail("--file is required")
		}
		raw, _, err := readCollectorEnvelope(file)
		if err != nil {
			return fail("cannot read bounded collector report")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		request = &ingest.Request{}
		if err = decoder.Decode(request); err != nil {
			return fail("invalid collector envelope")
		}
		if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			return fail("collector report must contain exactly one envelope")
		}
		if request.Tool != "trivy" || request.Scope != scope {
			return fail("collector producer or scope does not match upload authority")
		}
		if request.ObservedAt == nil || time.Since(*request.ObservedAt) > time.Hour {
			return fail("collector report is missing its timestamp or is older than one hour")
		}
	}
	body, err := imagecollector.Encode(request)
	if err != nil {
		return fail(err.Error())
	}
	if dryRun {
		_, err = fmt.Fprintln(out, string(body))
		if err != nil {
			return fail("cannot write report")
		}
		return ingestExitOK
	}
	if output != "" {
		if err = writeImagesReport(output, body); err != nil {
			return fail("cannot publish report (parent directory must exist and output must not exist)")
		}
		_, _ = fmt.Fprintf(out, "deckard images: wrote %d images/packages, %d findings; complete=%v\n", len(request.Artifacts), len(request.Findings), request.Complete)
		return ingestExitOK
	}
	return postIngest(ctx, endpoint, token, body, ingestFlags{tool: "trivy", scope: scope, timeout: timeout, incomplete: !request.Complete}, out, errw)
}

// Publish by an atomic link, not an overwrite. Failed or repeated runs cannot
// replace a previous report with partial bytes and accidentally reuse it.
func writeImagesReport(path string, body []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".deckard-images-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	if _, err = temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	return os.Link(temporary.Name(), path)
}
