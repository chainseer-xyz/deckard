package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/chainseer-xyz/deckard/internal/ingest"
)

const maxKubescapeInput = 64 << 20

// kubescapeBatches retains the scan timestamp and sorted finding identities.
// Disjoint findings give each batch a distinct canonical replay digest. Keep
// only request slices, rather than every encoded body, in memory.
func kubescapeBatches(req *ingest.Request) ([]ingest.Request, error) {
	empty := *req
	empty.Findings = []ingest.Finding{}
	header, err := json.Marshal(&empty)
	if err != nil {
		return nil, err
	}
	var batches []ingest.Request
	start, size := 0, len(header)
	for i := range req.Findings {
		item, err := json.Marshal(&req.Findings[i])
		if err != nil {
			return nil, err
		}
		extra := len(item)
		if i > start {
			extra++ // JSON array separator
		}
		if i > start && (i-start == ingest.MaxFindings || size+extra > ingest.MaxBodyBytes) {
			batch := *req
			batch.Findings = req.Findings[start:i]
			batches = append(batches, batch)
			start, size, extra = i, len(header), len(item)
		}
		if size+extra > ingest.MaxBodyBytes {
			return nil, fmt.Errorf("finding %d exceeds the request body limit", i)
		}
		size += extra
	}
	last := *req
	last.Findings = req.Findings[start:]
	batches = append(batches, last)
	// Validate every batch before allowing any network write.
	for i := range batches {
		if problems := ingest.Validate(&batches[i], ingest.Options{Now: time.Now()}); len(problems) > 0 {
			return nil, fmt.Errorf("batch %d would be rejected: %s", i+1, ingest.Summary(problems))
		}
	}
	return batches, nil
}

func ingestKubescapeBatches(req *ingest.Request, f ingestFlags, endpoint, src, token string, out, errw io.Writer) int {
	batches, err := kubescapeBatches(req)
	if err != nil {
		_, _ = fmt.Fprintf(errw, "deckard ingest: %v\n", err)
		return ingestExitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	for i := range batches {
		body, err := json.Marshal(&batches[i])
		if err != nil {
			_, _ = fmt.Fprintf(errw, "deckard ingest: encode batch %d: %v\n", i+1, err)
			return ingestExitUsage
		}
		if f.verbose {
			_, _ = fmt.Fprintf(errw, "deckard ingest: batch %d/%d: %d findings from %s (%s parser), %d bytes, complete=false, observed_at=%s\n",
				i+1, len(batches), len(batches[i].Findings), src, f.format, len(body), req.ObservedAt.Format(time.RFC3339))
		}
		if f.dryRun {
			if len(batches) == 1 {
				var pretty bytes.Buffer
				_ = json.Indent(&pretty, body, "", "  ")
				body = pretty.Bytes()
			}
			_, _ = fmt.Fprintln(out, string(body))
			continue
		}
		if code := postKubescapeBatch(ctx, endpoint, token, body, len(batches[i].Findings), f, out, errw); code != ingestExitOK {
			_, _ = fmt.Fprintf(errw, "deckard ingest: batch %d/%d failed; collection was not fully delivered\n", i+1, len(batches))
			return code
		}
	}
	return ingestExitOK
}

func postKubescapeBatch(ctx context.Context, endpoint, token string, body []byte, count int, f ingestFlags, out, errw io.Writer) int {
	status, response, err := postWithRetry(ctx, endpoint, token, body, f.timeout, f.verbose, errw)
	if err != nil {
		if errors.Is(err, errBadRequest) {
			_, _ = fmt.Fprintf(errw, "deckard ingest: build request: %v\n", err)
			return ingestExitUsage
		}
		_, _ = fmt.Fprintf(errw, "deckard ingest: could not reach deckard: %v\n", err)
		return ingestExitNetwork
	}
	if status == http.StatusOK {
		var receipt ingest.Response
		if json.Unmarshal(response, &receipt) == nil && (receipt.Complete || receipt.Resolved != 0 || receipt.ResolvedPending != 0 ||
			!receipt.Replay && receipt.Accepted != count || receipt.Replay && receipt.Accepted != 0) {
			_, _ = fmt.Fprintln(errw, "deckard ingest: invalid batch delivery receipt; acceptance was not confirmed")
			return ingestExitRejected
		}
	}
	return ingestOutcome(status, response, f, out, errw)
}
