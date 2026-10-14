package postgres_test

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

// Opt-in, reproducible contention evidence, not a production capacity/SLO claim.
// The database is a fresh testcontainer clone; never point this at operator data.
func TestIdentityLockConcurrentLoad(t *testing.T) {
	if os.Getenv("DECKARD_IDENTITY_LOAD") != "1" {
		t.Skip("set DECKARD_IDENTITY_LOAD=1 for the real PostgreSQL contention fixture")
	}
	s := newMigratedStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	const producers, passes, batch = 8, 16, 25
	now := time.Now().UTC().Add(-time.Hour)
	var workers sync.WaitGroup
	latencies := make(chan time.Duration, producers*passes+passes)
	errors := make(chan error, producers+1)
	started := time.Now()
	for producer := 0; producer < producers; producer++ {
		workers.Go(func() {
			for pass := 0; pass < passes; pass++ {
				in := store.IngestInput{Tool: "prowler", Scope: fmt.Sprintf("load:%d", producer), Check: "ext.prowler", Source: "ingest:prowler", ObservedAt: now.Add(time.Duration(pass) * time.Minute), Now: now.Add(time.Duration(pass) * time.Minute), Digest: fmt.Sprintf("load:%d:%d", producer, pass)}
				for item := 0; item < batch; item++ {
					key := fmt.Sprintf("resource:%d:%d", producer, item)
					in.Items = append(in.Items, store.IngestItem{Index: item, AssetKind: model.KindCloudResource, AssetKey: key, Finding: model.FindingInput{Key: key, Title: "Load fixture", Severity: model.SeverityLow}})
				}
				before := time.Now()
				_, err := s.IngestFindings(ctx, in)
				latencies <- time.Since(before)
				if err != nil {
					errors <- err
					return
				}
			}
		})
	}
	workers.Go(func() {
		for pass := 0; pass < passes; pass++ {
			var assets []store.AssetUpsert
			for item := 0; item < 50; item++ {
				assets = append(assets, store.AssetUpsert{AssetInput: model.AssetInput{Kind: model.KindHostname, Key: fmt.Sprintf("load-%d.example.com", item), Source: "load-native"}, Scope: model.ScopeExternal})
			}
			before := time.Now()
			_, err := s.ApplySnapshot(ctx, "load-native", assets, nil, now.Add(time.Duration(pass)*time.Minute))
			latencies <- time.Since(before)
			if err != nil {
				errors <- err
				return
			}
		}
	})
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	close(latencies)
	var samples []time.Duration
	for latency := range latencies {
		samples = append(samples, latency)
	}
	if len(samples) != (producers+1)*passes {
		t.Fatalf("completed %d transactions", len(samples))
	}
	_, count, err := s.ListFindings(ctx, store.FindingFilter{Check: "ext.prowler", Limit: 1})
	if err != nil || count != producers*batch {
		t.Fatalf("findings count=%d err=%v", count, err)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	elapsed := time.Since(started)
	t.Logf("identity lock: %d transactions, %d finding updates + %d inventory rows, %s, %.1f txn/s, p50=%s p95=%s p99=%s; 8 producers + 1 source, pool4, local PostgreSQL16, race-enabled", len(samples), producers*passes*batch, passes*50, elapsed.Round(time.Millisecond), float64(len(samples))/elapsed.Seconds(), samples[len(samples)*50/100].Round(time.Millisecond), samples[len(samples)*95/100].Round(time.Millisecond), samples[len(samples)*99/100].Round(time.Millisecond))
}
