package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
	"github.com/chainseer-xyz/deckard/internal/store/postgres"
)

const concurrencyARN = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/public/abc123"

func TestInventoryMutationsAndARNIngestShareIdentityLock(t *testing.T) {
	for _, operation := range []string{"snapshot", "partial_snapshot", "discovered", "derived", "arn_ingest", "opaque_ingest"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			t.Cleanup(cancel)
			s := newMigratedStore(t).(*postgres.Store)
			now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
			parent := seedIdentityAsset(t, ctx, s, now, concurrencyARN)
			blocker, observer, tx := holdIdentityLock(t, ctx, s)
			done := stateMigrationAsync(t, cancel, func() error {
				return identityMutation(ctx, s, parent, operation, now.Add(time.Minute))
			})
			pid := waitIdentityLock(t, ctx, observer, blocker.PgConn().PID(), done)
			assertIdentityLockPrecedesAssetWrites(t, ctx, observer, pid)
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			awaitStateMigration(t, ctx, done)
			if operation == "arn_ingest" {
				findings, _, err := s.ListFindings(ctx, store.FindingFilter{Check: "ext.prowler"})
				if err != nil || len(findings) != 1 || findings[0].AssetID != parent.ID {
					t.Fatalf("exact ARN was not correlated after lock release: %+v, %v", findings, err)
				}
			}
		})
	}
}

func identityMutation(ctx context.Context, s *postgres.Store, parent model.Asset, operation string, now time.Time) error {
	assets := []store.AssetUpsert{{AssetInput: model.AssetInput{
		Kind: model.KindHostname, Key: "new.example.com", Source: "test-inventory",
	}, Scope: model.ScopeExternal}}
	var err error
	switch operation {
	case "snapshot":
		_, err = s.ApplySnapshot(ctx, "test-inventory", assets, nil, now)
	case "partial_snapshot":
		_, err = s.UpsertSnapshot(ctx, "test-inventory", assets, nil, now)
	case "discovered":
		_, err = s.AddDiscovered(ctx, assets, nil, now)
	case "derived":
		_, err = s.ReplaceDerived(ctx, parent.ID, "test.check", assets, nil, now)
	case "arn_ingest":
		_, err = s.IngestFindings(ctx, identityIngest(now, concurrencyARN))
	case "opaque_ingest":
		_, err = s.IngestFindings(ctx, identityIngest(now, "repository:example/app"))
	default:
		return fmt.Errorf("unknown identity test operation %q", operation)
	}
	return err
}

func TestARNIngestObservesFactsCommittedWhileWaitingForIdentityLock(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprintf("ambiguous_%t", ambiguous), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			t.Cleanup(cancel)
			s := newMigratedStore(t).(*postgres.Store)
			now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
			initialARN := concurrencyARN
			if !ambiguous {
				initialARN += "-previous"
			}
			parent := seedIdentityAsset(t, ctx, s, now, initialARN)
			blocker, observer, tx := holdIdentityLock(t, ctx, s)
			var result store.IngestResult
			done := stateMigrationAsync(t, cancel, func() error {
				var err error
				result, err = s.IngestFindings(ctx, identityIngest(now.Add(time.Minute), concurrencyARN))
				return err
			})
			waitIdentityLock(t, ctx, observer, blocker.PgConn().PID(), done)
			otherID := commitIdentityFactChange(t, ctx, tx, parent.ID, ambiguous, now)
			awaitStateMigration(t, ctx, done)
			findings, _, err := s.ListFindings(ctx, store.FindingFilter{Check: "ext.prowler"})
			if err != nil {
				t.Fatal(err)
			}
			if !ambiguous {
				if len(findings) != 1 || findings[0].AssetID != parent.ID {
					t.Fatalf("ingest used an identity view from before the lock: %+v", findings)
				}
			} else {
				for _, finding := range findings {
					if finding.AssetID == parent.ID || finding.AssetID == otherID {
						t.Fatalf("ingest guessed between concurrent native claimants: %+v", finding)
					}
				}
				if len(findings) == 0 && len(result.Rejected) == 0 {
					t.Fatal("ambiguous input disappeared without an isolated finding or rejection")
				}
			}
		})
	}
}

func seedIdentityAsset(t *testing.T, ctx context.Context, s *postgres.Store, now time.Time, arn string) model.Asset {
	t.Helper()
	_, err := s.ApplySnapshot(ctx, "aws-native", []store.AssetUpsert{{AssetInput: model.AssetInput{
		Kind: model.KindCloudResource, Key: "aws:elbv2:us-west-2:public", Source: "aws-native",
		Attrs: map[string]any{"arn": arn, "aws.account": "123456789012", "aws.region": "us-west-2"},
	}, Scope: model.ScopeExternal}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.GetAssetByKey(ctx, model.KindCloudResource, "aws:elbv2:us-west-2:public")
	if err != nil {
		t.Fatal(err)
	}
	return *a
}

func identityIngest(now time.Time, key string) store.IngestInput {
	return store.IngestInput{Tool: "prowler", Scope: "aws:123456789012:us-west-2", Check: "ext.prowler", Source: "ingest:prowler",
		AssetScope: model.ScopeExternal, Complete: true, ObservedAt: now, Now: now, ResolveAfter: 1, Digest: "identity-lock-test",
		Items: []store.IngestItem{{Index: 0, AssetKind: model.KindCloudResource, AssetKey: key,
			Finding: model.FindingInput{Key: "check:" + key, Severity: model.SeverityHigh, Title: "exposure",
				Evidence: map[string]any{"provider": "aws", "account": "123456789012", "region": "us-west-2"}}}}}
}

func holdIdentityLock(t *testing.T, ctx context.Context, s *postgres.Store) (*pgx.Conn, *pgx.Conn, pgx.Tx) {
	t.Helper()
	url := s.Pool().Config().ConnConfig.ConnString()
	blocker := stateMigrationConn(t, ctx, url)
	observer := stateMigrationConn(t, ctx, url)
	tx := stateMigrationTx(t, ctx, blocker)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('deckard.inventory.identity', 0))`); err != nil {
		t.Fatal(err)
	}
	return blocker, observer, tx
}

func waitIdentityLock(t *testing.T, ctx context.Context, observer *pgx.Conn, blockerPID uint32, done <-chan error) uint32 {
	t.Helper()
	for {
		select {
		case err := <-done:
			t.Fatalf("mutation completed instead of waiting for the shared identity lock: %v", err)
		default:
		}
		var pid uint32
		err := observer.QueryRow(ctx, `SELECT waiting.pid FROM pg_locks held JOIN pg_locks waiting
			ON held.locktype = waiting.locktype AND held.database = waiting.database
			AND held.classid = waiting.classid AND held.objid = waiting.objid AND held.objsubid = waiting.objsubid
			WHERE held.pid = $1 AND held.granted AND held.locktype = 'advisory'
			AND NOT waiting.granted LIMIT 1`, blockerPID).Scan(&pid)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // The server's lock queue, not elapsed time, is the barrier.
		}
		if err != nil {
			t.Fatalf("observe identity advisory lock: %v", err)
		}
		return pid
	}
}

func assertIdentityLockPrecedesAssetWrites(t *testing.T, ctx context.Context, observer *pgx.Conn, pid uint32) {
	t.Helper()
	var writes int
	if err := observer.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid = $1 AND granted
		AND relation = 'assets'::regclass AND mode IN ('RowExclusiveLock', 'RowShareLock')`, pid).Scan(&writes); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatal("identity barrier was acquired after asset mutation or row locking")
	}
}

func commitIdentityFactChange(t *testing.T, ctx context.Context, tx pgx.Tx, parentID int64, ambiguous bool, now time.Time) int64 {
	t.Helper()
	attrs := map[string]any{"arn": concurrencyARN, "aws.account": "123456789012", "aws.region": "us-west-2"}
	var otherID int64
	if ambiguous {
		facts := map[string]model.SourceFact{"aws-other": {Attrs: attrs}}
		err := tx.QueryRow(ctx, `INSERT INTO assets (kind, key, source, scope, attrs, first_seen, last_seen, reporters, source_facts)
			VALUES ('cloud_resource', 'aws:elbv2:us-west-2:second', 'aws-other', 'external', $1, $2, $2, '{aws-other}', $3)
			RETURNING id`, attrs, now, facts).Scan(&otherID)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		facts := map[string]model.SourceFact{"aws-native": {Attrs: attrs}}
		if _, err := tx.Exec(ctx, `UPDATE assets SET attrs = $2, source_facts = $3 WHERE id = $1`, parentID, attrs, facts); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return otherID
}
