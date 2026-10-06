import { Link } from 'react-router-dom';
import { useChanges, useScans, useSources, useStats } from '../api/hooks';
import { SEVERITIES } from '../api/types';
import type { Severity, SyncStatus } from '../api/types';
import { NeedsAttentionList } from '../components/NeedsAttention';
import { SourceStatus } from '../components/SourceHealth';
import { Card, Empty, ErrorBox, PageHeader, SeverityBadge } from '../components/ui';
import { changeSummary, scanSummary } from '../lib/dashboard';
import { absTime, fmtDuration, isPartialSync, relTime, syncHealth, titleCase } from '../lib/format';
import type { Tally } from '../lib/triage';
import { useDashboardFindings } from './useDashboardFindings';

const EVENT_LABEL: Record<string, string> = {
  asset_added: 'Asset added',
  asset_removed: 'Asset removed',
  asset_changed: 'Asset changed',
  asset_revived: 'Asset revived',
  finding_opened: 'Finding opened',
  finding_resolved: 'Finding resolved',
  finding_reopened: 'Finding reopened',
};
export const eventLabel = (t: string) => EVENT_LABEL[t] ?? titleCase(t);

/** Reserves its final height while loading so the page does not jump. */
function Skeleton({ rows, rowClass = 'h-12' }: { rows: number; rowClass?: string }) {
  return (
    <div role="status" aria-label="Loading" className="divide-y divide-line">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className={`${rowClass} animate-pulse bg-surface2/50`} />
      ))}
    </div>
  );
}

function BarList({ data, hrefFor, empty }: { data: Tally[]; hrefFor: (k: string) => string; empty: string }) {
  const max = Math.max(1, ...data.map((d) => d.count));
  if (data.length === 0) return <Empty>{empty}</Empty>;
  return (
    <ul className="space-y-2 p-3">
      {data.map(({ key, count }) => (
        <li key={key} className="text-sm">
          <Link
            to={hrefFor(key)}
            className="block rounded-sm hover:bg-surface2"
            aria-label={`${key}: ${count} open findings above low`}
          >
            <span className="flex justify-between gap-2">
              <span className="min-w-0 truncate font-mono text-xs text-accent">{key}</span>
              <span className="tabular-nums">{count}</span>
            </span>
            <span className="mt-0.5 block h-1.5 rounded-sm bg-surface2" aria-hidden="true">
              <span className="block h-1.5 rounded-sm bg-accent" style={{ width: `${(count / max) * 100}%` }} />
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

function Counts({ data, hrefFor }: { data: Record<string, number>; hrefFor: (k: string) => string }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return <Empty>None</Empty>;
  return (
    <ul className="divide-y divide-line">
      {entries.map(([k, v]) => (
        <li key={k}>
          <Link to={hrefFor(k)} className="flex justify-between gap-2 px-3 py-1.5 text-sm hover:bg-surface2">
            <span className="font-mono text-xs text-accent">{k}</span>
            <span className="tabular-nums">{v}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

function SeverityTiles({ counts, fresh, loading }: { counts?: Record<string, number>; fresh?: Record<Severity, number>; loading: boolean }) {
  return (
    <section aria-label="Open findings by severity" className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {[...SEVERITIES].reverse().map((s) => {
        const n = counts?.[s] ?? 0;
        const fresh24 = fresh?.[s];
        return (
          <Link
            key={s}
            to={`/findings?severity=${s}`}
            className="card block min-h-28 p-3 hover:bg-surface2"
            aria-label={loading ? `Open ${s} findings` : `${n} open ${s} findings`}
          >
            <SeverityBadge severity={s} />
            <div className="mt-2 text-3xl font-semibold tabular-nums">{loading ? '–' : n}</div>
            <div className="text-xs text-muted">
              open
              {fresh24 !== undefined && fresh24 > 0 && (
                <span className="ml-2 font-medium text-fg">+{fresh24} new in 24h</span>
              )}
            </div>
          </Link>
        );
      })}
    </section>
  );
}

function SourceStrip({ items, now }: { items: SyncStatus[]; now: number }) {
  if (items.length === 0) {
    return <Empty>No sources configured. Add a source in the Deckard config to discover assets.</Empty>;
  }
  return (
    <ul className="grid gap-2 p-3 sm:grid-cols-2 lg:grid-cols-3">
      {items.map((s) => {
        const h = syncHealth(s, now);
        const border = h === 'failing' ? 'border-bad' : h === 'stale' || isPartialSync(s) ? 'border-warn' : 'border-line';
        return (
          <li key={s.source} className={`min-h-24 rounded-md border bg-surface p-2.5 text-sm ${border}`}>
            <div className="flex flex-wrap items-center justify-between gap-1">
              <span className="font-medium">{s.source}</span>
              <SourceStatus s={s} now={now} />
            </div>
            <div className="mt-1 text-xs text-muted">
              <span title={absTime(s.last_ok)}>last successful sync {relTime(s.last_ok, now)}</span>
              {' · '}
              {s.asset_count} assets
            </div>
            {s.error && <p className="mt-1 break-words text-xs text-bad">{s.error}</p>}
            {s.warning && !s.error && (
              <p className="mt-1 break-words text-xs text-warn">
                {s.warning}
              </p>
            )}
          </li>
        );
      })}
    </ul>
  );
}

const SCAN_WINDOW = 500;

export default function Dashboard() {
  const now = Date.now();
  const stats = useStats();
  const { attention: open, zones, checks, freshCounts: fresh, zoneTallies, checkTallies } = useDashboardFindings(now);
  const changes = useChanges(500);
  const sources = useSources();
  const scans = useScans(SCAN_WINDOW, 0);

  const feed = changes.data ? changeSummary(changes.data.items) : undefined;
  const scan = scans.data ? scanSummary(scans.data.items, SCAN_WINDOW, now) : undefined;

  return (
    <>
      <PageHeader title="Dashboard" />
      <div className="space-y-4">
        <Card
          title="Needs attention"
          right={
            <Link to="/findings?min_severity=high" className="text-xs text-accent hover:underline">
              All critical and high
            </Link>
          }
        >
          {open.isLoading && <Skeleton rows={3} rowClass="h-[4.5rem]" />}
          {open.isError && <ErrorBox error={open.error} onRetry={() => void open.refetch()} />}
          {open.data && <NeedsAttentionList items={open.data.items} total={open.data.total} now={now} />}
        </Card>

        {stats.isError ? (
          <ErrorBox error={stats.error} onRetry={() => void stats.refetch()} />
        ) : (
          <SeverityTiles counts={stats.data?.findings_by_severity} fresh={fresh} loading={stats.isLoading} />
        )}

        <Card title="Last 24 hours">
          <p className="min-h-10 px-3 py-2 text-sm" aria-live="polite">
            {changes.isLoading && <span className="text-muted">Loading…</span>}
            {changes.isError && <span className="text-bad">Could not load the change feed.</span>}
            {feed &&
              (feed.total === 0 ? (
                <span className="text-muted">No changes in the last 24 hours.</span>
              ) : (
                <>
                  <b>{feed.opened}</b> findings opened · <b>{feed.reopened}</b> reopened · <b>{feed.resolved}</b> resolved ·{' '}
                  <b>{feed.assetsAdded}</b> assets added · <b>{feed.assetsRemoved}</b> removed · <b>{feed.assetsChanged}</b> changed
                  {feed.total >= 500 && <span className="text-muted"> (feed capped at 500 events)</span>}
                </>
              ))}
          </p>
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Top zones by open findings above low">
            {zones.isLoading ? (
              <Skeleton rows={4} rowClass="h-9" />
            ) : zones.isError ? (
              <ErrorBox error={zones.error} onRetry={() => void zones.refetch()} />
            ) : (
              <BarList
                data={zoneTallies}
                hrefFor={(k) => `/findings?zone=${encodeURIComponent(k)}`}
                empty="No open findings above low severity."
              />
            )}
          </Card>
          <Card title="Top checks by open findings above low">
            {checks.isLoading ? (
              <Skeleton rows={4} rowClass="h-9" />
            ) : checks.isError ? (
              <ErrorBox error={checks.error} onRetry={() => void checks.refetch()} />
            ) : (
              <BarList
                data={checkTallies}
                hrefFor={(k) => `/findings?check=${encodeURIComponent(k)}`}
                empty="No open findings above low severity."
              />
            )}
          </Card>
        </div>

        <Card title="Source health" right={<Link to="/sources" className="text-xs text-accent hover:underline">Manage</Link>}>
          {sources.isLoading && <Skeleton rows={2} rowClass="h-24" />}
          {sources.isError && <ErrorBox error={sources.error} />}
          {sources.data && <SourceStrip items={sources.data.items} now={now} />}
        </Card>

        <Card title="Scan freshness" right={<Link to="/sources" className="text-xs text-accent hover:underline">Scan runs</Link>}>
          <div className="min-h-16 px-3 py-2 text-sm">
            {scans.isLoading && <span className="text-muted">Loading…</span>}
            {scans.isError && <span className="text-bad">Could not load scan runs.</span>}
            {scan &&
              (scans.data?.items.length === 0 ? (
                <span className="text-muted">No scans have completed yet. Scans start after the first source sync discovers assets.</span>
              ) : (
                <ul className="space-y-1">
                  <li>
                    <b>
                      {scan.lastHour}
                      {scan.atLeast ? '+' : ''}
                    </b>{' '}
                    scans in the last hour
                    {scan.lastRun && (
                      <span className="text-muted" title={absTime(scan.lastRun.started_at)}>
                        {' '}
                        · latest {relTime(scan.lastRun.started_at, now)}
                      </span>
                    )}
                  </li>
                  <li>
                    {scan.lastFailure ? (
                      <>
                        <span className="font-medium text-bad">Last failure</span>{' '}
                        <span title={absTime(scan.lastFailure.started_at)}>{relTime(scan.lastFailure.started_at, now)}</span>:{' '}
                        <span className="font-mono text-xs">{scan.lastFailure.check}</span> on{' '}
                        <Link className="text-accent hover:underline" to={`/assets/${scan.lastFailure.asset_id}`}>
                          asset #{scan.lastFailure.asset_id}
                        </Link>{' '}
                        <span className="break-words text-xs text-muted">
                          ({scan.lastFailure.error}, took {fmtDuration(scan.lastFailure.duration_ms)})
                        </span>
                      </>
                    ) : (
                      <span className="text-muted">No failed scans in the recent window.</span>
                    )}
                  </li>
                </ul>
              ))}
          </div>
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Recent changes" right={<span className="text-xs text-muted">live</span>}>
            <div className="min-h-40">
              {changes.isLoading && <Skeleton rows={4} rowClass="h-8" />}
              {changes.isError && <ErrorBox error={changes.error} />}
              {changes.data && changes.data.items.length === 0 && <Empty>No changes in the last 24 hours.</Empty>}
              <ul className="divide-y divide-line">
                {/* the feed is newest first */}
                {changes.data?.items.slice(0, 8).map((e) => (
                  <li key={e.id} className="flex items-baseline gap-2 px-3 py-1.5 text-sm">
                    <span className="w-32 shrink-0 text-xs font-medium">{eventLabel(e.type)}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs" title={e.subject}>
                      {e.subject}
                    </span>
                    <time className="shrink-0 text-xs text-muted" dateTime={e.at} title={absTime(e.at)}>
                      {relTime(e.at, now)}
                    </time>
                  </li>
                ))}
              </ul>
            </div>
          </Card>
          <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-1 xl:grid-cols-3">
            <Card title="Assets by kind">
              <Counts data={stats.data?.assets_by_kind ?? {}} hrefFor={(k) => `/inventory?kind=${k}`} />
            </Card>
            <Card title="Assets by source">
              <Counts data={stats.data?.assets_by_source ?? {}} hrefFor={(k) => `/inventory?source=${encodeURIComponent(k)}`} />
            </Card>
            <Card title="Assets by scope">
              <Counts data={stats.data?.assets_by_scope ?? {}} hrefFor={(k) => `/inventory?scope=${k}`} />
            </Card>
          </div>
        </div>
      </div>
    </>
  );
}
