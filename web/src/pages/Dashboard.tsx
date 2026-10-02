import { Link } from 'react-router-dom';
import { AlertTriangle, CheckCircle2, CircleSlash, Clock } from 'lucide-react';
import { useChanges, useSources, useStats } from '../api/hooks';
import { SEVERITIES } from '../api/types';
import type { SyncStatus } from '../api/types';
import { Card, Empty, ErrorBox, Loading, PageHeader, SeverityBadge } from '../components/ui';
import { absTime, relTime, syncHealth, titleCase } from '../lib/format';
import type { SyncHealth } from '../lib/format';

function Bars({ data, hrefFor }: { data: Record<string, number>; hrefFor?: (k: string) => string }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (entries.length === 0) return <Empty>None</Empty>;
  return (
    <ul className="space-y-1.5 p-3">
      {entries.map(([k, v]) => (
        <li key={k} className="text-sm">
          <div className="flex justify-between gap-2">
            {hrefFor ? (
              <Link to={hrefFor(k)} className="font-mono text-xs text-accent hover:underline">
                {k}
              </Link>
            ) : (
              <span className="font-mono text-xs">{k}</span>
            )}
            <span className="tabular-nums">{v}</span>
          </div>
          <div className="mt-0.5 h-1.5 rounded-sm bg-surface2" aria-hidden="true">
            <div className="h-1.5 rounded-sm bg-accent" style={{ width: `${(v / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

const HEALTH: Record<SyncHealth, { label: string; cls: string; Icon: typeof Clock }> = {
  ok: { label: 'Healthy', cls: 'text-ok', Icon: CheckCircle2 },
  stale: { label: 'Stale', cls: 'text-warn', Icon: Clock },
  failing: { label: 'Failing', cls: 'text-bad', Icon: AlertTriangle },
  never: { label: 'Never synced', cls: 'text-muted', Icon: CircleSlash },
};

export function HealthBadge({ s }: { s: SyncStatus }) {
  const h = HEALTH[syncHealth(s)];
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${h.cls}`}>
      <h.Icon size={12} aria-hidden="true" />
      {h.label}
    </span>
  );
}

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

export default function Dashboard() {
  const stats = useStats();
  const changes = useChanges(15);
  const sources = useSources();

  return (
    <>
      <PageHeader title="Dashboard" />
      {stats.isLoading && <Loading />}
      {stats.isError && <ErrorBox error={stats.error} onRetry={() => void stats.refetch()} />}
      {stats.data && (
        <div className="space-y-4">
          <section aria-label="Open findings by severity" className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {[...SEVERITIES].reverse().map((s) => (
              <Link
                key={s}
                to={`/findings?min_severity=${s}`}
                className="card block p-3 hover:bg-surface2"
                aria-label={`${stats.data.findings_by_severity[s] ?? 0} open ${s} findings`}
              >
                <SeverityBadge severity={s} />
                <div className="mt-2 text-3xl font-semibold tabular-nums">
                  {stats.data.findings_by_severity[s] ?? 0}
                </div>
                <div className="text-xs text-muted">open</div>
              </Link>
            ))}
          </section>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Open findings by check">
              <Bars data={stats.data.findings_by_check} hrefFor={(k) => `/findings?check=${encodeURIComponent(k)}`} />
            </Card>
            <Card title="Recent changes" right={<span className="text-xs text-muted">live</span>}>
              {changes.isLoading && <Loading />}
              {changes.isError && <ErrorBox error={changes.error} />}
              {changes.data && changes.data.items.length === 0 && <Empty>No recent changes.</Empty>}
              <ul className="divide-y divide-line">
                {changes.data?.items.map((e) => (
                  <li key={e.id} className="flex items-baseline gap-2 px-3 py-1.5 text-sm">
                    <span className="w-32 shrink-0 text-xs font-medium">{eventLabel(e.type)}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs" title={e.subject}>
                      {e.subject}
                    </span>
                    <time className="shrink-0 text-xs text-muted" dateTime={e.at} title={absTime(e.at)}>
                      {relTime(e.at)}
                    </time>
                  </li>
                ))}
              </ul>
            </Card>
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            <Card title="Assets by kind">
              <Bars data={stats.data.assets_by_kind} hrefFor={(k) => `/inventory?kind=${k}`} />
            </Card>
            <Card title="Assets by source">
              <Bars data={stats.data.assets_by_source} hrefFor={(k) => `/inventory?source=${encodeURIComponent(k)}`} />
            </Card>
            <Card title="Assets by scope">
              <Bars data={stats.data.assets_by_scope} hrefFor={(k) => `/inventory?scope=${k}`} />
            </Card>
          </div>

          <Card title="Source sync health" right={<Link to="/sources" className="text-xs text-accent hover:underline">Manage</Link>}>
            {sources.isLoading && <Loading />}
            {sources.isError && <ErrorBox error={sources.error} />}
            {sources.data && (
              <ul className="divide-y divide-line">
                {sources.data.items.map((s) => (
                  <li key={s.source} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 text-sm">
                    <span className="w-40 font-medium">{s.source}</span>
                    <span className="w-28">
                      <HealthBadge s={s} />
                    </span>
                    <span className="text-xs text-muted">last ok {relTime(s.last_ok)}</span>
                    <span className="text-xs text-muted">{s.asset_count} assets</span>
                    {s.error && <span className="min-w-0 flex-1 truncate text-xs text-bad" title={s.error}>{s.error}</span>}
                  </li>
                ))}
                {sources.data.items.length === 0 && <Empty>No sources configured.</Empty>}
              </ul>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
