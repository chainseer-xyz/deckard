import { useState } from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';
import { useMe, useScans, useSources, useSyncSource } from '../api/hooks';
import { Card, Empty, ErrorBox, Loading, PageHeader, Pagination } from '../components/ui';
import { SourceStatus } from '../components/SourceHealth';
import { absTime, fmtDuration, relTime, syncHealth } from '../lib/format';

const LIMIT = 50;

export default function Sources() {
  const sources = useSources();
  const me = useMe();
  const sync = useSyncSource();
  const [page, setPage] = useState(1);
  const scans = useScans(LIMIT, (page - 1) * LIMIT);
  const canWrite = me.data?.can_write ?? false;

  return (
    <>
      <PageHeader title="Sources & Scans" />
      <div className="space-y-4">
        <Card title="Sources">
          {sources.isLoading && <Loading />}
          {sources.isError && <ErrorBox error={sources.error} onRetry={() => void sources.refetch()} />}
          {sources.data && (sources.data.items.length === 0 ? <Empty>No sources configured.</Empty> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-line">
                  <tr>
                    <th className="th">Source</th><th className="th">Type</th><th className="th">Health</th>
                    <th className="th">Last run</th><th className="th">Last OK</th><th className="th">Assets</th>
                    <th className="th">Duration</th><th className="th">Error / warning</th><th className="th"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {sources.data.items.map((s) => {
                    const h = syncHealth(s);
                    return (
                      <tr key={s.source} className={`border-b border-line/60 ${h === 'failing' ? 'bg-bad/5' : h === 'stale' ? 'bg-warn/5' : ''}`}>
                        <td className="td font-medium">{s.source}</td>
                        <td className="td text-xs">{s.type}</td>
                        <td className="td"><SourceStatus s={s} /></td>
                        <td className="td text-xs" title={absTime(s.last_run)}>{relTime(s.last_run)}</td>
                        <td className="td text-xs" title={absTime(s.last_ok)}>{relTime(s.last_ok)}</td>
                        <td className="td tabular-nums">{s.asset_count}</td>
                        <td className="td text-xs">{fmtDuration(s.duration_ms)}</td>
                        <td className="td max-w-xs break-words text-xs">
                          {s.error ? <span className="text-bad">{s.error}</span> : s.warning ? <span className="text-warn">{s.warning}</span> : null}
                        </td>
                        <td className="td">
                          <button
                            className="btn btn-sm"
                            disabled={!canWrite || (sync.isPending && sync.variables === s.source)}
                            title={canWrite ? undefined : 'Read-only access'}
                            aria-label={`Sync ${s.source} now`}
                            onClick={() => sync.mutate(s.source)}
                          >
                            <RefreshCw size={12} aria-hidden="true" /> Sync now
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ))}
          {sync.isError && <p role="alert" className="px-3 pb-2 text-sm text-bad">Sync failed: {(sync.error as Error).message}</p>}
          {sync.isSuccess && <p role="status" className="px-3 pb-2 text-sm text-ok">Sync triggered for {sync.variables}.</p>}
        </Card>

        <Card title="Recent scan runs">
          {scans.isLoading && <Loading />}
          {scans.isError && <ErrorBox error={scans.error} onRetry={() => void scans.refetch()} />}
          {scans.data && (scans.data.items.length === 0 ? <Empty>No scans yet.</Empty> : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="border-b border-line">
                    <tr>
                      <th className="th">Started</th><th className="th">Check</th><th className="th">Tier</th><th className="th">Asset</th>
                      <th className="th">Findings</th><th className="th">Duration</th><th className="th">Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.data.items.map((r) => (
                      <tr key={r.id} className={`border-b border-line/60 ${r.error ? 'bg-bad/5' : ''}`}>
                        <td className="td text-xs" title={absTime(r.started_at)}>{relTime(r.started_at)}</td>
                        <td className="td font-mono text-xs">{r.check}</td>
                        <td className="td text-xs">{r.tier}</td>
                        <td className="td text-xs"><Link className="text-accent hover:underline" to={`/assets/${r.asset_id}`}>#{r.asset_id}</Link></td>
                        <td className="td tabular-nums">{r.findings}</td>
                        <td className="td text-xs">{fmtDuration(r.duration_ms)}</td>
                        <td className="td max-w-md break-words text-xs">
                          {r.error ? <span className="text-bad">Error: {r.error}</span> : <span className="text-ok">OK</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination total={scans.data.total} limit={scans.data.limit || LIMIT} offset={scans.data.offset} onPage={setPage} />
            </>
          ))}
        </Card>
      </div>
    </>
  );
}
