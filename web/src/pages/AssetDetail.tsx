import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, ArrowRight, Network, RefreshCw } from 'lucide-react';
import { useAsset, useMe, useRescan } from '../api/hooks';
import { Card, Empty, ErrorBox, Field, JsonViewer, KindBadge, Loading, PageHeader, ScopeBadge } from '../components/ui';
import { FindingsTable } from '../components/FindingsTable';
import { absTime, relTime } from '../lib/format';

export default function AssetDetail() {
  const id = Number(useParams().id);
  const q = useAsset(id);
  const me = useMe();
  const rescan = useRescan();
  const navigate = useNavigate();

  if (q.isLoading) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => void q.refetch()} />;
  if (!q.data) return null;
  const { asset, edges, observations, baselines, findings } = q.data;
  const canWrite = me.data?.can_write ?? false;

  return (
    <>
      <p className="mb-2 text-xs">
        <Link to="/inventory" className="text-accent hover:underline">Inventory</Link> / asset #{asset.id}
      </p>
      <PageHeader title={asset.key}>
        <Link className="btn btn-sm" to={`/inventory?view=map&asset=${asset.id}`}>
          <Network size={12} aria-hidden="true" /> Map
        </Link>
        <button
          className="btn btn-sm btn-primary"
          disabled={!canWrite || rescan.isPending}
          title={canWrite ? undefined : 'Read-only access'}
          onClick={() => rescan.mutate(asset.id)}
        >
          <RefreshCw size={12} aria-hidden="true" /> Rescan now
        </button>
      </PageHeader>
      <div role="status" aria-live="polite" className="mb-2 text-sm">
        {rescan.isSuccess && <span className="text-ok">Rescan queued.</span>}
        {rescan.isError && <span role="alert" className="text-bad">Rescan failed: {(rescan.error as Error).message}</span>}
      </div>

      <div className="space-y-4">
        <Card title="Overview">
          <dl className="grid grid-cols-2 gap-3 p-3 md:grid-cols-4">
            <Field label="Kind"><KindBadge kind={asset.kind} /></Field>
            <Field label="Scope"><ScopeBadge scope={asset.scope} /></Field>
            <Field label="Source">{asset.source}</Field>
            <Field label="Zone">{asset.zone ?? '-'}</Field>
            <Field label="First seen">{absTime(asset.first_seen)}</Field>
            <Field label="Last seen">{relTime(asset.last_seen)}</Field>
            <Field label="Status">{asset.removed_at ? `Removed ${relTime(asset.removed_at)}` : 'Active'}</Field>
          </dl>
          {asset.attrs && Object.keys(asset.attrs).length > 0 && (
            <div className="border-t border-line p-3">
              <JsonViewer value={asset.attrs} label="Asset attributes" />
            </div>
          )}
        </Card>

        <Card title={`Open findings (${findings.length})`}>
          <FindingsTable items={findings} compact onOpen={(f) => navigate(`/findings?finding=${f.id}`)} />
        </Card>

        <Card title={`Relations (${edges.length})`}>
          {edges.length === 0 ? (
            <Empty>No relations.</Empty>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b border-line">
                <tr><th className="th">Direction</th><th className="th">Relation</th><th className="th">Asset</th><th className="th">Scope</th></tr>
              </thead>
              <tbody>
                {edges.map((e, i) => (
                  <tr key={`${e.other.id}-${e.type}-${i}`} className="border-b border-line/60">
                    <td className="td">
                      {e.outbound ? <ArrowRight size={14} aria-label="outbound" /> : <ArrowLeft size={14} aria-label="inbound" />}
                    </td>
                    <td className="td font-mono text-xs">{e.type}</td>
                    <td className="td font-mono text-xs">
                      <KindBadge kind={e.other.kind} />{' '}
                      <Link className="text-accent hover:underline" to={`/assets/${e.other.id}`}>{e.other.key}</Link>
                    </td>
                    <td className="td"><ScopeBadge scope={e.other.scope} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Latest observations">
            {observations.length === 0 && <Empty>No observations yet.</Empty>}
            {observations.map((o) => (
              <details key={o.check} className="border-b border-line px-3 py-2 last:border-b-0">
                <summary className="cursor-pointer text-sm">
                  <span className="font-mono text-xs font-semibold">{o.check}</span>{' '}
                  <span className="text-xs text-muted" title={absTime(o.observed_at)}>{relTime(o.observed_at)}</span>
                </summary>
                <div className="mt-2"><JsonViewer value={o.data} label={`Observation ${o.check}`} /></div>
              </details>
            ))}
          </Card>
          <Card title="Baselines">
            {baselines.length === 0 && <Empty>No baselines learned yet.</Empty>}
            {baselines.map((b) => (
              <details key={b.check} className="border-b border-line px-3 py-2 last:border-b-0">
                <summary className="cursor-pointer text-sm">
                  <span className="font-mono text-xs font-semibold">{b.check}</span>{' '}
                  <span className={`text-xs ${b.stable ? 'text-ok' : 'text-warn'}`}>
                    {b.stable ? 'stable' : `learning (${b.consistent})`}
                  </span>
                </summary>
                <div className="mt-2"><JsonViewer value={b.data} label={`Baseline ${b.check}`} /></div>
              </details>
            ))}
          </Card>
        </div>
      </div>
    </>
  );
}
