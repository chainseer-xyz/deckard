import { Link, useParams, useSearchParams } from 'react-router-dom';
import { ArrowLeft, ArrowRight, Network, RefreshCw } from 'lucide-react';
import { useAsset, useMe, useRescan } from '../api/hooks';
import { AssetProperties } from '../components/AssetProperties';
import { DnsChainView } from '../components/DnsChainView';
import { FindingDrawer } from '../components/FindingDrawer';
import { FindingsTable } from '../components/FindingsTable';
import { BaselinesCard, ObservationsCard } from '../components/ObservationsPanel';
import { Card, Empty, ErrorBox, KindBadge, Loading, PageHeader, ScopeBadge } from '../components/ui';
import { buildDnsChain } from '../lib/dnsChain';
import { sortFindings } from '../lib/findingsFilter';

export default function AssetDetail() {
  const id = Number(useParams().id);
  const q = useAsset(id);
  const me = useMe();
  const rescan = useRescan();
  const [sp, setSp] = useSearchParams();
  const drawerId = Number(sp.get('finding')) || undefined;

  if (q.isLoading) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => void q.refetch()} />;
  if (!q.data) return null;
  const d = q.data;
  const { asset, edges, observations, baselines, findings } = d;
  const canWrite = me.data?.can_write ?? false;
  const chain = buildDnsChain(d);
  const sorted = sortFindings(findings, 'severity', 'desc');
  const setDrawer = (fid?: number) => {
    const n = new URLSearchParams(sp);
    if (fid) n.set('finding', String(fid));
    else n.delete('finding');
    setSp(n, { replace: !fid });
  };

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
      <div role="status" aria-live="polite" className="mb-2 min-h-5 text-sm">
        {rescan.isSuccess && <span className="text-ok">Rescan queued.</span>}
        {rescan.isError && <span role="alert" className="text-bad">Rescan failed: {(rescan.error as Error).message}</span>}
      </div>

      <div className="space-y-4">
        <AssetProperties d={d} />

        {chain && <DnsChainView chain={chain} />}

        <Card title={`Open findings (${findings.length})`}>
          {findings.length === 0 ? (
            <Empty>No open findings on this asset.</Empty>
          ) : (
            <FindingsTable items={sorted} compact selectedId={drawerId} onOpen={(f) => setDrawer(f.id)} />
          )}
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <ObservationsCard observations={observations} baselines={baselines} />
          <BaselinesCard observations={observations} baselines={baselines} />
        </div>

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
                      {e.other.removed_at && <span className="ml-2 rounded-sm border border-line px-1 text-[10px] uppercase">removed</span>}
                    </td>
                    <td className="td"><ScopeBadge scope={e.other.scope} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {drawerId && <FindingDrawer id={drawerId} seed={findings.find((f) => f.id === drawerId)} onClose={() => setDrawer(undefined)} />}
    </>
  );
}
