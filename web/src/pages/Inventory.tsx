import { Suspense, lazy, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { List, Network } from 'lucide-react';
import { useAssets, useGraph, useStats } from '../api/hooks';
import { ASSET_KINDS, SCOPES } from '../api/types';
import { Card, Empty, ErrorBox, KindBadge, Loading, PageHeader, Pagination, ScopeBadge } from '../components/ui';
import { relTime, absTime } from '../lib/format';

const AssetGraph = lazy(() => import('../components/AssetGraph'));
const LIMIT = 50;

function MapView({ assetId, depth, onPick, onDepth }: { assetId?: number; depth: number; onPick: (id: number) => void; onDepth: (d: number) => void }) {
  const [text, setText] = useState('');
  const [debounced, setDebounced] = useState('');
  useEffect(() => {
    const t = setTimeout(() => setDebounced(text), 250);
    return () => clearTimeout(t);
  }, [text]);
  const results = useAssets({ q: debounced, limit: 8 });
  const graph = useGraph(assetId, depth);

  return (
    <div className="grid gap-4 lg:grid-cols-[18rem_1fr]">
      <Card title="Pick an asset">
        <div className="space-y-2 p-3">
          <label htmlFor="map-q" className="sr-only">Search assets</label>
          <input id="map-q" type="search" className="input w-full" placeholder="Search hostname, IP…" value={text} onChange={(e) => setText(e.target.value)} />
          <ul className="max-h-80 divide-y divide-line overflow-auto">
            {results.data?.items.map((a) => (
              <li key={a.id}>
                <button
                  className={`block w-full px-1 py-1.5 text-left hover:bg-surface2 ${a.id === assetId ? 'bg-surface2 font-semibold' : ''}`}
                  aria-current={a.id === assetId}
                  onClick={() => onPick(a.id)}
                >
                  <span className="block truncate font-mono text-xs">{a.key}</span>
                  <KindBadge kind={a.kind} />
                </button>
              </li>
            ))}
          </ul>
          <div>
            <label htmlFor="depth" className="mr-2 text-xs text-muted">Depth</label>
            <select id="depth" className="input" value={depth} onChange={(e) => onDepth(Number(e.target.value))}>
              {[1, 2, 3, 4].map((d) => <option key={d}>{d}</option>)}
            </select>
          </div>
        </div>
      </Card>
      <Card title="Neighbourhood" right={assetId ? <Link className="text-xs text-accent hover:underline" to={`/assets/${assetId}`}>Open asset</Link> : undefined}>
        <div className="p-3">
          {!assetId && <Empty>Select an asset to see its neighbourhood.</Empty>}
          {graph.isLoading && <Loading />}
          {graph.isError && <ErrorBox error={graph.error} />}
          {graph.data && (
            <>
              <Suspense fallback={<Loading label="Loading graph" />}>
                <AssetGraph graph={graph.data} focusId={assetId} />
              </Suspense>
              <ul className="mt-2 flex flex-wrap gap-3 text-xs" aria-label="Legend">
                {ASSET_KINDS.map((k) => <li key={k}><KindBadge kind={k} /></li>)}
              </ul>
            </>
          )}
        </div>
      </Card>
    </div>
  );
}

export default function Inventory() {
  const [sp, setSp] = useSearchParams();
  const stats = useStats();
  const view = sp.get('view') === 'map' ? 'map' : 'table';
  const page = Math.max(1, Number(sp.get('page')) || 1);
  const params = {
    kind: sp.get('kind') ?? undefined,
    source: sp.get('source') ?? undefined,
    scope: sp.get('scope') ?? undefined,
    zone: sp.get('zone') ?? undefined,
    q: sp.get('q') ?? undefined,
    include_removed: sp.get('include_removed') === '1',
    limit: LIMIT,
    offset: (page - 1) * LIMIT,
  };
  const assets = useAssets(params);

  const set = (patch: Record<string, string | undefined>, keepPage = false) => {
    const n = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) {
      if (v) n.set(k, v);
      else n.delete(k);
    }
    if (!keepPage) n.delete('page');
    setSp(n, { replace: true });
  };

  const [text, setText] = useState(sp.get('q') ?? '');
  useEffect(() => {
    if (text === (sp.get('q') ?? '')) return;
    const t = setTimeout(() => set({ q: text || undefined }), 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text]);

  const sources = Object.keys(stats.data?.assets_by_source ?? {});
  const assetParam = Number(sp.get('asset')) || undefined;

  return (
    <>
      <PageHeader title="Inventory">
        <div role="tablist" aria-label="View" className="flex gap-1">
          {([['table', 'Table', List], ['map', 'Map', Network]] as const).map(([v, label, Icon]) => (
            <button
              key={v}
              role="tab"
              aria-selected={view === v}
              className={`btn btn-sm ${view === v ? 'border-accent bg-surface2' : ''}`}
              onClick={() => set({ view: v === 'map' ? 'map' : undefined }, true)}
            >
              <Icon size={12} aria-hidden="true" />
              {label}
            </button>
          ))}
        </div>
      </PageHeader>

      {view === 'map' ? (
        <MapView
          assetId={assetParam}
          depth={Number(sp.get('depth')) || 2}
          onPick={(id) => set({ asset: String(id) }, true)}
          onDepth={(d) => set({ depth: String(d) }, true)}
        />
      ) : (
        <>
          <Card className="mb-4">
            <form className="flex flex-wrap items-end gap-3 p-3" role="search" onSubmit={(e) => e.preventDefault()}>
              <div>
                <label htmlFor="i-q" className="mb-1 block text-xs text-muted">Search</label>
                <input id="i-q" type="search" className="input w-56" value={text} onChange={(e) => setText(e.target.value)} placeholder="key contains…" />
              </div>
              <div>
                <label htmlFor="i-kind" className="mb-1 block text-xs text-muted">Kind</label>
                <select id="i-kind" className="input" value={params.kind ?? ''} onChange={(e) => set({ kind: e.target.value || undefined })}>
                  <option value="">Any</option>
                  {ASSET_KINDS.map((k) => <option key={k}>{k}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="i-scope" className="mb-1 block text-xs text-muted">Scope</label>
                <select id="i-scope" className="input" value={params.scope ?? ''} onChange={(e) => set({ scope: e.target.value || undefined })}>
                  <option value="">Any</option>
                  {SCOPES.map((k) => <option key={k}>{k}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="i-src" className="mb-1 block text-xs text-muted">Source</label>
                <select id="i-src" className="input" value={params.source ?? ''} onChange={(e) => set({ source: e.target.value || undefined })}>
                  <option value="">Any</option>
                  {params.source && !sources.includes(params.source) && <option>{params.source}</option>}
                  {sources.map((k) => <option key={k}>{k}</option>)}
                </select>
              </div>
              <label className="flex items-center gap-1.5 pb-1 text-sm">
                <input type="checkbox" checked={params.include_removed} onChange={(e) => set({ include_removed: e.target.checked ? '1' : undefined })} />
                Include removed
              </label>
            </form>
          </Card>
          <Card>
            {assets.isLoading && <Loading />}
            {assets.isError && <ErrorBox error={assets.error} onRetry={() => void assets.refetch()} />}
            {assets.data && (
              <>
                {assets.data.items.length === 0 ? (
                  <Empty>No assets match.</Empty>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead className="border-b border-line">
                        <tr>
                          <th className="th">Kind</th>
                          <th className="th">Key</th>
                          <th className="th">Scope</th>
                          <th className="th">Source</th>
                          <th className="th">Zone</th>
                          <th className="th">Last seen</th>
                          <th className="th"><span className="sr-only">Map</span></th>
                        </tr>
                      </thead>
                      <tbody>
                        {assets.data.items.map((a) => (
                          <tr key={a.id} className={`border-b border-line/60 hover:bg-surface2/50 ${a.removed_at ? 'opacity-60' : ''}`}>
                            <td className="td"><KindBadge kind={a.kind} /></td>
                            <td className="td font-mono text-xs">
                              <Link className="text-accent hover:underline" to={`/assets/${a.id}`}>{a.key}</Link>
                              {a.removed_at && <span className="ml-2 rounded border border-line px-1 text-[10px] uppercase">removed</span>}
                            </td>
                            <td className="td"><ScopeBadge scope={a.scope} /></td>
                            <td className="td text-xs">{a.source}</td>
                            <td className="td text-xs">{a.zone ?? '-'}</td>
                            <td className="td text-xs text-muted" title={absTime(a.last_seen)}>{relTime(a.last_seen)}</td>
                            <td className="td">
                              <Link className="btn btn-sm" to={`/inventory?view=map&asset=${a.id}`} aria-label={`Show ${a.key} on map`}>
                                <Network size={12} aria-hidden="true" /> Map
                              </Link>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <Pagination total={assets.data.total} limit={assets.data.limit || LIMIT} offset={assets.data.offset} onPage={(p) => set({ page: p > 1 ? String(p) : undefined }, true)} />
              </>
            )}
          </Card>
        </>
      )}
    </>
  );
}
