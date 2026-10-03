import { Suspense, lazy, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { List, Network } from 'lucide-react';
import { useAllAssets, useAllFindings, useAssets, useGraph, useScans, useStats } from '../api/hooks';
import { ASSET_KINDS, SCOPES } from '../api/types';
import type { AssetKind, ScopeClass } from '../api/types';
import { Card, Empty, ErrorBox, KindBadge, Loading, PageHeader, Pagination, ScopeBadge, SeverityBadge } from '../components/ui';
import { relTime, absTime } from '../lib/format';
import {
  INVENTORY_PAGE_SIZE,
  assetFindingStats,
  hasNeedle,
  lastScanByAsset,
  parseInventory,
  sortByFindings,
  toAssetsApi,
  toInventoryParams,
} from '../lib/inventory';
import type { InventoryFilter } from '../lib/inventory';
import { pageOf } from '../lib/findingsFilter';

const AssetGraph = lazy(() => import('../components/AssetGraph'));
const SCAN_WINDOW = 500;

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
  const filter = useMemo(() => parseInventory(sp), [sp]);
  const apiParams = useMemo(() => toAssetsApi(filter), [filter]);

  // Open findings and recent scan runs feed the findings and last-scanned
  // columns; the API has neither per asset.
  const openFindings = useAllFindings({ status: ['open'] }, view === 'table');
  const scans = useScans(SCAN_WINDOW, 0);
  const findingStats = useMemo(() => assetFindingStats(openFindings.data ?? []), [openFindings.data]);
  const lastScan = useMemo(() => lastScanByAsset(scans.data?.items ?? []), [scans.data]);

  // Plain browsing pages on the server; the "findings >= medium" toggle needs
  // every matching asset to intersect with the findings, so it pages locally.
  const paged = useAssets({ ...apiParams, limit: INVENTORY_PAGE_SIZE, offset: (filter.page - 1) * INVENTORY_PAGE_SIZE });
  const all = useAllAssets(apiParams, filter.needles && view === 'table');
  const needleAssets = useMemo(
    () => (all.data ? sortByFindings(all.data.filter((a) => hasNeedle(findingStats.get(a.id))), findingStats) : []),
    [all.data, findingStats],
  );
  const q = filter.needles ? all : paged;
  const rows = useMemo(
    () => (filter.needles ? pageOf(needleAssets, filter.page, INVENTORY_PAGE_SIZE) : (paged.data?.items ?? [])),
    [filter.needles, filter.page, needleAssets, paged.data],
  );
  const total = filter.needles ? needleAssets.length : (paged.data?.total ?? 0);
  const waitingOnFindings = filter.needles && openFindings.isLoading;

  const set = (patch: Partial<InventoryFilter>, keepPage = false) =>
    setSp(toInventoryParams({ ...filter, ...patch, page: keepPage ? (patch.page ?? filter.page) : 1 }, sp), { replace: true });
  const setView = (v: string | undefined) => {
    const n = new URLSearchParams(sp);
    if (v) n.set('view', v);
    else n.delete('view');
    setSp(n, { replace: true });
  };
  const setMap = (patch: Record<string, string>) => {
    const n = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) n.set(k, v);
    setSp(n, { replace: true });
  };

  const [text, setText] = useState(filter.q);
  useEffect(() => setText(filter.q), [filter.q]);
  useEffect(() => {
    if (text === filter.q) return;
    const t = setTimeout(() => set({ q: text }), 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text]);

  const sources = Object.keys(stats.data?.assets_by_source ?? {});
  const zones = useMemo(
    () => [...new Set([...(openFindings.data ?? []).map((f) => f.zone), ...rows.map((a) => a.zone)].filter((z): z is string => !!z))].sort(),
    [openFindings.data, rows],
  );
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
              onClick={() => setView(v === 'map' ? 'map' : undefined)}
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
          onPick={(id) => setMap({ asset: String(id) })}
          onDepth={(d) => setMap({ depth: String(d) })}
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
                <select id="i-kind" className="input" value={filter.kind ?? ''} onChange={(e) => set({ kind: (e.target.value || undefined) as AssetKind | undefined })}>
                  <option value="">Any</option>
                  {ASSET_KINDS.map((k) => <option key={k}>{k}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="i-scope" className="mb-1 block text-xs text-muted">Scope</label>
                <select id="i-scope" className="input" value={filter.scope ?? ''} onChange={(e) => set({ scope: (e.target.value || undefined) as ScopeClass | undefined })}>
                  <option value="">Any</option>
                  {SCOPES.map((k) => <option key={k}>{k}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="i-src" className="mb-1 block text-xs text-muted">Source</label>
                <select id="i-src" className="input" value={filter.source} onChange={(e) => set({ source: e.target.value })}>
                  <option value="">Any</option>
                  {filter.source && !sources.includes(filter.source) && <option>{filter.source}</option>}
                  {sources.map((k) => <option key={k}>{k}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="i-zone" className="mb-1 block text-xs text-muted">Zone</label>
                <input
                  id="i-zone"
                  className="input w-40"
                  list="i-zones"
                  defaultValue={filter.zone}
                  key={filter.zone}
                  onBlur={(e) => e.target.value !== filter.zone && set({ zone: e.target.value })}
                  onKeyDown={(e) => { if (e.key === 'Enter') set({ zone: e.currentTarget.value }); }}
                />
                <datalist id="i-zones">{zones.map((z) => <option key={z} value={z} />)}</datalist>
              </div>
              <label className="flex items-center gap-1.5 pb-1 text-sm">
                <input type="checkbox" checked={filter.needles} onChange={(e) => set({ needles: e.target.checked })} />
                Has open findings ≥ medium
              </label>
              <label className="flex items-center gap-1.5 pb-1 text-sm">
                <input type="checkbox" checked={filter.includeRemoved} onChange={(e) => set({ includeRemoved: e.target.checked })} />
                Include removed
              </label>
            </form>
          </Card>
          <Card>
            {(q.isLoading || waitingOnFindings) && <Loading />}
            {q.isError && <ErrorBox error={q.error} onRetry={() => void q.refetch()} />}
            {q.data && !waitingOnFindings && (
              <>
                {rows.length === 0 ? (
                  <Empty>
                    {filter.needles
                      ? 'No assets with an open finding at medium or above match these filters.'
                      : 'No assets match. Clear a filter, or check that a source has synced (Sources & Scans).'}
                  </Empty>
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
                          <th className="th">Open findings</th>
                          <th className="th">Last scanned</th>
                          <th className="th">Last seen</th>
                          <th className="th"><span className="sr-only">Map</span></th>
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((a) => {
                          const fs = findingStats.get(a.id);
                          const scanned = lastScan.get(a.id);
                          return (
                            <tr key={a.id} className={`border-b border-line/60 hover:bg-surface2/50 ${a.removed_at ? 'opacity-60' : ''}`}>
                              <td className="td"><KindBadge kind={a.kind} /></td>
                              <td className="td font-mono text-xs">
                                <Link className="text-accent hover:underline" to={`/assets/${a.id}`}>{a.key}</Link>
                                {a.removed_at && <span className="ml-2 rounded-sm border border-line px-1 text-[10px] uppercase">removed</span>}
                              </td>
                              <td className="td"><ScopeBadge scope={a.scope} /></td>
                              <td className="td text-xs">{a.source}</td>
                              <td className="td text-xs">{a.zone ?? '-'}</td>
                              <td className="td min-w-28 text-xs">
                                {openFindings.isLoading ? (
                                  <span className="text-muted">…</span>
                                ) : fs ? (
                                  <Link
                                    to={`/findings?asset_id=${a.id}&min_severity=info`}
                                    className="inline-flex items-center gap-1.5 hover:underline"
                                    aria-label={`${fs.total} open findings on ${a.key}, worst ${fs.top}`}
                                  >
                                    <SeverityBadge severity={fs.top} />
                                    <span className="tabular-nums">{fs.total}</span>
                                  </Link>
                                ) : (
                                  <span className="text-muted">0</span>
                                )}
                              </td>
                              <td className="td whitespace-nowrap text-xs text-muted" title={scanned ? absTime(scanned) : 'No scan in the most recent runs'}>
                                {scanned ? relTime(scanned) : '-'}
                              </td>
                              <td className="td whitespace-nowrap text-xs text-muted" title={absTime(a.last_seen)}>{relTime(a.last_seen)}</td>
                              <td className="td">
                                <Link className="btn btn-sm" to={`/inventory?view=map&asset=${a.id}`} aria-label={`Show ${a.key} on map`}>
                                  <Network size={12} aria-hidden="true" /> Map
                                </Link>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                <Pagination total={total} limit={INVENTORY_PAGE_SIZE} offset={(filter.page - 1) * INVENTORY_PAGE_SIZE} onPage={(p) => set({ page: p }, true)} />
              </>
            )}
          </Card>
        </>
      )}
    </>
  );
}
