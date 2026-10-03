import type { AssetsParams } from '../api/client';
import { ASSET_KINDS, SCOPES, SEVERITIES, severityRank } from '../api/types';
import type { Asset, AssetKind, Finding, ScanRun, ScopeClass, Severity } from '../api/types';
import { emptyCounts } from './triage';

export const INVENTORY_PAGE_SIZE = 50;

export interface InventoryFilter {
  kind?: AssetKind;
  scope?: ScopeClass;
  source: string;
  zone: string;
  q: string;
  includeRemoved: boolean;
  /** only assets with an open finding at medium or above */
  needles: boolean;
  page: number; // 1-based
}

export const defaultInventoryFilter: InventoryFilter = {
  source: '',
  zone: '',
  q: '',
  includeRemoved: false,
  needles: false,
  page: 1,
};

/** URL contract: kind, scope, source, zone, q, include_removed=1, needles=1, page. */
export function parseInventory(sp: URLSearchParams): InventoryFilter {
  const f: InventoryFilter = { ...defaultInventoryFilter };
  const kind = sp.get('kind');
  if (kind && ASSET_KINDS.includes(kind as AssetKind)) f.kind = kind as AssetKind;
  const scope = sp.get('scope');
  if (scope && SCOPES.includes(scope as ScopeClass)) f.scope = scope as ScopeClass;
  f.source = sp.get('source') ?? '';
  f.zone = sp.get('zone') ?? '';
  f.q = sp.get('q') ?? '';
  f.includeRemoved = sp.get('include_removed') === '1';
  f.needles = sp.get('needles') === '1';
  const page = Number(sp.get('page'));
  if (Number.isInteger(page) && page > 1) f.page = page;
  return f;
}

/** Writes only non-default values; leaves unrelated params (view, asset, depth) alone when given `base`. */
export function toInventoryParams(f: InventoryFilter, base?: URLSearchParams): URLSearchParams {
  const sp = new URLSearchParams(base);
  for (const k of ['kind', 'scope', 'source', 'zone', 'q', 'include_removed', 'needles', 'page']) sp.delete(k);
  if (f.kind) sp.set('kind', f.kind);
  if (f.scope) sp.set('scope', f.scope);
  if (f.source) sp.set('source', f.source);
  if (f.zone) sp.set('zone', f.zone);
  if (f.q) sp.set('q', f.q);
  if (f.includeRemoved) sp.set('include_removed', '1');
  if (f.needles) sp.set('needles', '1');
  if (f.page > 1) sp.set('page', String(f.page));
  return sp;
}

export function toAssetsApi(f: InventoryFilter): Omit<AssetsParams, 'limit' | 'offset'> {
  return {
    kind: f.kind,
    scope: f.scope,
    source: f.source || undefined,
    zone: f.zone || undefined,
    q: f.q || undefined,
    include_removed: f.includeRemoved,
  };
}

export interface AssetFindingStats {
  counts: Record<Severity, number>;
  total: number;
  top: Severity;
}

/** Open findings per asset id. */
export function assetFindingStats(findings: Finding[]): Map<number, AssetFindingStats> {
  const m = new Map<number, AssetFindingStats>();
  for (const f of findings) {
    if (f.status !== 'open') continue;
    let s = m.get(f.asset_id);
    if (!s) {
      s = { counts: emptyCounts(), total: 0, top: 'info' };
      m.set(f.asset_id, s);
    }
    s.counts[f.severity] += 1;
    s.total += 1;
    if (severityRank(f.severity) > severityRank(s.top)) s.top = f.severity;
  }
  return m;
}

export const hasNeedle = (s: AssetFindingStats | undefined, min: Severity = 'medium'): boolean =>
  !!s && SEVERITIES.some((v) => severityRank(v) >= severityRank(min) && s.counts[v] > 0);

/** Worst severity first, then most findings, then key. */
export function sortByFindings(assets: Asset[], stats: Map<number, AssetFindingStats>): Asset[] {
  return [...assets].sort((a, b) => {
    const sa = stats.get(a.id);
    const sb = stats.get(b.id);
    return (
      severityRank(sb?.top ?? 'info') - severityRank(sa?.top ?? 'info') ||
      (sb?.total ?? 0) - (sa?.total ?? 0) ||
      a.key.localeCompare(b.key)
    );
  });
}

/** Most recent scan run per asset within the fetched window of runs. */
export function lastScanByAsset(scans: ScanRun[]): Map<number, string> {
  const m = new Map<number, string>();
  for (const r of scans) {
    const cur = m.get(r.asset_id);
    if (!cur || Date.parse(r.started_at) > Date.parse(cur)) m.set(r.asset_id, r.started_at);
  }
  return m;
}
