import { describe, expect, it } from 'vitest';
import {
  assetFindingStats,
  defaultInventoryFilter,
  hasNeedle,
  lastScanByAsset,
  parseInventory,
  sortByFindings,
  toAssetsApi,
  toInventoryParams,
} from './inventory';
import type { Asset, Finding, ScanRun } from '../api/types';

const sp = (s: string) => new URLSearchParams(s);

describe('inventory filter URL state', () => {
  it('defaults to nothing set and serialises to an empty query', () => {
    expect(parseInventory(sp(''))).toEqual(defaultInventoryFilter);
    expect(toInventoryParams(defaultInventoryFilter).toString()).toBe('');
  });

  it('round-trips every filter', () => {
    const q = 'kind=hostname&scope=owned&source=cloudflare&zone=example.com&q=www&include_removed=1&needles=1&page=4';
    const f = parseInventory(sp(q));
    expect(f).toEqual({
      kind: 'hostname',
      scope: 'owned',
      source: 'cloudflare',
      zone: 'example.com',
      q: 'www',
      includeRemoved: true,
      needles: true,
      page: 4,
    });
    expect(parseInventory(toInventoryParams(f))).toEqual(f);
    expect(toAssetsApi(f)).toEqual({
      kind: 'hostname',
      scope: 'owned',
      source: 'cloudflare',
      zone: 'example.com',
      q: 'www',
      include_removed: true,
      include_summary: true,
      open_min_severity: 'medium',
    });
  });

  it('keeps unrelated params such as the map view', () => {
    const out = toInventoryParams({ ...defaultInventoryFilter, needles: true }, sp('view=map&asset=3&kind=ip'));
    expect(out.get('view')).toBe('map');
    expect(out.get('asset')).toBe('3');
    expect(out.get('needles')).toBe('1');
    expect(out.has('kind')).toBe(false);
  });

  it('ignores junk', () => {
    const f = parseInventory(sp('kind=toaster&scope=mine&page=-2&needles=yes'));
    expect(f).toEqual(defaultInventoryFilter);
  });
});

const finding = (asset_id: number, severity: Finding['severity'], status: Finding['status'] = 'open') =>
  ({ asset_id, severity, status }) as Finding;

describe('asset finding stats', () => {
  const stats = assetFindingStats([
    finding(1, 'high'),
    finding(1, 'low'),
    finding(2, 'low'),
    finding(2, 'critical', 'suppressed'),
    finding(3, 'medium'),
  ]);
  it('counts open findings per asset and tracks the worst severity', () => {
    expect(stats.get(1)).toMatchObject({ total: 2, top: 'high' });
    expect(stats.get(2)).toMatchObject({ total: 1, top: 'low' }); // suppressed critical ignored
    expect(stats.has(4)).toBe(false);
  });
  it('detects needles at medium and above', () => {
    expect(hasNeedle(stats.get(1))).toBe(true);
    expect(hasNeedle(stats.get(2))).toBe(false);
    expect(hasNeedle(stats.get(3))).toBe(true);
    expect(hasNeedle(undefined)).toBe(false);
    expect(hasNeedle(stats.get(2), 'low')).toBe(true);
  });
  it('sorts worst first, then count, then key', () => {
    const a = (id: number, key: string) => ({ id, key }) as Asset;
    expect(sortByFindings([a(4, 'z'), a(2, 'b'), a(1, 'c'), a(3, 'a')], stats).map((x) => x.id)).toEqual([1, 3, 2, 4]);
  });
});

describe('lastScanByAsset', () => {
  it('keeps the newest run per asset', () => {
    const run = (asset_id: number, started_at: string) => ({ asset_id, started_at }) as ScanRun;
    const m = lastScanByAsset([run(1, '2026-10-01T00:00:00Z'), run(1, '2026-10-02T00:00:00Z'), run(2, '2026-09-30T00:00:00Z')]);
    expect(m.get(1)).toBe('2026-10-02T00:00:00Z');
    expect(m.get(2)).toBe('2026-09-30T00:00:00Z');
    expect(m.has(3)).toBe(false);
  });
});
