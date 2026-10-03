import { describe, expect, it } from 'vitest';
import { assetSources, assetTags, baselineView, isStaleObservation, severityCounts } from './assetView';
import type { Baseline, Finding, Observation } from '../api/types';

const NOW = Date.parse('2026-10-02T12:00:00Z');
const at = (h: number) => new Date(NOW - h * 3600_000).toISOString();

describe('staleness and counts', () => {
  it('flags observations older than 36h', () => {
    expect(isStaleObservation(at(35), NOW)).toBe(false);
    expect(isStaleObservation(at(37), NOW)).toBe(true);
  });
  it('counts open findings per severity only', () => {
    const f = (severity: Finding['severity'], status: Finding['status'] = 'open') => ({ severity, status }) as Finding;
    expect(severityCounts([f('high'), f('high'), f('low'), f('critical', 'suppressed')])).toEqual({
      critical: 0,
      high: 2,
      medium: 0,
      low: 1,
      info: 0,
    });
  });
});

describe('asset tags and sources from attrs', () => {
  it('collects tags and tech, deduplicated, ignoring junk', () => {
    expect(assetTags({ attrs: { tags: ['prod', 'web'], tech: ['nginx', 'prod'], other: 1 } })).toEqual(['prod', 'web', 'nginx']);
    expect(assetTags({})).toEqual([]);
    expect(assetTags({ attrs: { tags: 'nope' } })).toEqual([]);
  });
  it('lists the primary source first, then any extras', () => {
    expect(assetSources({ source: 'aws', attrs: { sources: ['cloudflare', 'aws'] } })).toEqual(['aws', 'cloudflare']);
    expect(assetSources({ source: 'aws' })).toEqual(['aws']);
  });
});

describe('baselineView', () => {
  const baseline = (data: Record<string, unknown>, updatedHoursAgo = 48): Baseline => ({
    asset_id: 1,
    check: 'dns.baseline',
    data,
    stable: true,
    consistent: 5,
    updated_at: at(updatedHoursAgo),
  });
  const obs = (data: Record<string, unknown>, hoursAgo = 1): Observation => ({ asset_id: 1, check: 'dns.baseline', data, observed_at: at(hoursAgo) });

  it('marks changed, new and gone keys and carries the latest value', () => {
    const v = baselineView(baseline({ a: ['1.1.1.1'], ns: ['x'], gone: 1 }), obs({ a: ['1.1.1.1', '2.2.2.2'], ns: ['x'], fresh: true }));
    expect(v.changes).toBe(3);
    expect(v.sinceBaseline).toBe(true);
    const byKey = Object.fromEntries(v.rows.map((r) => [r.key, r]));
    expect(byKey.a).toMatchObject({ change: 'changed', baseline: ['1.1.1.1'], latest: ['1.1.1.1', '2.2.2.2'] });
    expect(byKey.ns?.change).toBeUndefined();
    expect(byKey.gone?.change).toBe('gone');
    expect(byKey.fresh).toMatchObject({ change: 'new', latest: true });
  });

  it('is not "since the baseline" when the observation predates it', () => {
    expect(baselineView(baseline({ a: 1 }, 1), obs({ a: 2 }, 5)).sinceBaseline).toBe(false);
  });

  it('shows the baseline alone without an observation', () => {
    const v = baselineView(baseline({ a: 1 }), undefined);
    expect(v.changes).toBe(0);
    expect(v.rows).toHaveLength(1);
    expect(v.sinceBaseline).toBe(false);
  });
});
