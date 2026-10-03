import { describe, expect, it } from 'vitest';
import {
  applyExactSeverity,
  defaultFilter,
  pageOf,
  parseFilter,
  sortFindings,
  toApiParams,
  toSearchParams,
  untilToISO,
  validateSuppress,
  withoutSeverity,
} from './findingsFilter';
import type { Finding } from '../api/types';

const sp = (s: string) => new URLSearchParams(s);

describe('findings filter URL state', () => {
  it('defaults to open findings at medium and above, sorted by severity', () => {
    const f = parseFilter(sp(''));
    expect(f).toEqual(defaultFilter);
    expect(f.minSeverity).toBe('medium');
    expect(toSearchParams(f).toString()).toBe('');
    expect(toApiParams(f)).toMatchObject({ status: ['open'], min_severity: 'medium' });
  });

  it('round-trips a full filter through the URL', () => {
    const q =
      'status=open&status=suppressed&min_severity=high&check=tls.cert&zone=example.com&source=cf&asset_id=12&q=cert&group=zone&sort=last_seen&dir=asc&page=3';
    const f = parseFilter(sp(q));
    expect(f).toMatchObject({
      status: ['open', 'suppressed'],
      minSeverity: 'high',
      check: 'tls.cert',
      zone: 'example.com',
      source: 'cf',
      assetId: 12,
      q: 'cert',
      groupBy: 'zone',
      sort: 'last_seen',
      dir: 'asc',
      page: 3,
    });
    expect(parseFilter(toSearchParams(f))).toEqual(f);
    expect(toApiParams(f)).toMatchObject({ asset_id: 12, min_severity: 'high', check: 'tls.cert', zone: 'example.com' });
  });

  it('keeps the low-and-info toggle in the URL', () => {
    const all = parseFilter(sp('min_severity=info'));
    expect(all.minSeverity).toBe('info');
    expect(toApiParams(all).min_severity).toBeUndefined(); // info == no floor
    expect(toSearchParams(all).get('min_severity')).toBe('info');
    expect(parseFilter(sp('min_severity=any')).minSeverity).toBe('info');
    // medium is the default, so it is not written
    expect(toSearchParams({ ...defaultFilter, minSeverity: 'medium' }).has('min_severity')).toBe(false);
  });

  it('an exact severity wins over the floor and is applied client-side', () => {
    const f = parseFilter(sp('severity=high'));
    expect(f.severity).toBe('high');
    expect(toApiParams(f).min_severity).toBe('high');
    expect(parseFilter(toSearchParams(f))).toEqual(f);
    const items = [{ severity: 'critical' }, { severity: 'high' }, { severity: 'high' }] as Finding[];
    expect(applyExactSeverity(items, f)).toHaveLength(2);
    expect(applyExactSeverity(items, defaultFilter)).toHaveLength(3);
  });

  it('status=any removes the status filter and round-trips', () => {
    const f = parseFilter(sp('status=any'));
    expect(f.status).toEqual([]);
    expect(toApiParams(f).status).toBeUndefined();
    expect(toSearchParams(f).get('status')).toBe('any');
  });

  it('withoutSeverity lifts the floor for the "of M" total', () => {
    const p = toApiParams(parseFilter(sp('min_severity=high&check=x')));
    expect(withoutSeverity(p)).toMatchObject({ check: 'x', status: ['open'] });
    expect(withoutSeverity(p).min_severity).toBeUndefined();
  });

  it('ignores junk values', () => {
    const f = parseFilter(sp('status=bogus&min_severity=urgent&severity=x&page=-4&asset_id=abc&sort=x&group=planet'));
    expect(f.minSeverity).toBe('medium');
    expect(f.severity).toBeUndefined();
    expect(f.page).toBe(1);
    expect(f.assetId).toBeUndefined();
    expect(f.sort).toBe('severity');
    expect(f.groupBy).toBe('none');
    expect(f.status).toEqual([]);
  });
});

const mk = (id: number, severity: Finding['severity'], first_seen: string, last_seen = first_seen): Finding =>
  ({ id, severity, first_seen, last_seen }) as Finding;

describe('sortFindings', () => {
  const items = [
    mk(1, 'low', '2026-01-03T00:00:00Z', '2026-02-01T00:00:00Z'),
    mk(2, 'critical', '2026-01-02T00:00:00Z', '2026-02-03T00:00:00Z'),
    mk(3, 'high', '2026-01-01T00:00:00Z', '2026-02-02T00:00:00Z'),
  ];
  it('sorts by severity', () => {
    expect(sortFindings(items, 'severity', 'desc').map((f) => f.id)).toEqual([2, 3, 1]);
    expect(sortFindings(items, 'severity', 'asc').map((f) => f.id)).toEqual([1, 3, 2]);
  });
  it('breaks severity ties by most recently seen', () => {
    const tie = [mk(1, 'high', 'x', '2026-01-01T00:00:00Z'), mk(2, 'high', 'x', '2026-03-01T00:00:00Z')];
    expect(sortFindings(tie, 'severity', 'desc').map((f) => f.id)).toEqual([2, 1]);
    expect(sortFindings(tie, 'severity', 'asc').map((f) => f.id)).toEqual([2, 1]);
  });
  it('sorts by first seen, newest first when descending', () => {
    expect(sortFindings(items, 'first_seen', 'desc').map((f) => f.id)).toEqual([1, 2, 3]);
    expect(sortFindings(items, 'first_seen', 'asc').map((f) => f.id)).toEqual([3, 2, 1]);
  });
  it('sorts by last seen', () => {
    expect(sortFindings(items, 'last_seen', 'desc').map((f) => f.id)).toEqual([2, 3, 1]);
    expect(sortFindings(items, 'last_seen', 'asc').map((f) => f.id)).toEqual([1, 3, 2]);
  });
});

describe('pageOf', () => {
  it('slices 1-based pages', () => {
    const xs = Array.from({ length: 120 }, (_, i) => i);
    expect(pageOf(xs, 1)).toHaveLength(50);
    expect(pageOf(xs, 3)[0]).toBe(100);
    expect(pageOf(xs, 3)).toHaveLength(20);
    expect(pageOf(xs, 9)).toEqual([]);
  });
});

describe('validateSuppress', () => {
  const now = new Date('2026-06-01T12:00:00');
  it('requires a non-blank reason', () => {
    expect(validateSuppress({ note: '   ', until: '' }, now).note).toBeTruthy();
    expect(validateSuppress({ note: 'accepted risk', until: '' }, now)).toEqual({});
  });
  it('rejects past expiry and accepts future', () => {
    expect(validateSuppress({ note: 'x', until: '2026-05-01' }, now).until).toBeTruthy();
    expect(validateSuppress({ note: 'x', until: '2026-07-01' }, now)).toEqual({});
  });
  it('converts expiry to ISO', () => {
    expect(untilToISO('')).toBeUndefined();
    expect(untilToISO('2026-07-01')).toMatch(/^2026-07-0[12]T/);
  });
});
