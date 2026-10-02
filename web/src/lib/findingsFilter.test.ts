import { describe, expect, it } from 'vitest';
import {
  defaultFilter,
  parseFilter,
  sortFindings,
  toApiParams,
  toSearchParams,
  untilToISO,
  validateSuppress,
} from './findingsFilter';
import type { Finding } from '../api/types';

const sp = (s: string) => new URLSearchParams(s);

describe('findings filter URL state', () => {
  it('defaults to open findings sorted by severity', () => {
    const f = parseFilter(sp(''));
    expect(f).toEqual(defaultFilter);
    expect(toSearchParams(f).toString()).toBe('');
    expect(toApiParams(f)).toMatchObject({ status: ['open'], limit: 50, offset: 0 });
  });

  it('round-trips a full filter', () => {
    const q =
      'status=open&status=suppressed&min_severity=high&check=tls&zone=example.com&source=cf&asset_id=12&q=cert&sort=age&dir=asc&page=3';
    const f = parseFilter(sp(q));
    expect(f).toMatchObject({
      status: ['open', 'suppressed'],
      minSeverity: 'high',
      check: 'tls',
      assetId: 12,
      sort: 'age',
      dir: 'asc',
      page: 3,
    });
    expect(parseFilter(toSearchParams(f))).toEqual(f);
    expect(toApiParams(f)).toMatchObject({ offset: 100, asset_id: 12, min_severity: 'high' });
  });

  it('status=any removes the status filter and round-trips', () => {
    const f = parseFilter(sp('status=any'));
    expect(f.status).toEqual([]);
    expect(toApiParams(f).status).toBeUndefined();
    expect(toSearchParams(f).get('status')).toBe('any');
  });

  it('ignores junk values', () => {
    const f = parseFilter(sp('status=bogus&min_severity=urgent&page=-4&asset_id=abc&sort=x'));
    expect(f.minSeverity).toBeUndefined();
    expect(f.page).toBe(1);
    expect(f.assetId).toBeUndefined();
    expect(f.sort).toBe('severity');
    expect(f.status).toEqual([]);
  });
});

const mk = (id: number, severity: Finding['severity'], first_seen: string): Finding =>
  ({ id, severity, first_seen }) as Finding;

describe('sortFindings', () => {
  const items = [
    mk(1, 'low', '2026-01-03T00:00:00Z'),
    mk(2, 'critical', '2026-01-02T00:00:00Z'),
    mk(3, 'high', '2026-01-01T00:00:00Z'),
  ];
  it('sorts by severity', () => {
    expect(sortFindings(items, 'severity', 'desc').map((f) => f.id)).toEqual([2, 3, 1]);
    expect(sortFindings(items, 'severity', 'asc').map((f) => f.id)).toEqual([1, 3, 2]);
  });
  it('sorts by age, oldest first when descending', () => {
    expect(sortFindings(items, 'age', 'desc').map((f) => f.id)).toEqual([3, 2, 1]);
    expect(sortFindings(items, 'age', 'asc').map((f) => f.id)).toEqual([1, 2, 3]);
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
