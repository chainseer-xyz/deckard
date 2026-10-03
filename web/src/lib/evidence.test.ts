import { describe, expect, it } from 'vitest';
import { diffData, evidenceRows } from './evidence';

const kinds = (ev: Record<string, unknown>) => Object.fromEntries(evidenceRows(ev).map((r) => [r.key, r.kind]));

describe('evidenceRows', () => {
  it('classifies the known keys', () => {
    expect(
      kinds({
        host: 'promo.example.com',
        cname_target: 'x.azurewebsites.net',
        served_by: 'nginx',
        not_after: '2026-10-08T00:00:00Z',
        days_remaining: 6,
        ports: [22, 443],
        port: 22,
        cname_chain: ['a', 'b'],
        target_in_owned_zone: false,
        tags: ['a', 'b'],
        note: 'plain',
      }),
    ).toEqual({
      host: 'host',
      cname_target: 'host',
      served_by: 'host',
      not_after: 'time',
      days_remaining: 'days',
      ports: 'ports',
      port: 'ports',
      cname_chain: 'chain',
      target_in_owned_zone: 'bool',
      tags: 'list',
      note: 'text',
    });
  });

  it('uses friendly labels for known keys and title-cases the rest', () => {
    const rows = evidenceRows({ cname_target: 'x', not_after: '2026-10-08T00:00:00Z', some_key: 1 });
    expect(rows.map((r) => r.label)).toEqual(['CNAME target', 'Expires', 'Some key']);
  });

  it('treats any ISO timestamp as a time, even under an unknown key', () => {
    expect(kinds({ rotated_at: '2026-09-01T10:00:00Z' }).rotated_at).toBe('time');
    expect(kinds({ rotated_at: 'yesterday' }).rotated_at).toBe('text');
  });

  it('flattens nested objects to dotted keys but stops at the depth limit', () => {
    const rows = evidenceRows({ observed: { port: 443, protocol: 'tcp' }, deep: { a: { b: { c: 1 } } } });
    expect(rows.map((r) => r.key)).toEqual(['observed.port', 'observed.protocol', 'deep.a.b']);
    expect(rows[0]?.kind).toBe('ports');
    expect(rows[2]?.value).toEqual({ c: 1 });
  });

  it('hides the keys shown by the exploit-intelligence panel', () => {
    const rows = evidenceRows({ matched: 'u', kev: true, kev_date_added: '2021-12-10', epss: 0.9, epss_percentile: 0.9 });
    expect(rows.map((r) => r.key)).toEqual(['matched']);
  });

  it('handles empty and missing evidence', () => {
    expect(evidenceRows(undefined)).toEqual([]);
    expect(evidenceRows({})).toEqual([]);
  });
});

describe('diffData', () => {
  it('marks changed, new and gone keys', () => {
    const d = diffData({ a: [1], same: 'x', old: 1 }, { a: [1, 2], same: 'x', fresh: true });
    expect([...d.entries()].sort()).toEqual([
      ['a', 'changed'],
      ['fresh', 'new'],
      ['old', 'gone'],
    ]);
  });
  it('is empty without both sides', () => {
    expect(diffData(undefined, { a: 1 }).size).toBe(0);
  });
});
