import { describe, expect, it } from 'vitest';
import {
  findingMarkdown,
  groupFindings,
  isExpiry,
  isKev,
  isNew24h,
  isTakeover,
  needsAttention,
  remediationHint,
  topBy,
} from './triage';
import type { Finding } from '../api/types';

const NOW = Date.parse('2026-10-02T12:00:00Z');
const ago = (h: number) => new Date(NOW - h * 3600_000).toISOString();

let n = 0;
const mk = (p: Partial<Finding>): Finding => ({
  id: ++n,
  fingerprint: `fp${n}`,
  check: 'http.headers',
  asset_id: 1,
  asset_key: 'a.example.com',
  zone: 'example.com',
  severity: 'low',
  title: 'something',
  description: '',
  status: 'open',
  first_seen: ago(48),
  last_seen: ago(1),
  missed_runs: 0,
  reopened_count: 0,
  ...p,
});

describe('classifiers', () => {
  it('detects takeover by tag or check name', () => {
    expect(isTakeover(mk({ tags: ['dns', 'takeover'] }))).toBe(true);
    expect(isTakeover(mk({ check: 'dns.takeover' }))).toBe(true);
    expect(isTakeover(mk({ check: 'dns.dangling', tags: ['hygiene'] }))).toBe(false);
  });
  it('detects expiry from the certificate evidence or the title', () => {
    expect(isExpiry(mk({ check: 'tls.cert', evidence: { not_after: '2026-10-08T00:00:00Z' } }))).toBe(true);
    expect(isExpiry(mk({ title: 'TLS certificate on x expires in 6 days' }))).toBe(true);
    expect(isExpiry(mk({ title: 'Missing HSTS header' }))).toBe(false);
  });
  it('detects kev from tag or evidence, and new-in-24h from first_seen', () => {
    expect(isKev(mk({ tags: ['cve', 'KEV'] }))).toBe(true);
    expect(isKev(mk({ evidence: { kev: true } }))).toBe(true);
    expect(isKev(mk({}))).toBe(false);
    expect(isNew24h({ first_seen: ago(3) }, NOW)).toBe(true);
    expect(isNew24h({ first_seen: ago(30) }, NOW)).toBe(false);
  });
});

describe('needsAttention', () => {
  const crit = mk({ severity: 'critical', title: 'crit rce', first_seen: ago(10) });
  const critOld = mk({ severity: 'critical', title: 'crit old', first_seen: ago(200) });
  const high = mk({ severity: 'high', title: 'high' });
  const takeover = mk({ severity: 'high', title: 'takeover', check: 'dns.takeover', tags: ['takeover'] });
  const takeoverCrit = mk({ severity: 'critical', title: 'takeover crit', check: 'dns.takeover', tags: ['takeover'] });
  const expiry = mk({ severity: 'high', title: 'cert expires in 3 days', check: 'tls.cert', evidence: { not_after: ago(-72) } });
  const kevMedium = mk({ severity: 'medium', title: 'kev medium', tags: ['kev'] });
  const medium = mk({ severity: 'medium', title: 'medium' });
  const acked = mk({ severity: 'critical', title: 'acked', status: 'acknowledged' });

  it('keeps only open critical/high or kev findings', () => {
    const out = needsAttention([medium, acked, high, kevMedium, mk({ severity: 'low' })]);
    expect(out.map((f) => f.title)).toEqual(['high', 'kev medium']);
  });

  it('orders takeover first, then expiry, then the rest by severity, kev, age', () => {
    const out = needsAttention([high, kevMedium, crit, expiry, takeover, critOld, takeoverCrit]);
    expect(out.map((f) => f.title)).toEqual([
      'takeover crit',
      'takeover',
      'cert expires in 3 days',
      'crit old', // oldest critical before the newer one
      'crit rce',
      'high',
      'kev medium',
    ]);
  });
});

describe('remediationHint', () => {
  it('uses the first sentence of the remediation', () => {
    expect(remediationHint(mk({ remediation: 'Renew the certificate now. Then verify the pipeline.' }))).toBe('Renew the certificate now.');
  });
  it('truncates a long sentence', () => {
    const h = remediationHint(mk({ remediation: `${'word '.repeat(60)}end.` }), 40);
    expect(h.length).toBeLessThanOrEqual(40);
    expect(h.endsWith('…')).toBe(true);
  });
  it('falls back by finding type', () => {
    expect(remediationHint(mk({ tags: ['takeover'] }))).toMatch(/dangling DNS record/);
    expect(remediationHint(mk({ title: 'cert expires soon' }))).toMatch(/Renew/);
    expect(remediationHint(mk({ tags: ['kev'] }))).toMatch(/Patch/);
    expect(remediationHint(mk({}))).toMatch(/Open the finding/);
  });
});

describe('groupFindings', () => {
  const items = [
    mk({ asset_key: 'a', check: 'c1', severity: 'low', zone: 'z1' }),
    mk({ asset_key: 'b', check: 'c1', severity: 'critical', zone: 'z1' }),
    mk({ asset_key: 'a', check: 'c2', severity: 'medium', zone: '' }),
    mk({ asset_key: 'a', check: 'c1', severity: 'low', zone: 'z2' }),
  ];
  it('groups by asset with counts, worst group first', () => {
    const g = groupFindings(items, 'asset');
    expect(g.map((x) => [x.key, x.items.length, x.top])).toEqual([
      ['b', 1, 'critical'],
      ['a', 3, 'medium'],
    ]);
    expect(g[1]?.counts).toMatchObject({ low: 2, medium: 1, critical: 0 });
  });
  it('groups by check and by zone, labelling an empty zone', () => {
    expect(groupFindings(items, 'check').map((x) => x.key)).toEqual(['c1', 'c2']);
    const z = groupFindings(items, 'zone');
    expect(z.map((x) => x.label)).toEqual(['z1', '(no zone)', 'z2']);
  });
});

describe('topBy', () => {
  it('counts open findings above low per field and ignores the rest', () => {
    const items = [
      mk({ zone: 'a', severity: 'high' }),
      mk({ zone: 'a', severity: 'medium' }),
      mk({ zone: 'b', severity: 'critical' }),
      mk({ zone: 'b', severity: 'low' }),
      mk({ zone: 'b', severity: 'high', status: 'suppressed' }),
    ];
    expect(topBy(items, 'zone')).toEqual([
      { key: 'a', count: 2 },
      { key: 'b', count: 1 },
    ]);
    expect(topBy(items, 'zone', 'info').find((t) => t.key === 'b')?.count).toBe(2);
    expect(topBy(items, 'zone', 'medium', 1)).toHaveLength(1);
  });
});

describe('findingMarkdown', () => {
  it('produces a ticket-ready summary', () => {
    const md = findingMarkdown(
      mk({
        severity: 'critical',
        title: 'Dangling CNAME',
        asset_key: 'promo.example.com',
        check: 'dns.takeover',
        description: 'desc here',
        remediation: 'fix it',
        tags: ['dns'],
        reopened_count: 2,
        evidence: { cname: 'x.azurewebsites.net', ports: [80, 443] },
      }),
      () => 'T',
      'https://d.example/findings?finding=1',
    );
    expect(md).toContain('## [CRITICAL] Dangling CNAME');
    expect(md).toContain('- **Asset:** `promo.example.com`');
    expect(md).toContain('- **Reopened:** 2x');
    expect(md).toContain('https://d.example/findings?finding=1');
    expect(md).toContain('### Remediation\n\nfix it');
    expect(md).toContain('- `cname`: x.azurewebsites.net');
    expect(md).toContain('- `ports`: [80,443]');
  });
});
