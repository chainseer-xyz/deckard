import { describe, expect, it } from 'vitest';
import { buildDnsChain } from './dnsChain';
import type { Asset, AssetDetail, AssetEdge, Finding, Observation } from '../api/types';

const asset = (kind: Asset['kind'], key: string, id = 1): Asset =>
  ({ id, kind, key, source: 's', scope: 'owned', first_seen: '', last_seen: '' }) as Asset;
const detail = (p: Partial<AssetDetail> & { asset: Asset }): AssetDetail => ({
  edges: [],
  observations: [],
  baselines: [],
  findings: [],
  ...p,
});
const obs = (check: string, data: Record<string, unknown>): Observation => ({ asset_id: 1, check, data, observed_at: '' });

describe('buildDnsChain', () => {
  it('returns null for non-DNS assets', () => {
    expect(buildDnsChain(detail({ asset: asset('ip', '203.0.113.1') }))).toBeNull();
  });

  it('uses the dns.dangling observation and its NXDOMAIN state', () => {
    const c = buildDnsChain(
      detail({
        asset: asset('hostname', 'promo.example.com'),
        observations: [
          obs('dns.dangling', { cname_chain: ['promo.example.com', 'a.net', 'b.azurewebsites.net'], cname_state: 'nxdomain' }),
        ],
      }),
    );
    expect(c).toMatchObject({ hops: ['promo.example.com', 'a.net', 'b.azurewebsites.net'], state: 'nxdomain', source: 'observation' });
  });

  it('derives the state from legacy final_resolves', () => {
    const mk = (data: Record<string, unknown>) =>
      buildDnsChain(detail({ asset: asset('hostname', 'h'), observations: [obs('dns.dangling', { cname_chain: ['h', 'x'], ...data })] }));
    expect(mk({ final_resolves: true })?.state).toBe('resolved');
    expect(mk({ final_resolves: false })?.state).toBe('nxdomain');
    expect(mk({ final_resolves: false, final_error: 'timeout' })?.state).toBe('unknown');
    expect(mk({})?.state).toBe('unknown');
  });

  it('falls back to a finding with cname_chain evidence', () => {
    const f = { evidence: { cname_chain: ['h', 'x'], nxdomain_at_hop: 1 } } as unknown as Finding;
    const c = buildDnsChain(detail({ asset: asset('hostname', 'h'), findings: [f] }));
    expect(c).toMatchObject({ hops: ['h', 'x'], state: 'nxdomain', source: 'finding' });
  });

  it('falls back to cname edges and resolved addresses', () => {
    const edge = (type: string, other: Asset): AssetEdge => ({ type, other, outbound: true });
    const c = buildDnsChain(
      detail({
        asset: asset('hostname', 'h'),
        edges: [edge('cname_to', asset('hostname', 'edge.example.com', 2)), edge('resolves_to', asset('ip', '203.0.113.9', 3))],
      }),
    );
    expect(c).toMatchObject({ hops: ['h', 'edge.example.com'], addresses: ['203.0.113.9'], state: 'resolved', source: 'edges' });
  });

  it('is null when nothing is known about the host', () => {
    expect(buildDnsChain(detail({ asset: asset('hostname', 'h') }))).toBeNull();
  });
});
