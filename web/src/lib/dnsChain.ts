import type { AssetDetail } from '../api/types';

export type DnsState = 'resolved' | 'nxdomain' | 'nodata' | 'unknown' | 'loop' | 'too-deep';

export interface DnsChain {
  /** host first, then each CNAME target in order */
  hops: string[];
  /** state of the last hop; unknown when never observed */
  state: DnsState;
  /** addresses the final hop resolves to, when known from asset edges */
  addresses: string[];
  source: 'observation' | 'finding' | 'edges';
}

const isStrings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === 'string');

function stateOf(o: Record<string, unknown>): DnsState | undefined {
  const s = o.cname_state;
  if (s === 'resolved' || s === 'nxdomain' || s === 'nodata' || s === 'unknown' || s === 'loop' || s === 'too-deep') return s;
  if (typeof o.final_resolves === 'boolean') {
    if (o.final_resolves) return 'resolved';
    return typeof o.final_error === 'string' ? 'unknown' : 'nxdomain';
  }
  if (o.exists === false) return 'nxdomain';
  if (typeof o.cname_error === 'string') return 'unknown';
  return undefined;
}

/**
 * Builds the DNS path of a hostname from, in order of trust: the latest
 * dns.dangling observation, an open finding's cname_chain evidence, and the
 * asset's own cname/alias edges.
 */
export function buildDnsChain(d: Pick<AssetDetail, 'asset' | 'edges' | 'observations' | 'findings'>): DnsChain | null {
  const { asset } = d;
  if (asset.kind !== 'hostname' && asset.kind !== 'zone') return null;
  const addresses = d.edges
    .filter((e) => e.outbound && e.type === 'resolves_to' && e.other.kind === 'ip')
    .map((e) => e.other.key);

  for (const o of d.observations) {
    if (!/dangling/i.test(o.check)) continue;
    const chain = o.data.cname_chain;
    const state = stateOf(o.data);
    if (isStrings(chain) && chain.length > 0) {
      return { hops: chain, state: state ?? 'unknown', addresses, source: 'observation' };
    }
    if (state === 'nxdomain') return { hops: [asset.key], state, addresses, source: 'observation' };
  }

  for (const f of d.findings) {
    const chain = f.evidence?.cname_chain;
    if (isStrings(chain) && chain.length > 0) {
      const nx = typeof f.evidence?.nxdomain_at_hop === 'number';
      return { hops: chain, state: nx ? 'nxdomain' : 'unknown', addresses, source: 'finding' };
    }
  }

  const hops = [asset.key];
  const seen = new Set(hops);
  for (const e of d.edges) {
    if (e.outbound && (e.type === 'cname_to' || e.type === 'alias_to') && !seen.has(e.other.key)) {
      hops.push(e.other.key);
      seen.add(e.other.key);
    }
  }
  if (hops.length > 1 || addresses.length > 0) {
    return { hops, state: addresses.length > 0 ? 'resolved' : 'unknown', addresses, source: 'edges' };
  }
  return null;
}
