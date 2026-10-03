import { Card } from './ui';
import { ChainPath } from './Evidence';
import type { DnsChain, DnsState } from '../lib/dnsChain';

const STATE: Record<DnsState, { label: string; bad: boolean; text: string }> = {
  resolved: { label: 'resolves', bad: false, text: 'The chain resolves.' },
  nxdomain: {
    label: 'NXDOMAIN',
    bad: true,
    text: 'The last name does not exist (NXDOMAIN). If a third party can claim it, this is a takeover risk.',
  },
  nodata: { label: 'no data', bad: false, text: 'The last name exists but has no address records.' },
  unknown: { label: 'unknown', bad: false, text: 'Resolution state not observed or inconclusive (SERVFAIL, timeout).' },
  loop: { label: 'loop', bad: true, text: 'The CNAME chain loops back on itself.' },
  'too-deep': { label: 'too deep', bad: true, text: 'The CNAME chain is longer than the resolver follows.' },
};

const SOURCE: Record<DnsChain['source'], string> = {
  observation: 'latest dns.dangling observation',
  finding: 'an open finding',
  edges: 'asset relations (resolution state not observed)',
};

/** host -> CNAME -> ... -> final target, with the resolution state on the last hop. */
export function DnsChainView({ chain }: { chain: DnsChain }) {
  const st = STATE[chain.state];
  const single = chain.hops.length === 1;
  return (
    <Card title="DNS chain">
      <div className="space-y-2 p-3">
        <ChainPath hops={chain.hops} endLabel={single && !st.bad ? undefined : st.label} endBad={st.bad} />
        {chain.addresses.length > 0 && chain.state !== 'nxdomain' && (
          <p className="text-sm">
            Resolves to{' '}
            {chain.addresses.map((a, i) => (
              <span key={a}>
                {i > 0 && ', '}
                <span className="font-mono text-xs">{a}</span>
              </span>
            ))}
          </p>
        )}
        <p className={`text-xs ${st.bad ? 'font-medium text-bad' : 'text-muted'}`}>
          {st.text} <span className="text-muted">Source: {SOURCE[chain.source]}.</span>
        </p>
      </div>
    </Card>
  );
}
