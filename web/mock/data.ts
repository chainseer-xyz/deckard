import type {
  Asset,
  AssetEdge,
  Baseline,
  ChangeEvent,
  Finding,
  Graph,
  Observation,
  ScanRun,
  SyncStatus,
} from '../src/api/types';

const now = Date.now();
const ago = (mins: number) => new Date(now - mins * 60_000).toISOString();

export function makeAssets(): Asset[] {
  const a = (
    id: number,
    kind: Asset['kind'],
    key: string,
    source: string,
    scope: Asset['scope'],
    extra: Partial<Asset> = {},
  ): Asset => ({
    id,
    kind,
    key,
    source,
    scope,
    zone: 'example.com',
    first_seen: ago(60 * 24 * 30),
    last_seen: ago(5),
    ...extra,
  });
  return [
    a(1, 'zone', 'example.com', 'cloudflare', 'owned'),
    a(2, 'hostname', 'www.example.com', 'cloudflare', 'owned', { attrs: { proxied: true } }),
    a(3, 'hostname', 'api.example.com', 'cloudflare', 'owned'),
    a(4, 'hostname', 'old.example.com', 'cloudflare', 'owned', { removed_at: ago(600) }),
    a(5, 'ip', '203.0.113.10', 'aws', 'owned'),
    a(6, 'ip', '198.51.100.7', 'discovered', 'external', { zone: undefined }),
    a(7, 'service', '203.0.113.10:443/tcp', 'discovered', 'owned', { attrs: { banner: 'nginx' } }),
    a(8, 'service', '203.0.113.10:22/tcp', 'discovered', 'owned'),
    a(9, 'certificate', 'sha256:ab12cd34', 'discovered', 'shared'),
    a(10, 'cloud_resource', 'aws:s3:example-assets', 'aws', 'owned'),
  ];
}

export const assets: Asset[] = makeAssets();
const byId = (id: number) => assets.find((x) => x.id === id) as Asset;

export const relations: { from: number; to: number; type: string }[] = [
  { from: 2, to: 1, type: 'in_zone' },
  { from: 3, to: 1, type: 'in_zone' },
  { from: 2, to: 5, type: 'resolves_to' },
  { from: 3, to: 5, type: 'resolves_to' },
  { from: 4, to: 6, type: 'resolves_to' },
  { from: 5, to: 7, type: 'exposes' },
  { from: 5, to: 8, type: 'exposes' },
  { from: 7, to: 9, type: 'has_cert' },
];

export function edgesFor(id: number): AssetEdge[] {
  return relations
    .filter((r) => r.from === id || r.to === id)
    .map((r) => ({ other: byId(r.from === id ? r.to : r.from), type: r.type, outbound: r.from === id }));
}

export function graphFor(id: number, depth: number): Graph {
  const seen = new Set([id]);
  let frontier = [id];
  for (let d = 0; d < depth; d++) {
    const next: number[] = [];
    for (const r of relations) {
      for (const [a, b] of [[r.from, r.to], [r.to, r.from]] as const) {
        if (frontier.includes(a) && !seen.has(b)) {
          seen.add(b);
          next.push(b);
        }
      }
    }
    frontier = next;
  }
  return {
    nodes: [...seen].map((i) => {
      const x = byId(i);
      return { id: x.id, kind: x.kind, key: x.key, scope: x.scope };
    }),
    edges: relations.filter((r) => seen.has(r.from) && seen.has(r.to)),
  };
}

export function makeFindings(): Finding[] {
  const f = (
    id: number,
    sev: Finding['severity'],
    check: string,
    asset: number,
    title: string,
    extra: Partial<Finding> = {},
  ): Finding => ({
    id,
    fingerprint: `fp${id}`,
    check,
    asset_id: asset,
    asset_key: byId(asset).key,
    zone: 'example.com',
    source: byId(asset).source,
    severity: sev,
    title,
    description: `${title}. This was detected by the ${check} check.`,
    evidence: { observed: { port: 443, protocol: 'tcp' }, expected: null },
    remediation: 'Review the exposure and restrict or remove it if unintended.',
    status: 'open',
    first_seen: ago(60 * id),
    last_seen: ago(5),
    missed_runs: 0,
    reopened_count: 0,
    ...extra,
  });
  return [
    f(1, 'critical', 'subdomain_takeover', 4, 'Dangling CNAME allows subdomain takeover'),
    f(2, 'high', 'tls_expiry', 7, 'TLS certificate expires in 6 days', { evidence: { not_after: ago(-8640), issuer: 'R3' } }),
    f(3, 'high', 'open_port', 8, 'SSH exposed to the internet'),
    f(4, 'medium', 'http_headers', 2, 'Missing Strict-Transport-Security header'),
    f(5, 'medium', 'dns_baseline', 3, 'A record changed from baseline', { status: 'acknowledged' }),
    f(6, 'low', 'http_headers', 3, 'Server header discloses version', { status: 'suppressed', suppression_note: 'Accepted: behind WAF', suppressed_until: ago(-60 * 24 * 20) }),
    f(7, 'info', 'tech_detect', 2, 'nginx detected', { status: 'false_positive' }),
    f(8, 'low', 'open_port', 5, 'Unexpected port 8080 open', { status: 'resolved', resolved_at: ago(30) }),
    f(9, 'critical', 'nuclei', 2, 'Apache Log4j2 remote code execution (CVE-2021-44228)', {
      description: 'Apache Log4j2 JNDI RCE. Known exploited (CISA KEV, added 2021-12-10). EPSS 94.4% exploitation probability (99.9th percentile).',
      evidence: {
        matched: 'https://www.example.com/',
        kev: true,
        kev_date_added: '2021-12-10',
        kev_ransomware: true,
        kev_required_action: 'Apply updates per vendor instructions.',
        epss: 0.94434,
        epss_percentile: 0.99975,
      },
      tags: ['cve', 'cve-2021-44228', 'kev'],
    }),
    f(10, 'medium', 'nuclei', 3, 'Example Server information disclosure (CVE-2020-0001)', {
      evidence: { matched: 'https://api.example.com/', epss: 0.3125, epss_percentile: 0.9 },
      tags: ['cve', 'cve-2020-0001'],
    }),
  ];
}
export const findings: Finding[] = makeFindings();

export const observations = (id: number): Observation[] => [
  { asset_id: id, check: 'http_headers', data: { status: 200, headers: { server: 'nginx' } }, observed_at: ago(7) },
  { asset_id: id, check: 'tls_expiry', data: { days_left: 6 }, observed_at: ago(12) },
];
export const baselines = (id: number): Baseline[] => [
  { asset_id: id, check: 'dns_baseline', data: { a: ['203.0.113.10'] }, stable: true, consistent: 12, updated_at: ago(40) },
  { asset_id: id, check: 'open_port', data: { ports: [22, 443] }, stable: false, consistent: 2, updated_at: ago(40) },
];

export const sources: SyncStatus[] = [
  { source: 'cloudflare', type: 'cloudflare', last_run: ago(4), last_ok: ago(4), asset_count: 4, duration_ms: 1840 },
  { source: 'aws', type: 'aws', last_run: ago(10), last_ok: ago(60 * 30), error: 'AccessDenied: sts:AssumeRole', asset_count: 3, duration_ms: 920 },
  { source: 'gcp', type: 'gcp', last_run: ago(60 * 20), last_ok: ago(60 * 20), asset_count: 0, duration_ms: 3100 },
];

export const scans: ScanRun[] = Array.from({ length: 12 }, (_, i) => ({
  id: 100 - i,
  asset_id: (i % 8) + 1,
  check: ['http_headers', 'tls_expiry', 'open_port', 'dns_baseline'][i % 4] as string,
  tier: i % 4 === 2 ? 'active' : 'passive',
  started_at: ago(i * 3 + 1),
  duration_ms: 200 + i * 37,
  findings: i % 3,
  error: i === 4 ? 'dial tcp 203.0.113.10:443: i/o timeout' : undefined,
}));

export const changes: ChangeEvent[] = [
  { id: 5, type: 'finding_opened', subject: 'subdomain_takeover on old.example.com', at: ago(2) },
  { id: 4, type: 'asset_added', subject: 'hostname api.example.com', at: ago(15) },
  { id: 3, type: 'finding_resolved', subject: 'open_port on 203.0.113.10', at: ago(30) },
  { id: 2, type: 'asset_changed', subject: 'hostname www.example.com', at: ago(90) },
  { id: 1, type: 'asset_removed', subject: 'hostname old.example.com', at: ago(600) },
];

/** CSRF token the mock /me hands out (cookie-session mode). */
export const mockCsrfToken = 'mock-csrf-token';
