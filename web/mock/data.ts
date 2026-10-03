import type {
  Asset,
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
    a(4, 'hostname', 'old.example.com', 'cloudflare', 'owned', { removed_at: ago(600), last_seen: ago(610) }),
    a(5, 'ip', '203.0.113.10', 'aws', 'owned'),
    a(6, 'ip', '198.51.100.7', 'discovered', 'external', { zone: undefined }),
    a(7, 'service', '203.0.113.10:443/tcp', 'discovered', 'owned', { attrs: { banner: 'nginx' } }),
    a(8, 'service', '203.0.113.10:22/tcp', 'discovered', 'owned'),
    a(9, 'certificate', 'sha256:ab12cd34', 'discovered', 'shared'),
    a(10, 'cloud_resource', 'aws:s3:example-assets', 'aws', 'owned'),
    a(11, 'hostname', 'promo.example.com', 'cloudflare', 'owned', { first_seen: ago(60 * 24 * 3) }),
    a(12, 'hostname', '_domainkey.example.com', 'cloudflare', 'owned'),
    a(13, 'zone', 'example.org', 'cloudflare', 'owned', { zone: 'example.org' }),
    a(14, 'hostname', 'shop.example.org', 'cloudflare', 'owned', { zone: 'example.org' }),
    a(15, 'hostname', 'staging.example.com', 'kubernetes', 'owned', { first_seen: ago(60 * 20) }),
    a(16, 'url', 'https://staging.example.com/', 'kubernetes', 'owned', { first_seen: ago(60 * 20) }),
  ];
}

export const assets: Asset[] = makeAssets();
const byId = (id: number) => assets.find((x) => x.id === id) as Asset;

export const relations: { from: number; to: number; type: string }[] = [
  { from: 2, to: 1, type: 'in_zone' },
  { from: 3, to: 1, type: 'in_zone' },
  { from: 11, to: 1, type: 'in_zone' },
  { from: 12, to: 1, type: 'in_zone' },
  { from: 15, to: 1, type: 'in_zone' },
  { from: 14, to: 13, type: 'in_zone' },
  { from: 2, to: 5, type: 'resolves_to' },
  { from: 3, to: 5, type: 'resolves_to' },
  { from: 15, to: 5, type: 'resolves_to' },
  { from: 4, to: 6, type: 'resolves_to' },
  { from: 5, to: 7, type: 'exposes' },
  { from: 5, to: 8, type: 'exposes' },
  { from: 7, to: 9, type: 'has_cert' },
  { from: 15, to: 16, type: 'serves' },
];

/** Edges in the server's wire shape ({direction, type, asset}); the client normalises them. */
export function edgesFor(id: number) {
  return relations
    .filter((r) => r.from === id || r.to === id)
    .map((r) => ({ direction: r.from === id ? 'out' : 'in', type: r.type, asset: byId(r.from === id ? r.to : r.from) }));
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
    zone: byId(asset).zone,
    source: byId(asset).source,
    severity: sev,
    title,
    description: `${title}. This was detected by the ${check} check.`,
    evidence: { observed: { port: 443, protocol: 'tcp' }, expected: null },
    remediation: 'Review the exposure and restrict or remove it if unintended. Close the port at the firewall.',
    status: 'open',
    first_seen: ago(60 * 24 * 10 + id),
    last_seen: ago(5),
    missed_runs: 0,
    reopened_count: 0,
    ...extra,
  });
  return [
    f(1, 'critical', 'dns.takeover', 11, 'possible subdomain takeover via Azure App Service', {
      description:
        'promo.example.com is a CNAME to promo-site.azurewebsites.net (Azure App Service) and the provider reports the target resource as unclaimed. An attacker could register that resource with the provider and serve content, steal cookies scoped to the parent domain, or phish under your name.',
      remediation:
        'Remove the CNAME for promo.example.com if it is unused, or re-create and claim the resource at Azure App Service that it points to. Prefer deleting the DNS record before decommissioning the provider resource.',
      evidence: {
        host: 'promo.example.com',
        cname: 'promo-site.azurewebsites.net',
        provider: 'Azure App Service',
        status: 'vulnerable',
        reason: 'NXDOMAIN on the provider endpoint',
        https_cert: 'unavailable',
      },
      tags: ['dns', 'takeover', 'azure-app-service'],
      first_seen: ago(60 * 24 * 3),
    }),
    f(2, 'high', 'dns.dangling', 11, 'promo.example.com CNAME chain ends in NXDOMAIN (promo-site.azurewebsites.net)', {
      description:
        'The CNAME chain for this name terminates at a name that does not exist. If the target is a third-party service endpoint that someone else can claim, this is a subdomain takeover risk.',
      remediation:
        'Remove the stale CNAME for promo.example.com, or restore the third-party resource it pointed at. Review dns.takeover results for the same host.',
      evidence: {
        host: 'promo.example.com',
        cname_target: 'promo-site.azurewebsites.net',
        target_in_owned_zone: false,
        cname_chain: ['promo.example.com', 'promo-site.trafficmanager.net', 'promo-site.azurewebsites.net'],
        nxdomain_at_hop: 2,
      },
      tags: ['dns', 'dangling', 'takeover'],
      first_seen: ago(60 * 24 * 3),
    }),
    f(3, 'high', 'tls.cert', 7, 'TLS certificate on 203.0.113.10:443 expires in 6 days', {
      description:
        'The certificate expires in 6 days, within the critical threshold of 7 days.',
      remediation: 'Renew the certificate now and verify the automated renewal pipeline.',
      evidence: {
        port: 443,
        sni: 'www.example.com',
        not_after: ago(-60 * 24 * 6),
        days_remaining: 6,
        served_by: 'nginx/1.25',
        issuer: "Let's Encrypt R3",
      },
      tags: ['tls', 'expiry'],
      first_seen: ago(60 * 20),
    }),
    f(4, 'high', 'net.ports', 8, 'SSH exposed to the internet', {
      evidence: { port: 22, service_guess: 'ssh', class: 'admin', ports: [22, 443, 8080] },
      first_seen: ago(60 * 24 * 12),
    }),
    f(5, 'critical', 'nuclei', 2, 'Apache Log4j2 remote code execution (CVE-2021-44228)', {
      description:
        'Apache Log4j2 JNDI RCE. Known exploited (CISA KEV, added 2021-12-10). EPSS 94.4% exploitation probability (99.9th percentile).',
      remediation: 'Upgrade Log4j2 to 2.17.1 or later. Apply updates per vendor instructions.',
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
      first_seen: ago(60 * 5),
    }),
    f(6, 'medium', 'http.headers', 2, 'Missing Strict-Transport-Security header', {
      remediation: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS response.',
      evidence: { url: 'https://www.example.com/', header: 'strict-transport-security', present: false },
      first_seen: ago(60 * 24 * 30),
    }),
    f(7, 'medium', 'dns.baseline', 3, 'A record changed from baseline', {
      status: 'acknowledged',
      evidence: { field: 'a', change: 'added', old: ['203.0.113.10'], new: ['203.0.113.10', '203.0.113.99'] },
      tags: ['drift'],
    }),
    f(8, 'medium', 'nuclei', 3, 'Example Server information disclosure (CVE-2020-0001)', {
      evidence: { matched: 'https://api.example.com/', epss: 0.3125, epss_percentile: 0.9 },
      tags: ['cve', 'cve-2020-0001'],
    }),
    f(9, 'medium', 'dns.hygiene', 1, 'example.com has no DMARC record', {
      remediation: 'Publish a _dmarc TXT record, starting with p=none and rua reporting, then tighten the policy.',
      evidence: { zone: 'example.com', record: '_dmarc.example.com', found: false },
      first_seen: ago(60 * 24 * 40),
      reopened_count: 2,
      tags: ['dns', 'email-auth'],
    }),
    f(10, 'medium', 'tls.cert', 14, 'TLS certificate on shop.example.org:443 expires in 24 days', {
      remediation: 'Renew the certificate and confirm automated renewal is working.',
      evidence: { port: 443, sni: 'shop.example.org', not_after: ago(-60 * 24 * 24), days_remaining: 24 },
      first_seen: ago(60 * 2),
      tags: ['tls', 'expiry'],
    }),
    f(11, 'low', 'http.headers', 3, 'Server header discloses version', {
      status: 'suppressed',
      suppression_note: 'Accepted: behind WAF',
      suppressed_until: ago(-60 * 24 * 20),
    }),
    f(12, 'info', 'http.tech', 2, 'nginx detected', { status: 'false_positive' }),
    f(13, 'low', 'net.ports', 5, 'Unexpected port 8080 open', { status: 'resolved', resolved_at: ago(30) }),
    f(14, 'low', 'http.headers', 2, 'Missing X-Content-Type-Options header'),
    f(15, 'low', 'http.headers', 3, 'Missing Referrer-Policy header'),
    f(16, 'info', 'http.tech', 3, 'Express detected', { first_seen: ago(60 * 3) }),
    f(
      17,
      'low',
      'dns.dangling',
      12,
      '_domainkey.example.com is a service-record CNAME to a name that does not exist (dkim.retired-mail.example.net)',
      {
        remediation:
          'Delete the record for _domainkey.example.com if the service is retired, or restore the target dkim.retired-mail.example.net if it should still work.',
        evidence: {
          host: '_domainkey.example.com',
          cname_target: 'dkim.retired-mail.example.net',
          target_in_owned_zone: false,
        },
        tags: ['dns', 'dangling', 'hygiene'],
      },
    ),
    f(18, 'medium', 'http.headers', 15, 'Missing Content-Security-Policy header', { first_seen: ago(60 * 2) }),
  ];
}
export const findings: Finding[] = makeFindings();

const T = (mins: number) => ago(mins);
const OBS: Record<number, Observation[]> = {
  2: [
    { asset_id: 2, check: 'http.headers', data: { status: 200, headers: { server: 'nginx', hsts: false } }, observed_at: T(7) },
    { asset_id: 2, check: 'tls.cert', data: { port: 443, not_after: ago(-60 * 24 * 52), days_remaining: 52 }, observed_at: T(12) },
    { asset_id: 2, check: 'dns.baseline', data: { a: ['203.0.113.10', '203.0.113.77'] }, observed_at: T(6) },
    { asset_id: 2, check: 'net.ports', data: { ports: [22, 443, 8080] }, observed_at: T(60 * 30) },
    {
      asset_id: 2,
      check: 'dns.dangling',
      data: {
        host: 'www.example.com',
        cname_chain: ['www.example.com', 'www.example.com.cdn.cloudflare.net'],
        cname_state: 'resolved',
        final_resolves: true,
      },
      observed_at: T(9),
    },
  ],
  11: [
    {
      asset_id: 11,
      check: 'dns.dangling',
      data: {
        host: 'promo.example.com',
        cname_chain: ['promo.example.com', 'promo-site.trafficmanager.net', 'promo-site.azurewebsites.net'],
        cname_state: 'nxdomain',
        final_resolves: false,
      },
      observed_at: T(8),
    },
    {
      asset_id: 11,
      check: 'dns.takeover',
      data: { host: 'promo.example.com', cname: 'promo-site.azurewebsites.net', provider: 'Azure App Service', status: 'vulnerable' },
      observed_at: T(8),
    },
  ],
};
export const observations = (id: number): Observation[] =>
  OBS[id] ?? [
    { asset_id: id, check: 'http.headers', data: { status: 200, headers: { server: 'nginx' } }, observed_at: ago(7) },
    { asset_id: id, check: 'tls.cert', data: { port: 443, days_remaining: 6 }, observed_at: ago(12) },
  ];
export const baselines = (id: number): Baseline[] =>
  id === 2
    ? [
        { asset_id: id, check: 'dns.baseline', data: { a: ['203.0.113.10'] }, stable: true, consistent: 12, updated_at: ago(60 * 24 * 2) },
        { asset_id: id, check: 'net.ports', data: { ports: [22, 443] }, stable: false, consistent: 2, updated_at: ago(60 * 24 * 2) },
      ]
    : [
        { asset_id: id, check: 'dns.baseline', data: { a: ['203.0.113.10'] }, stable: true, consistent: 12, updated_at: ago(40) },
      ];

export const sources: SyncStatus[] = [
  { source: 'cloudflare', type: 'cloudflare', last_run: ago(4), last_ok: ago(4), asset_count: 9, duration_ms: 1840 },
  {
    source: 'kubernetes',
    type: 'kubernetes',
    last_run: ago(3),
    last_ok: ago(3),
    warning: 'partial discovery, removals skipped: cluster prod-eu unreachable',
    asset_count: 2,
    duration_ms: 5200,
  },
  { source: 'aws', type: 'aws', last_run: ago(10), last_ok: ago(60 * 30), error: 'AccessDenied: sts:AssumeRole', asset_count: 3, duration_ms: 920 },
  { source: 'azure', type: 'azure', last_run: ago(50), last_ok: ago(50), asset_count: 0, duration_ms: 2100 },
  { source: 'gcp', type: 'gcp', last_run: ago(60 * 20), last_ok: ago(60 * 20), asset_count: 0, duration_ms: 3100 },
];

export const scans: ScanRun[] = Array.from({ length: 16 }, (_, i) => ({
  id: 100 - i,
  asset_id: (i % 8) + 1,
  check: ['http.headers', 'tls.cert', 'net.ports', 'dns.baseline'][i % 4] as string,
  tier: i % 4 === 2 ? 'active' : 'passive',
  started_at: ago(i * 7 + 1),
  duration_ms: 200 + i * 37,
  findings: i % 3,
  error: i === 2 ? 'dial tcp 203.0.113.10:443: i/o timeout' : undefined,
}));

export const changes: ChangeEvent[] = [
  { id: 9, type: 'finding_opened', subject: 'dns.takeover on promo.example.com', at: ago(2) },
  { id: 8, type: 'finding_opened', subject: 'nuclei on www.example.com', at: ago(60 * 5) },
  { id: 7, type: 'finding_reopened', subject: 'dns.hygiene on example.com', at: ago(60 * 6) },
  { id: 6, type: 'asset_added', subject: 'hostname staging.example.com', at: ago(15) },
  { id: 5, type: 'asset_added', subject: 'hostname promo.example.com', at: ago(40) },
  { id: 4, type: 'finding_resolved', subject: 'net.ports on 203.0.113.10', at: ago(30) },
  { id: 3, type: 'asset_changed', subject: 'hostname www.example.com', at: ago(90) },
  { id: 2, type: 'asset_removed', subject: 'hostname old.example.com', at: ago(600) },
  { id: 1, type: 'finding_opened', subject: 'http.headers on api.example.com', at: ago(60 * 30) },
];

/** CSRF token the mock /me hands out (cookie-session mode). */
export const mockCsrfToken = 'mock-csrf-token';
