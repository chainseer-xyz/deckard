import { titleCase } from './format';

export type EvidenceKind = 'text' | 'host' | 'time' | 'ports' | 'list' | 'bool' | 'chain' | 'days';

export interface EvidenceRow {
  /** dotted path of the key, e.g. `observed.port` */
  key: string;
  label: string;
  kind: EvidenceKind;
  value: unknown;
}

const LABELS: Record<string, string> = {
  cname_target: 'CNAME target',
  cname: 'CNAME',
  cname_chain: 'CNAME chain',
  nxdomain_at_hop: 'NXDOMAIN at hop',
  served_by: 'Served by',
  host: 'Host',
  expected_host: 'Expected host',
  sni: 'SNI',
  not_after: 'Expires',
  not_before: 'Valid from',
  days_remaining: 'Days remaining',
  port: 'Port',
  ports: 'Ports',
  nameserver: 'Nameserver',
  target_in_owned_zone: 'Target in an owned zone',
  proxied_hostnames: 'Proxied hostnames',
  unproxied_hostnames: 'Unproxied hostnames',
  service_guess: 'Service guess',
};

const HOST_KEYS = new Set([
  'host',
  'hostname',
  'expected_host',
  'cname',
  'cname_target',
  'cname_end',
  'served_by',
  'nameserver',
  'zone',
  'sni',
  'matched',
  'origin',
  'ip',
]);
const PORT_KEYS = new Set(['port', 'ports', 'open_ports', 'expected_ports', 'new_ports', 'closed_ports']);
const CHAIN_KEYS = new Set(['cname_chain']);
const TIME_KEYS = new Set(['not_after', 'not_before', 'expires', 'expiry', 'expires_at', 'kev_date_added']);
const DAYS_KEYS = new Set(['days_remaining', 'days_left']);

/** Rendered by the exploit-intelligence panel instead. */
const HIDDEN = new Set(['kev', 'kev_date_added', 'kev_ransomware', 'kev_required_action', 'kev_cves', 'epss', 'epss_percentile']);

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const isPrimitive = (v: unknown) => v === null || ['string', 'number', 'boolean'].includes(typeof v);

export function isTimeString(v: unknown): v is string {
  return typeof v === 'string' && ISO.test(v) && Number.isFinite(Date.parse(v));
}

function classify(leaf: string, v: unknown): EvidenceKind {
  if (typeof v === 'boolean') return 'bool';
  if (CHAIN_KEYS.has(leaf) && Array.isArray(v) && v.every((x) => typeof x === 'string')) return 'chain';
  if (PORT_KEYS.has(leaf) && (typeof v === 'number' || (Array.isArray(v) && v.every((x) => typeof x === 'number'))))
    return 'ports';
  if (isTimeString(v) || (TIME_KEYS.has(leaf) && typeof v === 'string' && Number.isFinite(Date.parse(v)))) return 'time';
  if (DAYS_KEYS.has(leaf) && typeof v === 'number') return 'days';
  if (HOST_KEYS.has(leaf) && typeof v === 'string') return 'host';
  if (Array.isArray(v) && v.every(isPrimitive)) return 'list';
  return 'text';
}

/** Flattens evidence (or observation data) into typed rows; nested objects become dotted keys. */
export function evidenceRows(ev: Record<string, unknown> | undefined | null, maxDepth = 2): EvidenceRow[] {
  const rows: EvidenceRow[] = [];
  const walk = (obj: Record<string, unknown>, prefix: string, depth: number) => {
    for (const [k, v] of Object.entries(obj)) {
      if (depth === 0 && HIDDEN.has(k)) continue;
      const key = prefix ? `${prefix}.${k}` : k;
      if (isPlainObject(v) && depth < maxDepth && Object.keys(v).length > 0) {
        walk(v, key, depth + 1);
        continue;
      }
      const kind = classify(k, v);
      const label = LABELS[k] && !prefix ? (LABELS[k] as string) : titleCase(key.replace(/\./g, ' › '));
      rows.push({ key, label, kind, value: v });
    }
  };
  if (ev) walk(ev, '', 0);
  return rows;
}

export type DataChange = 'changed' | 'new' | 'gone';

/**
 * Compares a learned baseline with the latest observation on flattened keys.
 * `new` = only in the observation, `gone` = only in the baseline.
 */
export function diffData(
  baseline: Record<string, unknown> | undefined,
  latest: Record<string, unknown> | undefined,
): Map<string, DataChange> {
  const out = new Map<string, DataChange>();
  if (!baseline || !latest) return out;
  const b = new Map(evidenceRows(baseline).map((r) => [r.key, JSON.stringify(r.value)]));
  const l = new Map(evidenceRows(latest).map((r) => [r.key, JSON.stringify(r.value)]));
  for (const [k, v] of l) {
    if (!b.has(k)) out.set(k, 'new');
    else if (b.get(k) !== v) out.set(k, 'changed');
  }
  for (const k of b.keys()) if (!l.has(k)) out.set(k, 'gone');
  return out;
}
