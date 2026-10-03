import { SEVERITIES, severityRank } from '../api/types';
import type { Finding, Severity } from '../api/types';
import { intelOf } from './intel';

export const DAY_MS = 24 * 3600 * 1000;

export const isKev = (f: Pick<Finding, 'tags' | 'evidence'>): boolean => intelOf(f)?.kev ?? false;

export function isTakeover(f: Pick<Finding, 'check' | 'tags' | 'severity'>): boolean {
  if ((f.tags ?? []).includes('takeover')) return true;
  return /takeover/i.test(f.check);
}

export function isExpiry(f: Pick<Finding, 'check' | 'title' | 'evidence'>): boolean {
  const ev = f.evidence ?? {};
  if (/cert/i.test(f.check) && ('not_after' in ev || 'days_remaining' in ev)) return true;
  return /\b(expired|expires|expiring|expiry)\b/i.test(f.title);
}

/** First seen within the last 24h. */
export function isNew24h(f: Pick<Finding, 'first_seen'>, now = Date.now()): boolean {
  const t = Date.parse(f.first_seen);
  return Number.isFinite(t) && now - t < DAY_MS && now - t >= -60_000;
}

/** Takeover first, then expiry, then everything else. */
export function attentionRank(f: Finding): number {
  if (isTakeover(f)) return 0;
  if (isExpiry(f)) return 1;
  return 2;
}

/**
 * Open critical and high findings, plus anything tagged kev. Ordered: takeover,
 * expiry, rest; within each by severity (worst first), kev first, then oldest
 * (longest unresolved) first.
 */
export function needsAttention(items: Finding[]): Finding[] {
  return items
    .filter((f) => f.status === 'open' && (severityRank(f.severity) >= severityRank('high') || isKev(f)))
    .sort(
      (a, b) =>
        attentionRank(a) - attentionRank(b) ||
        severityRank(b.severity) - severityRank(a.severity) ||
        Number(isKev(b)) - Number(isKev(a)) ||
        Date.parse(a.first_seen) - Date.parse(b.first_seen) ||
        a.id - b.id,
    );
}

/** One-line remediation hint: first sentence of the remediation, with sensible fallbacks. */
export function remediationHint(f: Finding, max = 140): string {
  const text = (f.remediation ?? '').trim();
  if (text) {
    const m = /^(.+?[.!?])(\s|$)/.exec(text.replace(/\s+/g, ' '));
    const first = (m ? m[1] : text.replace(/\s+/g, ' ')) as string;
    return first.length > max ? `${first.slice(0, max - 1)}…` : first;
  }
  if (isTakeover(f)) return 'Remove the dangling DNS record or reclaim the target.';
  if (isExpiry(f)) return 'Renew the certificate.';
  if (isKev(f)) return 'Patch per vendor and CISA guidance.';
  return 'Open the finding for details.';
}

export type GroupBy = 'none' | 'asset' | 'check' | 'zone';
export const GROUP_BYS: GroupBy[] = ['none', 'asset', 'check', 'zone'];

export interface FindingGroup {
  key: string;
  label: string;
  items: Finding[];
  counts: Record<Severity, number>;
  top: Severity;
}

const groupKey = (f: Finding, by: Exclude<GroupBy, 'none'>): string =>
  by === 'asset' ? f.asset_key : by === 'check' ? f.check : (f.zone ?? '');

export const emptyCounts = (): Record<Severity, number> =>
  Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;

/** Groups keep the incoming item order; groups sort by worst severity, then size, then name. */
export function groupFindings(items: Finding[], by: Exclude<GroupBy, 'none'>): FindingGroup[] {
  const map = new Map<string, FindingGroup>();
  for (const f of items) {
    const key = groupKey(f, by);
    let g = map.get(key);
    if (!g) {
      g = { key, label: key || '(no zone)', items: [], counts: emptyCounts(), top: 'info' };
      map.set(key, g);
    }
    g.items.push(f);
    g.counts[f.severity] += 1;
    if (severityRank(f.severity) > severityRank(g.top)) g.top = f.severity;
  }
  return [...map.values()].sort(
    (a, b) =>
      severityRank(b.top) - severityRank(a.top) ||
      b.items.length - a.items.length ||
      a.label.localeCompare(b.label),
  );
}

export interface Tally {
  key: string;
  count: number;
}

/** Top N values of a field by number of open findings at or above minSeverity. */
export function topBy(items: Finding[], field: 'zone' | 'check', min: Severity = 'medium', n = 6): Tally[] {
  const m = new Map<string, number>();
  for (const f of items) {
    if (f.status !== 'open' || severityRank(f.severity) < severityRank(min)) continue;
    const k = f[field] ?? '';
    if (!k) continue;
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
    .slice(0, n);
}

/** Ticket-ready markdown summary of a finding. */
export function findingMarkdown(f: Finding, absTime: (s?: string | null) => string, link?: string): string {
  const lines: string[] = [];
  lines.push(`## [${f.severity.toUpperCase()}] ${f.title}`, '');
  lines.push(`- **Asset:** \`${f.asset_key}\``);
  if (f.zone) lines.push(`- **Zone:** ${f.zone}`);
  lines.push(`- **Check:** \`${f.check}\``);
  lines.push(`- **Status:** ${f.status}`);
  lines.push(`- **First seen:** ${absTime(f.first_seen)}`);
  lines.push(`- **Last seen:** ${absTime(f.last_seen)}`);
  if (f.reopened_count > 0) lines.push(`- **Reopened:** ${f.reopened_count}x`);
  if (f.tags?.length) lines.push(`- **Tags:** ${f.tags.join(', ')}`);
  if (link) lines.push(`- **Link:** ${link}`);
  if (f.description) lines.push('', '### Description', '', f.description);
  if (f.remediation) lines.push('', '### Remediation', '', f.remediation);
  const ev = Object.entries(f.evidence ?? {});
  if (ev.length) {
    lines.push('', '### Evidence', '');
    for (const [k, v] of ev) {
      const s = typeof v === 'string' ? v : JSON.stringify(v);
      lines.push(`- \`${k}\`: ${s.length > 300 ? `${s.slice(0, 299)}…` : s}`);
    }
  }
  return lines.join('\n');
}
