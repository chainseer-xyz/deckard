import type { FindingsParams } from '../api/client';
import { SEVERITIES, STATUSES, severityRank } from '../api/types';
import type { Finding, FindingStatus, Severity } from '../api/types';
import { GROUP_BYS } from './triage';
import type { GroupBy } from './triage';

export type SortKey = 'severity' | 'last_seen' | 'first_seen';
export const SORT_KEYS: SortKey[] = ['severity', 'last_seen', 'first_seen'];
export type SortDir = 'asc' | 'desc';

export interface FindingsFilter {
  /** empty array means "any status" */
  status: FindingStatus[];
  /** severity floor; `info` shows everything */
  minSeverity: Severity;
  /** exactly this severity (dashboard tiles); wins over the floor */
  severity?: Severity;
  check: string;
  zone: string;
  source: string;
  assetId?: number;
  q: string;
  groupBy: GroupBy;
  sort: SortKey;
  dir: SortDir;
  page: number; // 1-based
}

export const PAGE_SIZE = 50;
export const DEFAULT_STATUS: FindingStatus[] = ['open'];
/** The default view hides low and info noise; one toggle brings it back. */
export const DEFAULT_MIN_SEVERITY: Severity = 'medium';

export const defaultFilter: FindingsFilter = {
  status: DEFAULT_STATUS,
  minSeverity: DEFAULT_MIN_SEVERITY,
  check: '',
  zone: '',
  source: '',
  q: '',
  groupBy: 'none',
  sort: 'severity',
  dir: 'desc',
  page: 1,
};

/**
 * URL contract: `status` repeats (status=open&status=acknowledged); absent means
 * the default (open); `status=any` means no status filter. `min_severity`
 * absent means medium; `min_severity=info` shows everything. `severity=high`
 * shows exactly high. `group=asset|check|zone`.
 */
export function parseFilter(sp: URLSearchParams): FindingsFilter {
  const f: FindingsFilter = { ...defaultFilter };
  const st = sp.getAll('status');
  if (st.includes('any')) f.status = [];
  else if (st.length) f.status = st.filter((s): s is FindingStatus => STATUSES.includes(s as FindingStatus));
  const ms = sp.get('min_severity');
  if (ms === 'any') f.minSeverity = 'info';
  else if (ms && SEVERITIES.includes(ms as Severity)) f.minSeverity = ms as Severity;
  const sev = sp.get('severity');
  if (sev && SEVERITIES.includes(sev as Severity)) f.severity = sev as Severity;
  f.check = sp.get('check') ?? '';
  f.zone = sp.get('zone') ?? '';
  f.source = sp.get('source') ?? '';
  f.q = sp.get('q') ?? '';
  const aid = Number(sp.get('asset_id'));
  if (Number.isInteger(aid) && aid > 0) f.assetId = aid;
  const group = sp.get('group');
  if (group && GROUP_BYS.includes(group as GroupBy)) f.groupBy = group as GroupBy;
  const sort = sp.get('sort');
  if (SORT_KEYS.includes(sort as SortKey)) f.sort = sort as SortKey;
  const dir = sp.get('dir');
  if (dir === 'asc' || dir === 'desc') f.dir = dir;
  const page = Number(sp.get('page'));
  if (Number.isInteger(page) && page > 1) f.page = page;
  return f;
}

const sameStatus = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Serialises only non-default values so URLs stay short and shareable. */
export function toSearchParams(f: FindingsFilter): URLSearchParams {
  const sp = new URLSearchParams();
  if (f.status.length === 0) sp.append('status', 'any');
  else if (!sameStatus(f.status, DEFAULT_STATUS)) f.status.forEach((s) => sp.append('status', s));
  if (f.minSeverity !== DEFAULT_MIN_SEVERITY) sp.set('min_severity', f.minSeverity);
  if (f.severity) sp.set('severity', f.severity);
  if (f.check) sp.set('check', f.check);
  if (f.zone) sp.set('zone', f.zone);
  if (f.source) sp.set('source', f.source);
  if (f.assetId) sp.set('asset_id', String(f.assetId));
  if (f.q) sp.set('q', f.q);
  if (f.groupBy !== 'none') sp.set('group', f.groupBy);
  if (f.sort !== defaultFilter.sort) sp.set('sort', f.sort);
  if (f.dir !== defaultFilter.dir) sp.set('dir', f.dir);
  if (f.page > 1) sp.set('page', String(f.page));
  return sp;
}

/** The effective severity floor sent to the server. */
export const severityFloor = (f: FindingsFilter): Severity => f.severity ?? f.minSeverity;

/** The server applies filters and sort order before selecting a page. */
export function toApiParams(f: FindingsFilter): Omit<FindingsParams, 'limit' | 'offset'> {
  const floor = severityFloor(f);
  return {
    status: f.status.length ? f.status : undefined,
    min_severity: floor === 'info' ? undefined : floor,
    severity: f.severity,
    check: f.check || undefined,
    zone: f.zone || undefined,
    source: f.source || undefined,
    asset_id: f.assetId,
    q: f.q || undefined,
    sort: f.sort,
    direction: f.dir,
  };
}

/** The same filters with the severity floor lifted: "M" in "Showing N of M". */
export function withoutSeverity(p: ReturnType<typeof toApiParams>): ReturnType<typeof toApiParams> {
  return { ...p, min_severity: undefined, severity: undefined };
}

/** Local helper for mock data and exported finding collections. */
export function applyExactSeverity(items: Finding[], f: FindingsFilter): Finding[] {
  return f.severity ? items.filter((x) => x.severity === f.severity) : items;
}

export function pageOf<T>(items: T[], page: number, size = PAGE_SIZE): T[] {
  return items.slice((page - 1) * size, page * size);
}

/** Local helper mirroring the server's allowed sort orders. */
export function sortFindings(items: Finding[], key: SortKey, dir: SortDir): Finding[] {
  const sign = dir === 'asc' ? 1 : -1;
  const sev = (a: Finding, b: Finding) => severityRank(a.severity) - severityRank(b.severity);
  const t = (s: string) => Date.parse(s) || 0;
  return [...items].sort((a, b) => {
    let v: number;
    if (key === 'severity') {
      v = sev(a, b);
      if (v !== 0) return v * sign;
      // equal severity: most recently seen first, whichever way severity runs
      return t(b.last_seen) - t(a.last_seen) || a.id - b.id;
    }
    v = key === 'first_seen' ? t(a.first_seen) - t(b.first_seen) : t(a.last_seen) - t(b.last_seen);
    if (v !== 0) return v * sign;
    return sev(b, a) || a.id - b.id;
  });
}

export interface SuppressInput {
  note: string;
  until: string; // yyyy-mm-dd or ''
}
export interface SuppressErrors {
  note?: string;
  until?: string;
}

export function validateSuppress(i: SuppressInput, now = new Date()): SuppressErrors {
  const e: SuppressErrors = {};
  if (!i.note.trim()) e.note = 'A reason is required.';
  if (i.until) {
    const d = new Date(`${i.until}T23:59:59`);
    if (Number.isNaN(d.getTime())) e.until = 'Enter a valid date.';
    else if (d.getTime() <= now.getTime()) e.until = 'Expiry must be in the future.';
  }
  return e;
}

export function untilToISO(until: string): string | undefined {
  if (!until) return undefined;
  return new Date(`${until}T23:59:59`).toISOString();
}
