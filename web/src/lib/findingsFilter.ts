import type { FindingsParams } from '../api/client';
import { SEVERITIES, STATUSES, severityRank } from '../api/types';
import type { Finding, FindingStatus, Severity } from '../api/types';

export type SortKey = 'severity' | 'age';
export type SortDir = 'asc' | 'desc';

export interface FindingsFilter {
  /** empty array means "any status" */
  status: FindingStatus[];
  minSeverity?: Severity;
  check: string;
  zone: string;
  source: string;
  assetId?: number;
  q: string;
  sort: SortKey;
  dir: SortDir;
  page: number; // 1-based
}

export const PAGE_SIZE = 50;
export const DEFAULT_STATUS: FindingStatus[] = ['open'];

export const defaultFilter: FindingsFilter = {
  status: DEFAULT_STATUS,
  check: '',
  zone: '',
  source: '',
  q: '',
  sort: 'severity',
  dir: 'desc',
  page: 1,
};

/**
 * URL contract: `status` repeats (status=open&status=acknowledged); absent means
 * the default (open); `status=any` means no status filter.
 */
export function parseFilter(sp: URLSearchParams): FindingsFilter {
  const f: FindingsFilter = { ...defaultFilter };
  const st = sp.getAll('status');
  if (st.includes('any')) f.status = [];
  else if (st.length) f.status = st.filter((s): s is FindingStatus => STATUSES.includes(s as FindingStatus));
  const ms = sp.get('min_severity');
  if (ms && SEVERITIES.includes(ms as Severity)) f.minSeverity = ms as Severity;
  f.check = sp.get('check') ?? '';
  f.zone = sp.get('zone') ?? '';
  f.source = sp.get('source') ?? '';
  f.q = sp.get('q') ?? '';
  const aid = Number(sp.get('asset_id'));
  if (Number.isInteger(aid) && aid > 0) f.assetId = aid;
  const sort = sp.get('sort');
  if (sort === 'severity' || sort === 'age') f.sort = sort;
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
  if (f.minSeverity) sp.set('min_severity', f.minSeverity);
  if (f.check) sp.set('check', f.check);
  if (f.zone) sp.set('zone', f.zone);
  if (f.source) sp.set('source', f.source);
  if (f.assetId) sp.set('asset_id', String(f.assetId));
  if (f.q) sp.set('q', f.q);
  if (f.sort !== defaultFilter.sort) sp.set('sort', f.sort);
  if (f.dir !== defaultFilter.dir) sp.set('dir', f.dir);
  if (f.page > 1) sp.set('page', String(f.page));
  return sp;
}

export function toApiParams(f: FindingsFilter): FindingsParams {
  return {
    status: f.status.length ? f.status : undefined,
    min_severity: f.minSeverity,
    check: f.check || undefined,
    zone: f.zone || undefined,
    source: f.source || undefined,
    asset_id: f.assetId,
    q: f.q || undefined,
    limit: PAGE_SIZE,
    offset: (f.page - 1) * PAGE_SIZE,
  };
}

/** The API has no sort parameter, so order the fetched page client-side. */
export function sortFindings(items: Finding[], key: SortKey, dir: SortDir): Finding[] {
  const sign = dir === 'asc' ? 1 : -1;
  return [...items].sort((a, b) => {
    const primary =
      key === 'severity'
        ? severityRank(a.severity) - severityRank(b.severity)
        : Date.parse(a.first_seen) - Date.parse(b.first_seen);
    // older first_seen == greater age, so "age desc" means oldest first
    const v = key === 'age' ? -primary : primary;
    if (v !== 0) return v * sign;
    return a.id - b.id;
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
