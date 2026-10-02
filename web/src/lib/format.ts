/** Go's zero time.Time serialises as 0001-01-01T00:00:00Z. */
export function isZeroTime(s?: string | null): boolean {
  return !s || s.startsWith('0001-');
}

export function relTime(s?: string | null, now = Date.now()): string {
  if (isZeroTime(s)) return 'never';
  const diff = Math.round((now - Date.parse(s as string)) / 1000);
  const abs = Math.abs(diff);
  const fmt = (n: number, u: string) => (diff >= 0 ? `${n}${u} ago` : `in ${n}${u}`);
  if (abs < 45) return diff >= 0 ? 'just now' : 'in <1m';
  if (abs < 3600) return fmt(Math.round(abs / 60), 'm');
  if (abs < 86400) return fmt(Math.round(abs / 3600), 'h');
  return fmt(Math.round(abs / 86400), 'd');
}

export function absTime(s?: string | null): string {
  if (isZeroTime(s)) return '-';
  return new Date(s as string).toLocaleString();
}

export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 60000)}m`;
}

export const STALE_AFTER_MS = 12 * 3600 * 1000;

export type SyncHealth = 'ok' | 'stale' | 'failing' | 'never';

/** A source is failing if its last run errored, stale if it has not succeeded recently. */
export function syncHealth(
  s: { last_ok: string; error?: string },
  now = Date.now(),
): SyncHealth {
  if (s.error) return 'failing';
  if (isZeroTime(s.last_ok)) return 'never';
  if (now - Date.parse(s.last_ok) > STALE_AFTER_MS) return 'stale';
  return 'ok';
}

export function titleCase(s: string): string {
  return s.replace(/[_-]/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}
