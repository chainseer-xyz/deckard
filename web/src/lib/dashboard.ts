import { SEVERITIES } from '../api/types';
import type { ChangeEvent, Finding, ScanRun, Severity } from '../api/types';
import { HOUR_MS, isNew24h } from './triage';

export interface ScanSummary {
  /** scans started in the last hour within the fetched window */
  lastHour: number;
  /** the fetched window was full and entirely inside the last hour, so the real count is higher */
  atLeast: boolean;
  lastRun?: ScanRun;
  lastFailure?: ScanRun;
}

/** `limit` is the page size that was requested; the API returns the newest runs. */
export function scanSummary(items: ScanRun[], limit: number, now = Date.now()): ScanSummary {
  const t = (r: ScanRun) => Date.parse(r.started_at) || 0;
  const inHour = items.filter((r) => now - t(r) <= HOUR_MS);
  const newest = (xs: ScanRun[]) => xs.reduce<ScanRun | undefined>((m, r) => (!m || t(r) > t(m) ? r : m), undefined);
  return {
    lastHour: inHour.length,
    atLeast: items.length >= limit && inHour.length === items.length,
    lastRun: newest(items),
    lastFailure: newest(items.filter((r) => r.error)),
  };
}

export interface ChangeSummary {
  opened: number;
  reopened: number;
  resolved: number;
  assetsAdded: number;
  assetsRemoved: number;
  assetsChanged: number;
  total: number;
}

/** Counts of the change feed (the API defaults to the last 24h). */
export function changeSummary(events: ChangeEvent[]): ChangeSummary {
  const c: ChangeSummary = { opened: 0, reopened: 0, resolved: 0, assetsAdded: 0, assetsRemoved: 0, assetsChanged: 0, total: events.length };
  for (const e of events) {
    if (e.type === 'finding_opened') c.opened++;
    else if (e.type === 'finding_reopened') c.reopened++;
    else if (e.type === 'finding_resolved') c.resolved++;
    else if (e.type === 'asset_added') c.assetsAdded++;
    else if (e.type === 'asset_removed') c.assetsRemoved++;
    else if (e.type === 'asset_changed') c.assetsChanged++;
  }
  return c;
}

/** Open findings first seen in the last 24h, per severity. */
export function newBySeverity(items: Finding[], now = Date.now()): Record<Severity, number> {
  const out = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of items) if (f.status === 'open' && isNew24h(f, now)) out[f.severity] += 1;
  return out;
}
