import { describe, expect, it } from 'vitest';
import { changeSummary, newBySeverity, scanSummary } from './dashboard';
import type { ChangeEvent, Finding, ScanRun } from '../api/types';

const NOW = Date.parse('2026-10-02T12:00:00Z');
const minsAgo = (m: number) => new Date(NOW - m * 60_000).toISOString();
const run = (id: number, mins: number, error?: string): ScanRun =>
  ({ id, asset_id: id, check: 'c', tier: 'passive', started_at: minsAgo(mins), duration_ms: 1, findings: 0, error }) as ScanRun;

describe('scanSummary', () => {
  it('counts scans in the last hour and finds the newest run and failure', () => {
    const s = scanSummary([run(1, 5), run(2, 30, 'boom'), run(3, 59), run(4, 90), run(5, 120, 'old')], 500, NOW);
    expect(s.lastHour).toBe(3);
    expect(s.atLeast).toBe(false);
    expect(s.lastRun?.id).toBe(1);
    expect(s.lastFailure?.id).toBe(2);
  });
  it('flags a full window that never leaves the hour as a lower bound', () => {
    expect(scanSummary([run(1, 1), run(2, 2)], 2, NOW).atLeast).toBe(true);
    expect(scanSummary([run(1, 1), run(2, 200)], 2, NOW).atLeast).toBe(false);
  });
  it('copes with no scans', () => {
    expect(scanSummary([], 500, NOW)).toEqual({ lastHour: 0, atLeast: false, lastRun: undefined, lastFailure: undefined });
  });
});

describe('changeSummary', () => {
  it('counts the feed by event type', () => {
    const ev = (type: string) => ({ id: 1, type, subject: '', at: '' }) as ChangeEvent;
    const s = changeSummary(
      ['finding_opened', 'finding_opened', 'finding_reopened', 'finding_resolved', 'asset_added', 'asset_removed', 'asset_changed', 'weird'].map(ev),
    );
    expect(s).toEqual({ opened: 2, reopened: 1, resolved: 1, assetsAdded: 1, assetsRemoved: 1, assetsChanged: 1, total: 8 });
  });
});

describe('newBySeverity', () => {
  it('counts open findings first seen in the last 24h per severity', () => {
    const f = (severity: Finding['severity'], hoursAgo: number, status: Finding['status'] = 'open') =>
      ({ severity, status, first_seen: new Date(NOW - hoursAgo * 3600_000).toISOString() }) as Finding;
    const out = newBySeverity([f('high', 2), f('high', 30), f('critical', 1), f('critical', 1, 'resolved'), f('low', 5)], NOW);
    expect(out).toEqual({ critical: 1, high: 1, medium: 0, low: 1, info: 0 });
  });
});
