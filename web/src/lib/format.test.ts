import { describe, expect, it } from 'vitest';
import { STALE_AFTER_MS, SYNC_INTERVAL_MS, absUtc, isPartialSync, relTime, syncHealth } from './format';

const NOW = Date.parse('2026-10-02T12:00:00Z');
const ago = (ms: number) => new Date(NOW - ms).toISOString();

describe('syncHealth', () => {
  it('is stale after three missed sync intervals', () => {
    expect(STALE_AFTER_MS).toBe(3 * SYNC_INTERVAL_MS);
    expect(syncHealth({ last_ok: ago(STALE_AFTER_MS - 1000) }, NOW)).toBe('ok');
    expect(syncHealth({ last_ok: ago(STALE_AFTER_MS + 1000) }, NOW)).toBe('stale');
  });
  it('failing beats stale; never for a zero time', () => {
    expect(syncHealth({ last_ok: ago(5 * STALE_AFTER_MS), error: 'boom' }, NOW)).toBe('failing');
    expect(syncHealth({ last_ok: '0001-01-01T00:00:00Z' }, NOW)).toBe('never');
  });
});

describe('isPartialSync', () => {
  it('is true only when the last run carried a warning', () => {
    expect(isPartialSync({ warning: 'partial discovery, removals skipped: x' })).toBe(true);
    expect(isPartialSync({ warning: '' })).toBe(false);
    expect(isPartialSync({})).toBe(false);
  });
});

describe('time formatting', () => {
  it('formats absolute UTC deterministically', () => {
    expect(absUtc('2026-10-08T09:05:30Z')).toBe('2026-10-08 09:05 UTC');
    expect(absUtc('0001-01-01T00:00:00Z')).toBe('-');
  });
  it('formats relative past and future', () => {
    expect(relTime(ago(3 * 86400_000), NOW)).toBe('3d ago');
    expect(relTime(ago(-6 * 86400_000), NOW)).toBe('in 6d');
  });
});
