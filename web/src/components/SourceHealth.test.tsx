import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SourceStatus } from './SourceHealth';
import type { SyncStatus } from '../api/types';

const NOW = Date.parse('2026-10-02T12:00:00Z');
const ago = (m: number) => new Date(NOW - m * 60_000).toISOString();
const src = (p: Partial<SyncStatus>): SyncStatus => ({
  source: 's',
  type: 't',
  last_run: ago(1),
  last_ok: ago(1),
  asset_count: 1,
  duration_ms: 1,
  ...p,
});

describe('SourceStatus', () => {
  it('shows a PARTIAL badge, with the reason, when the last sync was partial', () => {
    render(<SourceStatus s={src({ warning: 'partial discovery, removals skipped: cluster x unreachable' })} now={NOW} />);
    const badge = screen.getByText('Partial');
    expect(badge).toBeInTheDocument();
    expect(badge.closest('span[title]')).toHaveAttribute('title', expect.stringContaining('cluster x unreachable'));
    expect(screen.getByText('Healthy')).toBeInTheDocument(); // partial still synced
  });

  it('has no badge for a clean sync', () => {
    render(<SourceStatus s={src({})} now={NOW} />);
    expect(screen.queryByText('Partial')).not.toBeInTheDocument();
    expect(screen.getByText('Healthy')).toBeInTheDocument();
  });

  it('marks a source stale after three sync intervals (30m)', () => {
    const { rerender } = render(<SourceStatus s={src({ last_ok: ago(29) })} now={NOW} />);
    expect(screen.getByText('Healthy')).toBeInTheDocument();
    rerender(<SourceStatus s={src({ last_ok: ago(31) })} now={NOW} />);
    expect(screen.getByText('Stale')).toBeInTheDocument();
  });

  it('shows failing for an errored run and keeps PARTIAL independent', () => {
    render(<SourceStatus s={src({ error: 'denied', warning: 'partial discovery' })} now={NOW} />);
    expect(screen.getByText('Failing')).toBeInTheDocument();
    expect(screen.getByText('Partial')).toBeInTheDocument();
  });
});
