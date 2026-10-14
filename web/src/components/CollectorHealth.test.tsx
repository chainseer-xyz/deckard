import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import type { CollectorState } from '../api/types';
import { CollectorHealth } from './CollectorHealth';

const report = (p: Partial<CollectorState> = {}): CollectorState => ({
  tool: 'prowler', scope: 'aws:staging', expected_interval_seconds: 300,
  health: 'healthy', coverage: 'complete', open_findings: 1,
  last_report: '2026-10-14T12:00:00Z', last_complete: '2026-10-14T12:00:00Z', ...p,
});

describe('CollectorHealth', () => {
  it('separates fresh report delivery from incomplete assessment coverage', () => {
    render(<CollectorHealth collectors={[report({ coverage: 'incomplete', last_complete: '2026-10-13T12:00:00Z' })]} />);
    const table = screen.getByRole('table', { name: 'Collector reports' });
    expect(within(table).getByText('Report fresh')).toBeInTheDocument();
    expect(within(table).getByText('Incomplete assessment')).toBeInTheDocument();
    expect(within(table).getByRole('columnheader', { name: 'Last report' })).toBeInTheDocument();
    expect(within(table).getByRole('columnheader', { name: 'Last complete assessment' })).toBeInTheDocument();
    expect(table.querySelector('time[dateTime="2026-10-13T12:00:00Z"]')).toBeInTheDocument();
    expect(within(table).getByText('1 open finding')).toBeInTheDocument();
    expect(screen.queryByText('Healthy')).not.toBeInTheDocument();
  });

  it('never presents runtime event reports as complete coverage', () => {
    render(<CollectorHealth collectors={[report({ tool: 'tetragon', coverage: 'event_only', last_complete: undefined, open_findings: 2 })]} />);
    expect(screen.getByText('Events only')).toBeInTheDocument();
    expect(screen.getByText('Event silence does not establish complete coverage.')).toBeInTheDocument();
    expect(screen.queryByText('Latest report complete')).not.toBeInTheDocument();
    expect(screen.getByText('2 open findings')).toBeInTheDocument();
    expect(screen.getByText('Not applicable')).toBeInTheDocument();
  });

  it('shows overdue and never-seen producers without inventing report times', () => {
    render(<CollectorHealth collectors={[
      report({ tool: 'trivy', health: 'stale', coverage: 'complete', open_findings: 0 }),
      report({ tool: 'kubescape', scope: 'never', health: 'never', coverage: 'never', last_report: undefined, last_complete: undefined }),
      report({ tool: 'custom', scope: 'unscheduled', health: 'reporting', expected_interval_seconds: 0 }),
    ]} />);
    expect(screen.getByText('Report overdue')).toBeInTheDocument();
    expect(screen.getByText('Never reported')).toBeInTheDocument();
    expect(screen.getByText('No assessment received')).toBeInTheDocument();
    expect(screen.getByText('Reporting')).toBeInTheDocument();
    expect(screen.getByText('No freshness interval configured')).toBeInTheDocument();
    expect(screen.getByText('0 open findings')).toBeInTheDocument();
    const never = screen.getByText('kubescape').closest('tr')!;
    expect(never.querySelector('time')).toBeNull();
  });

  it('renders scope text safely and permits long scope wrapping', () => {
    const scope = '<img src=x onerror=alert(1)>:' + 'x'.repeat(200);
    render(<CollectorHealth collectors={[report({ scope })]} />);
    const cell = screen.getByText(scope);
    expect(cell).toHaveClass('break-words');
    expect(cell.querySelector('img')).toBeNull();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('explains an empty producer list without claiming healthy coverage', () => {
    render(<CollectorHealth collectors={[]} />);
    expect(screen.getByText('No collector reports configured or received.')).toBeInTheDocument();
    expect(screen.queryByText('Report fresh')).not.toBeInTheDocument();
  });
});
