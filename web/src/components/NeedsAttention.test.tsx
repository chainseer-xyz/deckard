import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { NeedsAttentionList } from './NeedsAttention';
import { needsAttention } from '../lib/triage';
import type { Finding } from '../api/types';

const NOW = Date.parse('2026-10-02T12:00:00Z');
let n = 0;
const mk = (p: Partial<Finding>): Finding => ({
  id: ++n,
  fingerprint: '',
  check: 'http.headers',
  asset_id: 7,
  asset_key: 'a.example.com',
  severity: 'high',
  title: `finding ${n}`,
  description: '',
  status: 'open',
  first_seen: new Date(NOW - 3 * 86400_000).toISOString(),
  last_seen: new Date(NOW).toISOString(),
  missed_runs: 0,
  reopened_count: 0,
  ...p,
});
const renderList = (items: Finding[]) =>
  render(
    <MemoryRouter>
      <NeedsAttentionList items={items} now={NOW} />
    </MemoryRouter>,
  );

describe('NeedsAttentionList', () => {
  it('renders severity, title, asset, check, age and a remediation hint per row, in the given order', () => {
    const items = needsAttention([
      mk({ severity: 'critical', title: 'rce', remediation: 'Patch it. Then restart.' }),
      mk({ severity: 'high', title: 'dangling', check: 'dns.takeover', tags: ['takeover'] }),
      mk({ severity: 'high', title: 'cert expires in 2 days', check: 'tls.cert', evidence: { not_after: '2026-10-04T00:00:00Z' } }),
    ]);
    renderList(items);
    const rows = screen.getAllByRole('listitem');
    expect(rows.map((r) => within(r).getAllByRole('link')[0]?.textContent)).toEqual(['dangling', 'cert expires in 2 days', 'rce']);
    const rce = rows[2] as HTMLElement;
    expect(within(rce).getByText('critical')).toBeInTheDocument();
    expect(within(rce).getByRole('link', { name: 'a.example.com' })).toHaveAttribute('href', '/assets/7');
    expect(within(rce).getByText('http.headers')).toBeInTheDocument();
    expect(within(rce).getByText('first seen 3d ago')).toBeInTheDocument();
    expect(within(rce).getByText('Patch it.')).toBeInTheDocument(); // first sentence only
    expect(within(rows[0] as HTMLElement).getByText('Takeover')).toBeInTheDocument();
    expect(within(rows[1] as HTMLElement).getByText('Expiry')).toBeInTheDocument();
  });

  it('links each title to the finding drawer', () => {
    const f = mk({ title: 'x' });
    renderList([f]);
    expect(screen.getByRole('link', { name: 'x' })).toHaveAttribute('href', `/findings?finding=${f.id}`);
  });

  it('shows eight rows and expands to all', async () => {
    renderList(Array.from({ length: 11 }, () => mk({})));
    expect(screen.getAllByRole('listitem')).toHaveLength(8);
    await userEvent.click(screen.getByRole('button', { name: 'Show all 11' }));
    expect(screen.getAllByRole('listitem')).toHaveLength(11);
    await userEvent.click(screen.getByRole('button', { name: 'Show fewer' }));
    expect(screen.getAllByRole('listitem')).toHaveLength(8);
  });

  it('has an empty state that points at medium findings', () => {
    renderList([]);
    expect(screen.getByText(/Nothing needs attention/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Review medium findings' })).toHaveAttribute('href', '/findings');
  });
});
