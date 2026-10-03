import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EvidenceTable } from './Evidence';

const NOW = Date.parse('2026-10-02T12:00:00Z');

describe('EvidenceTable', () => {
  it('renders key/value rows with friendly labels, not JSON', () => {
    render(<EvidenceTable data={{ cname_target: 'x.azurewebsites.net', served_by: 'nginx', host: 'promo.example.com' }} label="Evidence" />);
    const t = screen.getByRole('table', { name: 'Evidence' });
    expect(within(t).getByRole('rowheader', { name: 'CNAME target' })).toBeInTheDocument();
    expect(within(t).getByText('x.azurewebsites.net')).toBeInTheDocument();
    expect(within(t).getByRole('rowheader', { name: 'Served by' })).toBeInTheDocument();
    expect(t.textContent).not.toContain('{');
  });

  it('shows expiry as absolute and relative time', () => {
    render(<EvidenceTable data={{ not_after: '2026-10-08T12:00:00Z' }} label="E" now={NOW} />);
    expect(screen.getByText(/2026-10-08 12:00 UTC/)).toBeInTheDocument();
    expect(screen.getByText('(in 6d)')).toBeInTheDocument();
    expect(screen.getByRole('rowheader', { name: 'Expires' })).toBeInTheDocument();
  });

  it('shows a past expiry as relative-ago', () => {
    render(<EvidenceTable data={{ not_after: '2026-09-30T12:00:00Z' }} label="E" now={NOW} />);
    expect(screen.getByText('(2d ago)')).toBeInTheDocument();
  });

  it('renders port lists as chips', () => {
    render(<EvidenceTable data={{ ports: [22, 443, 8080] }} label="E" />);
    const ports = screen.getByRole('list', { name: 'Ports' });
    expect(within(ports).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['22', '443', '8080']);
  });

  it('renders a CNAME chain as an ordered path', () => {
    render(<EvidenceTable data={{ cname_chain: ['a.example.com', 'b.net', 'c.net'] }} label="E" />);
    const chain = screen.getByRole('list', { name: 'Chain' });
    expect(within(chain).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['a.example.com', 'b.net', 'c.net']);
  });

  it('collapses long values until expanded', async () => {
    const long = 'x'.repeat(400);
    render(<EvidenceTable data={{ note: long }} label="E" raw={false} />);
    const table = screen.getByRole('table', { name: 'E' });
    expect(table.textContent).not.toContain(long);
    await userEvent.click(screen.getByRole('button', { name: /Show more: Note/ }));
    expect(table.textContent).toContain(long);
    await userEvent.click(screen.getByRole('button', { name: /Show less: Note/ }));
    expect(table.textContent).not.toContain(long);
  });

  it('collapses long lists to the first items', async () => {
    const tags = Array.from({ length: 12 }, (_, i) => `tag${i}`);
    render(<EvidenceTable data={{ names: tags }} label="E" raw={false} />);
    expect(screen.queryByText('tag11')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Show all: Names/ }));
    expect(screen.getByText('tag11')).toBeInTheDocument();
  });

  it('marks changed keys and keeps raw JSON behind a disclosure', () => {
    render(<EvidenceTable data={{ a: [1, 2] }} label="E" changes={new Map([['a', 'changed' as const]])} />);
    expect(screen.getByText('changed')).toBeInTheDocument();
    expect(screen.getByText('Raw JSON')).toBeInTheDocument();
  });

  it('says so when there is no evidence', () => {
    render(<EvidenceTable data={{}} label="E" />);
    expect(screen.getByText('No evidence recorded.')).toBeInTheDocument();
  });
});
