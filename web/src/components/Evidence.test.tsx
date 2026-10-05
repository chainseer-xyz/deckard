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

  it('bounds long ARN/JSON rows without losing their expandable full values', async () => {
    const arn = `arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/${'resource-'.repeat(30)}`;
    const json = [{ resource: arn, metadata: 'x'.repeat(400) }];
    const longKey = `aws_${'metadata_'.repeat(20)}identifier`;
    render(<EvidenceTable data={{ arn, payload: json, [longKey]: 'recorded' }} label="AWS facts" raw={false} />);
    const table = screen.getByRole('table', { name: 'AWS facts' });
    // jsdom does not calculate intrinsic table widths. Guard the layout and
    // wrapping contract here; actual 375px rendering requires Brave verification.
    expect(table).toHaveClass('w-full', 'table-fixed');
    for (const header of within(table).getAllByRole('rowheader')) {
      expect(header).toHaveAttribute('scope', 'row');
      expect(header).toHaveClass('[overflow-wrap:anywhere]');
      expect(header).not.toHaveClass('min-w-28');
    }
    for (const cell of within(table).getAllByRole('cell')) {
      expect(cell).toHaveClass('[overflow-wrap:anywhere]');
    }
    expect(table.textContent).not.toContain(arn);
    const expandArn = within(table).getByRole('button', { name: 'Show more: Arn' });
    await userEvent.click(expandArn);
    expect(expandArn).toHaveAttribute('aria-expanded', 'true');
    expect(table.textContent).toContain(arn);
    await userEvent.click(within(table).getByRole('button', { name: 'Show more: Payload' }));
    expect(table.textContent).toContain(JSON.stringify(json));
    expect(within(table).getByRole('button', { name: 'Show less: Payload' })).toHaveAttribute('aria-expanded', 'true');
  });

  it('wraps long list chips and lets each chip reveal its complete value', async () => {
    const arn = `arn:aws:iam::123456789012:role/${'nested-role/'.repeat(25)}`;
    render(<EvidenceTable data={{ resources: [arn, 'short'] }} label="AWS resources" raw={false} />);
    const table = screen.getByRole('table', { name: 'AWS resources' });
    expect(table.textContent).not.toContain(arn);
    const expand = within(table).getByRole('button', { name: 'Show more: Resources item 1' });
    await userEvent.click(expand);
    expect(expand).toHaveAttribute('aria-expanded', 'true');
    expect(table.textContent).toContain(arn);
    for (const chip of within(table).getAllByRole('listitem')) {
      expect(chip).toHaveClass('min-w-0', 'max-w-full', '[overflow-wrap:anywhere]');
    }
    await userEvent.click(within(table).getByRole('button', { name: 'Show less: Resources item 1' }));
    expect(table.textContent).not.toContain(arn);
    expect(within(table).getByText('short')).toBeInTheDocument();
  });

  it('keeps long CNAME chips within the evidence value column', () => {
    render(<EvidenceTable data={{ cname_chain: [`${'long-host'.repeat(20)}.example.com`, 'target.example.com'] }} label="DNS facts" raw={false} />);
    const chain = screen.getByRole('list', { name: 'Chain' });
    for (const hop of within(chain).getAllByRole('listitem')) {
      expect(hop).toHaveClass('min-w-0', 'max-w-full');
      expect(hop.querySelector('span')).toHaveClass('[overflow-wrap:anywhere]');
    }
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
