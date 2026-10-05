import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { mockServer, renderRoute } from '../test/utils';
import type { Asset, Finding, ScanRun } from '../api/types';
import { makeFindings } from '../../mock/data';
import Findings from './Findings';
import Inventory from './Inventory';
import Dashboard from './Dashboard';

const { server, state } = mockServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterAll(() => server.close());
afterEach(() => {
  server.resetHandlers();
  state.findings = makeFindings();
  state.assets = undefined;
  state.scans = undefined;
});

const findings = (n: number): Finding[] => {
  const base = makeFindings()[0] as Finding;
  return Array.from({ length: n }, (_, i) => ({
    ...base,
    id: i + 1,
    fingerprint: `fp-${i}`,
    title: `Finding ${i + 1}`,
    asset_id: 1,
    asset_key: 'mass.example',
    check: 'mass',
    zone: 'mass.example',
    severity: 'high',
    status: 'open',
    tags: [],
    evidence: {},
    first_seen: new Date(Date.now() - 3600_000 + i * 100).toISOString(),
    last_seen: new Date(Date.now() - 3600_000 + i * 100).toISOString(),
  }));
};

describe('complete inventory with bounded responses', () => {
  it('shows findings beyond row 5000 with an exact severity filter and server sort', async () => {
    state.findings = findings(6005);
    state.findings.push({ ...state.findings[0] as Finding, id: 7000, severity: 'critical', title: 'Exclude this critical finding' });
    renderRoute(<Findings />, '/findings', '/findings?severity=high&sort=first_seen&dir=asc&page=101');
    expect(await screen.findByText('Finding 5001')).toBeInTheDocument();
    expect(screen.getByText('Finding 5050')).toBeInTheDocument();
    expect(screen.queryByText('Exclude this critical finding')).not.toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(51);
    expect(screen.getByText('Showing 6005 high findings.')).toBeInTheDocument();
    expect(screen.getByText('5001-5050 of 6005')).toBeInTheDocument();
    expect(screen.queryByText(/Showing all/)).not.toBeInTheDocument();
  });

  it('aggregates all 6005 group members and pages expanded members', async () => {
    state.findings = findings(6005);
    renderRoute(<Findings />, '/findings', '/findings?group=check&sort=first_seen&dir=asc');
    const toggle = await screen.findByRole('button', { name: 'mass, 6005 findings: 6005 high' });
    await userEvent.click(toggle);
    expect(await screen.findByText('Finding 1')).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(51);
    expect(screen.getByText('1-50 of 6005')).toBeInTheDocument();
    const pagination = screen.getByText('1-50 of 6005').closest('nav') as HTMLElement;
    await userEvent.click(within(pagination).getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('Finding 51')).toBeInTheDocument();
    expect(screen.queryByText('Finding 1')).not.toBeInTheDocument();
  });

  it('includes the tail in dashboard triage, zone counts and fresh severity counts', async () => {
    state.findings = findings(6005).map((finding, i) => ({ ...finding, severity: 'medium', zone: i < 5000 ? 'mass.example' : 'tail.example' }));
    state.findings[6004] = { ...state.findings[6004] as Finding, severity: 'critical', check: 'dns.takeover', title: 'Tail takeover', tags: ['takeover'] };
    renderRoute(<Dashboard />);
    const panel = await screen.findByRole('region', { name: 'Needs attention' });
    expect(await within(panel).findByText('Tail takeover')).toBeInTheDocument();
    const zones = screen.getByRole('region', { name: /Top zones/ });
    expect(await within(zones).findByRole('link', { name: 'tail.example: 1005 open findings above low' })).toBeInTheDocument();
    const critical = await screen.findByLabelText('1 open critical findings');
    await waitFor(() => expect(critical).toHaveTextContent('+1 new in 24h'));
    const medium = screen.getByLabelText('6004 open medium findings');
    expect(medium).toHaveTextContent('+6004 new in 24h');
  });

  it('finds an asset beyond row 5000 and shows complete per-asset findings and an old scan', async () => {
    state.assets = Array.from({ length: 6005 }, (_, i): Asset => ({
      id: i + 1, kind: 'hostname', key: `asset-${i + 1}.example`, source: 'static', scope: 'owned',
      first_seen: '2026-09-01T00:00:00Z', last_seen: '2026-10-04T00:00:00Z',
    }));
    state.findings = findings(6001).map((finding) => ({ ...finding, asset_id: 6005, asset_key: 'asset-6005.example' }));
    state.scans = [
      ...Array.from({ length: 1000 }, (_, i): ScanRun => ({ id: i, asset_id: 1, check: 'mass', tier: 'passive', started_at: new Date().toISOString(), duration_ms: 0, findings: 0 })),
      { id: 1001, asset_id: 6005, check: 'mass', tier: 'passive', started_at: '2026-09-01T00:00:00Z', duration_ms: 0, findings: 0 },
    ];
    renderRoute(<Inventory />, '/inventory', '/inventory?needles=1');
    const row = (await screen.findByRole('link', { name: 'asset-6005.example' })).closest('tr') as HTMLElement;
    expect(within(row).getByLabelText('6001 open findings on asset-6005.example, worst high')).toBeInTheDocument();
    expect(within(row).getAllByRole('cell')[6]).not.toHaveTextContent(/^\s*-\s*$/);
    expect(screen.getByText('1-1 of 1')).toBeInTheDocument();
  });

  it('discloses a truncated graph', async () => {
    server.use(http.get('*/api/v1/assets/2/graph', () => HttpResponse.json({ nodes: [], edges: [], truncated: true })));
    renderRoute(<Inventory />, '/inventory', '/inventory?view=map&asset=2');
    expect(await screen.findByText(/This graph reached the node limit/)).toBeInTheDocument();
  });
});
