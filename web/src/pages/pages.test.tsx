import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { mockServer, renderRoute } from '../test/utils';
import { makeFindings } from '../../mock/data';
import { clearToken } from '../api/auth';
import { configureClient } from '../api/client';
import Dashboard from './Dashboard';
import Findings from './Findings';
import Inventory from './Inventory';
import AssetDetail from './AssetDetail';
import Sources from './Sources';
import { Login } from './Login';
import { AuthGate } from '../App';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';

vi.mock('../components/AssetGraph', () => ({
  default: ({ graph }: { graph: { nodes: { key: string }[] } }) => (
    <ul aria-label="graph nodes">
      {graph.nodes.map((n) => (
        <li key={n.key}>{n.key}</li>
      ))}
    </ul>
  ),
}));

const { server, state } = mockServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  clearToken();
  state.canWrite = true;
  state.findings = makeFindings(); // actions mutate the shared mock state
});
afterAll(() => server.close());

describe('Dashboard', () => {
  it('leads with needs-attention: takeover and expiry first, each row complete', async () => {
    renderRoute(<Dashboard />);
    const panel = await screen.findByRole('region', { name: 'Needs attention' });
    const rows = await within(panel).findAllByRole('listitem');
    expect(rows.map((r) => within(r).getAllByRole('link')[0]?.textContent)).toEqual([
      'possible subdomain takeover via Azure App Service',
      expect.stringMatching(/CNAME chain ends in NXDOMAIN/),
      expect.stringMatching(/TLS certificate on 203.0.113.10:443 expires in 6 days/),
      expect.stringMatching(/Log4j2/),
      'SSH exposed to the internet',
    ]);
    const first = rows[0] as HTMLElement;
    expect(within(first).getByText('critical')).toBeInTheDocument(); // severity as text
    expect(within(first).getByText('Takeover')).toBeInTheDocument();
    expect(within(first).getByRole('link', { name: 'promo.example.com' })).toHaveAttribute('href', '/assets/11');
    expect(within(first).getByText('dns.takeover')).toBeInTheDocument();
    expect(within(first).getByText(/first seen 3d ago/)).toBeInTheDocument();
    expect(within(first).getByText(/Remove the CNAME for promo.example.com if it is unused/)).toBeInTheDocument();
    expect(within(rows[2] as HTMLElement).getByText('Expiry')).toBeInTheDocument();
    expect(within(rows[3] as HTMLElement).getByText('KEV')).toBeInTheDocument();
    expect(within(rows[3] as HTMLElement).getByText(/New/)).toBeInTheDocument();
    // medium findings do not belong here
    expect(within(panel).queryByText(/Strict-Transport-Security/)).not.toBeInTheDocument();
  });

  it('links each severity tile to the pre-filtered findings with open counts', async () => {
    renderRoute(<Dashboard />);
    const crit = await screen.findByLabelText('2 open critical findings');
    expect(crit).toHaveAttribute('href', '/findings?severity=critical');
    expect(crit).toHaveTextContent('+1 new in 24h'); // the KEV finding is 5h old
    expect(screen.getByLabelText('3 open high findings')).toHaveAttribute('href', '/findings?severity=high');
    expect(screen.getByLabelText('5 open medium findings')).toBeInTheDocument();
    expect(screen.getByLabelText('3 open low findings')).toBeInTheDocument();
    expect(screen.getByLabelText('1 open info findings')).toBeInTheDocument();
  });

  it('shows change-feed counts for the last 24h', async () => {
    renderRoute(<Dashboard />);
    const card = await screen.findByRole('region', { name: 'Last 24 hours' });
    await waitFor(() => expect(card).toHaveTextContent('2 findings opened · 1 reopened · 1 resolved · 2 assets added · 1 removed · 1 changed'));
  });

  it('ranks the top zones and checks above low and links them to filtered findings', async () => {
    renderRoute(<Dashboard />);
    const zones = await screen.findByRole('region', { name: /Top zones/ });
    await waitFor(() => expect(within(zones).getByRole('link', { name: /example.com: 9 open/ })).toHaveAttribute('href', '/findings?zone=example.com'));
    expect(within(zones).getByRole('link', { name: /example.org: 1 open/ })).toBeInTheDocument();
    const checks = screen.getByRole('region', { name: /Top checks/ });
    const link = await within(checks).findByRole('link', { name: /^tls.cert: 2 open/ });
    expect(link).toHaveAttribute('href', '/findings?check=tls.cert');
    expect(within(checks).queryByRole('link', { name: /http.tech/ })).not.toBeInTheDocument(); // info only
  });

  it('shows source health with PARTIAL, stale and failing states and last successful sync', async () => {
    renderRoute(<Dashboard />);
    const strip = await screen.findByRole('region', { name: 'Source health' });
    const card = (name: string) => within(strip).getByText(name, { selector: 'span.font-medium' }).closest('li') as HTMLElement;
    await waitFor(() => expect(card('kubernetes')).toBeInTheDocument());
    expect(within(card('kubernetes')).getByText('Partial')).toBeInTheDocument();
    expect(within(card('kubernetes')).getByText(/partial discovery, removals skipped: cluster prod-eu unreachable/)).toBeInTheDocument();
    expect(within(card('cloudflare')).queryByText('Partial')).not.toBeInTheDocument();
    expect(within(card('cloudflare')).getByText('Healthy')).toBeInTheDocument();
    expect(within(card('cloudflare')).getByText(/last successful sync 4m ago/)).toBeInTheDocument();
    expect(within(card('gcp')).getByText('Stale')).toBeInTheDocument();
    expect(card('gcp').className).toContain('border-warn');
    expect(within(card('azure')).getByText('Stale')).toBeInTheDocument(); // 50m > 3 x 10m
    expect(within(card('aws')).getByText('Failing')).toBeInTheDocument();
    expect(within(card('aws')).getByText(/AccessDenied/)).toBeInTheDocument();
    expect(within(card('aws')).getByText(/last successful sync 1d ago/)).toBeInTheDocument();
  });

  it('shows scan freshness with the last failure', async () => {
    renderRoute(<Dashboard />);
    const card = await screen.findByRole('region', { name: 'Scan freshness' });
    await waitFor(() => expect(card).toHaveTextContent(/9 scans in the last hour/));
    expect(card).toHaveTextContent('Last failure');
    expect(card).toHaveTextContent('dial tcp 203.0.113.10:443: i/o timeout');
    expect(within(card).getByRole('link', { name: 'asset #3' })).toHaveAttribute('href', '/assets/3');
  });

  it('has empty states that say what to do', async () => {
    server.use(
      http.get('*/api/v1/findings', () => HttpResponse.json({ items: [], total: 0, limit: 500, offset: 0 })),
      http.get('*/api/v1/sources', () => HttpResponse.json({ items: [], total: 0, limit: 50, offset: 0 })),
      http.get('*/api/v1/scans', () => HttpResponse.json({ items: [], total: 0, limit: 500, offset: 0 })),
      http.get('*/api/v1/changes', () => HttpResponse.json({ items: [], total: 0, limit: 500, offset: 0 })),
    );
    renderRoute(<Dashboard />);
    expect(await screen.findByText(/Nothing needs attention/)).toBeInTheDocument();
    expect(await screen.findByText(/No sources configured/)).toBeInTheDocument();
    expect(await screen.findByText(/No scans have completed yet/)).toBeInTheDocument();
    expect((await screen.findAllByText('No changes in the last 24 hours.')).length).toBe(2);
    expect((await screen.findAllByText('No open findings above low severity.')).length).toBe(2);
  });

  it('shows an error with retry when stats fail', async () => {
    server.use(http.get('*/api/v1/stats', () => HttpResponse.json({ error: { code: 'internal', message: 'db down' } }, { status: 500 })));
    renderRoute(<Dashboard />);
    expect(await screen.findByRole('alert')).toHaveTextContent('db down');
  });
});

describe('Findings', () => {
  const rowTitles = () => screen.getAllByRole('row').slice(1).map((r) => within(r).getAllByRole('button')[0]?.textContent ?? '');

  it('defaults to open, medium and above, and says how much noise is hidden', async () => {
    renderRoute(<Findings />, '/findings');
    expect(await screen.findByText('possible subdomain takeover via Azure App Service')).toBeInTheDocument();
    expect(screen.getByText('Missing Strict-Transport-Security header')).toBeInTheDocument();
    expect(screen.queryByText('Missing X-Content-Type-Options header')).not.toBeInTheDocument(); // low
    expect(screen.queryByText('A record changed from baseline')).not.toBeInTheDocument(); // acknowledged
    expect(await screen.findByText('Showing 10 of 14 findings (medium and above).')).toBeInTheDocument();
    expect(screen.getByLabelText('Min severity')).toHaveValue('medium');
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/findings$/);
  });

  it('brings low and info back with one click and writes it to the URL', async () => {
    renderRoute(<Findings />, '/findings');
    await userEvent.click(await screen.findByRole('button', { name: 'Include low and info' }));
    expect(await screen.findByText('Missing X-Content-Type-Options header')).toBeInTheDocument();
    expect(screen.getByText('Showing all 14 findings.')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('min_severity=info');
    await userEvent.click(screen.getByRole('button', { name: 'Hide low and info' }));
    await waitFor(() => expect(screen.queryByText('Missing X-Content-Type-Options header')).not.toBeInTheDocument());
    expect(screen.getByTestId('location')).not.toHaveTextContent('min_severity');
  });

  it('reads every filter from the URL', async () => {
    renderRoute(<Findings />, '/findings', '/findings?min_severity=high&check=net.ports&zone=example.com&source=discovered&q=ssh');
    expect(await screen.findByText('SSH exposed to the internet')).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(2);
    expect(screen.getByLabelText('Min severity')).toHaveValue('high');
    expect(screen.getByLabelText('Check')).toHaveValue('net.ports');
    expect(screen.getByLabelText('Source')).toHaveValue('discovered');
    expect(screen.getByLabelText('Zone')).toHaveValue('example.com');
    expect(screen.getByLabelText('Search')).toHaveValue('ssh');
  });

  it('writes filter changes back to the URL', async () => {
    renderRoute(<Findings />, '/findings');
    await screen.findByText('SSH exposed to the internet');
    await userEvent.selectOptions(screen.getByLabelText('Min severity'), 'critical');
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('min_severity=critical'));
    await userEvent.selectOptions(screen.getByLabelText('Check'), 'nuclei');
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('check=nuclei'));
    await userEvent.click(screen.getByRole('button', { name: /Acknowledged/ }));
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('status=open&status=acknowledged'));
    expect(await screen.findByText(/Log4j2/)).toBeInTheDocument();
  });

  it('filters to an exact severity from a dashboard tile link', async () => {
    renderRoute(<Findings />, '/findings', '/findings?severity=high');
    expect(await screen.findByText('SSH exposed to the internet')).toBeInTheDocument();
    expect(screen.queryByText(/Log4j2/)).not.toBeInTheDocument(); // critical
    expect(screen.getByText('Showing 3 high findings.')).toBeInTheDocument();
  });

  it('shows severity as text, plus kev, new-24h and reopened badges and the full column set', async () => {
    renderRoute(<Findings />, '/findings');
    const kev = (await screen.findByText(/Apache Log4j2 remote code execution/)).closest('tr') as HTMLElement;
    expect(within(kev).getByText('KEV')).toBeInTheDocument();
    expect(within(kev).getByText(/^New/)).toBeInTheDocument();
    expect(within(kev).getByText('critical')).toBeInTheDocument();
    expect(within(kev).getByText('Open')).toBeInTheDocument();
    const hygiene = screen.getByText('example.com has no DMARC record').closest('tr') as HTMLElement;
    expect(within(hygiene).getByText('Reopened 2×')).toBeInTheDocument();
    expect(within(hygiene).queryByText('KEV')).not.toBeInTheDocument();
    expect(within(hygiene).getByText('dns.hygiene')).toBeInTheDocument();
    const heads = screen.getAllByRole('columnheader').map((h) => h.textContent);
    expect(heads).toEqual(['Severity', 'Finding', 'Asset', 'Zone', 'Check', 'Status', 'First seen', 'Last seen']);
  });

  it('sorts by severity, last seen and first seen from the column headers', async () => {
    renderRoute(<Findings />, '/findings');
    await screen.findByText('SSH exposed to the internet');
    expect(rowTitles()[0]).toMatch(/Azure App Service|Log4j2/); // critical first
    await userEvent.click(screen.getByRole('button', { name: 'First seen' }));
    expect(screen.getByTestId('location')).toHaveTextContent('sort=first_seen');
    // newest first_seen (the 2h-old CSP finding) leads
    await waitFor(() => expect(rowTitles()[0]).toBe('Missing Content-Security-Policy header'));
    await userEvent.click(screen.getByRole('button', { name: 'First seen' }));
    expect(screen.getByTestId('location')).toHaveTextContent('dir=asc');
    await waitFor(() => expect(rowTitles()[0]).toBe('example.com has no DMARC record')); // oldest first seen: 40d
    expect(screen.getByRole('columnheader', { name: /First seen/ })).toHaveAttribute('aria-sort', 'ascending');
    await userEvent.click(screen.getByRole('button', { name: 'Last seen' }));
    expect(screen.getByTestId('location')).toHaveTextContent('sort=last_seen');
  });

  it('groups by check with counts and expands a group inline', async () => {
    renderRoute(<Findings />, '/findings', '/findings?group=check');
    const toggle = await screen.findByRole('button', { name: /tls\.cert/ });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(toggle).toHaveAccessibleName('tls.cert, 2 findings: 1 high, 1 medium');
    expect(screen.queryByText(/TLS certificate on shop/)).not.toBeInTheDocument();
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(await screen.findByText(/TLS certificate on shop.example.org/)).toBeInTheDocument();
    expect(screen.getByText('7 check groups')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Expand all' }));
    expect(await screen.findByText('SSH exposed to the internet')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Collapse all' }));
    expect(screen.queryByText('SSH exposed to the internet')).not.toBeInTheDocument();
  });

  it('groups by asset (worst group first) and by zone from the selector', async () => {
    renderRoute(<Findings />, '/findings');
    await screen.findByText('SSH exposed to the internet');
    await userEvent.selectOptions(screen.getByLabelText('Group by'), 'asset');
    expect(screen.getByTestId('location')).toHaveTextContent('group=asset');
    const groups = await screen.findAllByRole('button', { name: /findings?\b/ });
    expect(groups[0]).toHaveAccessibleName('promo.example.com, 2 findings: 1 critical, 1 high'); // worst first
    await userEvent.selectOptions(screen.getByLabelText('Group by'), 'zone');
    expect(await screen.findByRole('button', { name: 'example.org, 1 finding: 1 medium' })).toBeInTheDocument();
  });
});

describe('Finding drawer', () => {
  it('opens from a row with title, description, remediation, tags and a readable evidence table', async () => {
    renderRoute(<Findings />, '/findings');
    await userEvent.click(await screen.findByRole('button', { name: 'possible subdomain takeover via Azure App Service' }));
    const dlg = await screen.findByRole('dialog', { name: 'Finding details' });
    expect(screen.getByTestId('location')).toHaveTextContent('finding=1');
    expect(within(dlg).getByRole('heading', { name: 'possible subdomain takeover via Azure App Service' })).toBeInTheDocument();
    expect(within(dlg).getByText('critical')).toBeInTheDocument();
    expect(within(dlg).getByText(/An attacker could register that resource/)).toBeInTheDocument();
    expect(within(dlg).getByText(/Prefer deleting the DNS record before decommissioning/)).toBeInTheDocument();
    expect(within(dlg).getByText('azure-app-service')).toBeInTheDocument();
    const ev = within(dlg).getByRole('table', { name: /Evidence for possible subdomain takeover/ });
    expect(within(ev).getByRole('rowheader', { name: 'Provider' })).toBeInTheDocument();
    expect(within(ev).getByText('Azure App Service')).toBeInTheDocument();
    expect(ev.textContent).not.toContain('{');
  });

  it('closes with Escape and the close button, restoring the URL', async () => {
    renderRoute(<Findings />, '/findings', '/findings?finding=3');
    const dlg = await screen.findByRole('dialog', { name: 'Finding details' });
    expect(within(dlg).getByRole('button', { name: 'Close' })).toHaveFocus();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByTestId('location')).not.toHaveTextContent('finding=');
  });

  it('opens a finding straight from a link, even one outside the list filters', async () => {
    renderRoute(<Findings />, '/findings', '/findings?finding=13');
    const dlg = await screen.findByRole('dialog', { name: 'Finding details' });
    expect(await within(dlg).findByRole('heading', { name: 'Unexpected port 8080 open' })).toBeInTheDocument();
    expect(within(dlg).getByText('Resolved')).toBeInTheDocument();
    expect(within(dlg).getByText('Resolved findings cannot be changed.')).toBeInTheDocument();
  });

  it('renders expiry as absolute and relative time and ports as chips', async () => {
    renderRoute(<Findings />, '/findings', '/findings?finding=3');
    const ev = await screen.findByRole('table', { name: /Evidence for TLS certificate on 203/ });
    expect(within(ev).getByRole('rowheader', { name: 'Expires' })).toBeInTheDocument();
    expect(within(ev).getByText(/\(in 6d\)/)).toBeInTheDocument();
    expect(within(ev).getByText(/UTC/)).toBeInTheDocument();
    expect(within(ev).getByRole('list', { name: 'Ports' })).toHaveTextContent('443');
    expect(within(ev).getByRole('rowheader', { name: 'Served by' })).toBeInTheDocument();
  });

  it('shows KEV and EPSS intelligence', async () => {
    renderRoute(<Findings />, '/findings', '/findings?finding=5');
    const intel = await screen.findByLabelText('Exploit intelligence');
    expect(intel).toHaveTextContent('Known exploited (CISA KEV, added 2021-12-10)');
    expect(intel).toHaveTextContent('used in ransomware campaigns');
    expect(intel).toHaveTextContent('Required action: Apply updates per vendor instructions.');
    expect(intel).toHaveTextContent('EPSS 94.4%');
    expect(intel).toHaveTextContent('(99.9th percentile)');
  });

  it('links to the asset, other findings on it, and the same check in the same zone', async () => {
    renderRoute(<Findings />, '/findings', '/findings?finding=1');
    const dlg = await screen.findByRole('dialog', { name: 'Finding details' });
    expect(await within(dlg).findByRole('link', { name: /Open asset promo.example.com/ })).toHaveAttribute('href', '/assets/11');
    const other = within(dlg).getByRole('link', { name: 'Other findings on this asset' });
    expect(other).toHaveAttribute('href', '/findings?asset_id=11&min_severity=info');
    const same = within(dlg).getByRole('link', { name: 'Same check, same zone' });
    expect(same).toHaveAttribute('href', '/findings?check=dns.takeover&zone=example.com&min_severity=info');
    await waitFor(() => expect(within(dlg).getByText('(2 open)')).toBeInTheDocument()); // asset 11 has 2 open
  });

  it('acknowledges directly from the drawer', async () => {
    renderRoute(<Findings />, '/findings', '/findings?finding=4');
    const dlg = await screen.findByRole('dialog', { name: 'Finding details' });
    await userEvent.click(await within(dlg).findByRole('button', { name: 'Acknowledge' }));
    await waitFor(() => expect(state.findings.find((f) => f.id === 4)?.status).toBe('acknowledged'));
    expect(await within(dlg).findByRole('button', { name: 'Reopen' })).toBeInTheDocument();
  });

  it('suppress needs a reason; false-positive and reopen work', async () => {
    renderRoute(<Findings />, '/findings', '/findings?finding=3');
    const drawer = await screen.findByRole('dialog', { name: 'Finding details' });
    await userEvent.click(await within(drawer).findByRole('button', { name: 'Suppress' }));
    const dlg = (await screen.findAllByRole('dialog')).find((d) => d !== drawer) as HTMLElement;
    await userEvent.click(within(dlg).getByRole('button', { name: 'Suppress' }));
    expect(within(dlg).getByText('A reason is required.')).toBeInTheDocument();
    await userEvent.type(within(dlg).getByLabelText(/Reason/), 'accepted until renewal');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Suppress' }));
    await waitFor(() => expect(state.findings.find((f) => f.id === 3)).toMatchObject({ status: 'suppressed', suppression_note: 'accepted until renewal' }));
    await userEvent.click(await within(drawer).findByRole('button', { name: 'Reopen' }));
    await waitFor(() => expect(state.findings.find((f) => f.id === 3)?.status).toBe('open'));

    await userEvent.click(await within(drawer).findByRole('button', { name: 'False positive' }));
    const fp = (await screen.findAllByRole('dialog')).find((d) => d !== drawer) as HTMLElement;
    await userEvent.type(within(fp).getByLabelText(/Reason/), 'scanner artefact');
    await userEvent.click(within(fp).getByRole('button', { name: 'Mark false positive' }));
    await waitFor(() => expect(state.findings.find((f) => f.id === 3)?.status).toBe('false_positive'));
  });

  it('Escape inside the suppress dialog closes only that dialog', async () => {
    renderRoute(<Findings />, '/findings', '/findings?finding=6');
    const drawer = await screen.findByRole('dialog', { name: 'Finding details' });
    await userEvent.click(await within(drawer).findByRole('button', { name: 'Suppress' }));
    await screen.findByRole('dialog', { name: 'Suppress finding' });
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Suppress finding' })).not.toBeInTheDocument());
    expect(screen.getByRole('dialog', { name: 'Finding details' })).toBeInTheDocument();
  });

  it('queues a rescan of the asset', async () => {
    let rescanned = 0;
    server.use(http.post('*/api/v1/assets/11/rescan', () => { rescanned = 11; return HttpResponse.json({}, { status: 202 }); }));
    renderRoute(<Findings />, '/findings', '/findings?finding=1');
    await userEvent.click(await screen.findByRole('button', { name: /Rescan asset/ }));
    await waitFor(() => expect(rescanned).toBe(11));
    expect(await screen.findByText('Rescan queued for promo.example.com.')).toBeInTheDocument();
  });

  it('copies a ticket-ready markdown summary', async () => {
    const user = userEvent.setup();
    renderRoute(<Findings />, '/findings', '/findings?finding=1');
    await user.click(await screen.findByRole('button', { name: /Copy as markdown/ }));
    expect(await screen.findByText('Copied to clipboard.')).toBeInTheDocument();
    const md = await navigator.clipboard.readText();
    expect(md).toContain('## [CRITICAL] possible subdomain takeover via Azure App Service');
    expect(md).toContain('- **Asset:** `promo.example.com`');
    expect(md).toContain('### Remediation');
    expect(md).toContain('- `cname`: promo-site.azurewebsites.net');
    expect(md).toContain('/findings?finding=1');
  });

  it('disables write actions for read-only users but still allows copy', async () => {
    state.canWrite = false;
    renderRoute(<Findings />, '/findings', '/findings?finding=6');
    const dlg = await screen.findByRole('dialog', { name: 'Finding details' });
    expect(await within(dlg).findByRole('button', { name: 'Acknowledge' })).toBeDisabled();
    expect(within(dlg).getByRole('button', { name: /Rescan asset/ })).toBeDisabled();
    expect(within(dlg).getByRole('button', { name: /Copy as markdown/ })).toBeEnabled();
    state.canWrite = true;
  });
});

describe('Inventory', () => {
  it('lists, filters and paginates assets, hiding removed ones by default', async () => {
    renderRoute(<Inventory />, '/inventory');
    expect(await screen.findByRole('link', { name: 'www.example.com' })).toBeInTheDocument();
    expect(screen.queryByText('old.example.com')).not.toBeInTheDocument(); // removed hidden
    await userEvent.click(screen.getByLabelText('Include removed'));
    expect(await screen.findByRole('link', { name: 'old.example.com' })).toBeInTheDocument();
    expect(screen.getByText(/1-16 of 16/)).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('include_removed=1');
  });

  it('shows findings count with worst severity and last scanned per asset', async () => {
    renderRoute(<Inventory />, '/inventory');
    const promo = (await screen.findByRole('link', { name: 'promo.example.com' })).closest('tr') as HTMLElement;
    const badge = await within(promo).findByLabelText('2 open findings on promo.example.com, worst critical');
    expect(badge).toHaveAttribute('href', '/findings?asset_id=11&min_severity=info');
    expect(within(badge).getByText('critical')).toBeInTheDocument(); // text, not colour alone
    const clean = screen.getByRole('link', { name: 'example.org' }).closest('tr') as HTMLElement;
    await waitFor(() => expect(within(clean).getAllByRole('cell')[5]).toHaveTextContent('0'));
    // asset 1 was scanned 1m ago in the mock runs, asset 11 never
    const zone = screen.getByRole('link', { name: 'example.com' }).closest('tr') as HTMLElement;
    expect(within(zone).getAllByRole('cell')[6]).toHaveTextContent('1m ago');
    expect(within(promo).getAllByRole('cell')[6]).toHaveTextContent('-');
  });

  it('reads kind, scope, source, zone and search from the URL', async () => {
    renderRoute(<Inventory />, '/inventory', '/inventory?kind=hostname&scope=owned&source=cloudflare&zone=example.org&q=shop');
    expect(await screen.findByRole('link', { name: 'shop.example.org' })).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(2);
    expect(screen.getByLabelText('Kind')).toHaveValue('hostname');
    expect(screen.getByLabelText('Scope')).toHaveValue('owned');
    expect(screen.getByLabelText('Source')).toHaveValue('cloudflare');
    expect(screen.getByLabelText('Zone')).toHaveValue('example.org');
    expect(screen.getByLabelText('Search')).toHaveValue('shop');
  });

  it('writes filter changes to the URL', async () => {
    renderRoute(<Inventory />, '/inventory');
    await screen.findByRole('link', { name: 'www.example.com' });
    await userEvent.selectOptions(screen.getByLabelText('Kind'), 'ip');
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('kind=ip'));
    await userEvent.selectOptions(screen.getByLabelText('Scope'), 'external');
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('scope=external'));
    expect(await screen.findByRole('link', { name: '198.51.100.7' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: '203.0.113.10' })).not.toBeInTheDocument();
  });

  it('"has open findings >= medium" keeps only assets with needles, worst first, and persists in the URL', async () => {
    renderRoute(<Inventory />, '/inventory');
    await screen.findByRole('link', { name: 'www.example.com' });
    await userEvent.click(screen.getByLabelText('Has open findings ≥ medium'));
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('needles=1'));
    await waitFor(() => expect(screen.queryByRole('link', { name: 'example.org' })).not.toBeInTheDocument()); // no findings
    const keys = screen.getAllByRole('row').slice(1).map((r) => within(r).getAllByRole('link')[0]?.textContent);
    // both critical; www has more open findings (3 vs 2), so it leads
    expect(keys.slice(0, 2)).toEqual(['www.example.com', 'promo.example.com']);
    expect(keys).toContain('api.example.com'); // medium only, sorts after the criticals and highs
    expect(keys).toContain('staging.example.com');
    expect(keys).not.toContain('_domainkey.example.com'); // only a low finding
  });

  it('applies the needles toggle straight from the URL', async () => {
    renderRoute(<Inventory />, '/inventory', '/inventory?needles=1&scope=owned');
    expect(await screen.findByRole('link', { name: 'promo.example.com' })).toBeInTheDocument();
    expect(screen.getByLabelText('Has open findings ≥ medium')).toBeChecked();
  });

  it('says what to do when the toggle matches nothing', async () => {
    renderRoute(<Inventory />, '/inventory', '/inventory?needles=1&zone=nope.example');
    expect(await screen.findByText(/No assets with an open finding at medium or above/)).toBeInTheDocument();
  });

  it('renders the map view for an asset', async () => {
    renderRoute(<Inventory />, '/inventory', '/inventory?view=map&asset=2');
    const list = await screen.findByRole('list', { name: 'graph nodes' });
    expect(within(list).getByText('203.0.113.10')).toBeInTheDocument();
    expect(within(list).getByText('www.example.com')).toBeInTheDocument();
  });
});

describe('Asset detail', () => {
  const panel = async (name: string) => within(await screen.findByRole('region', { name }));

  it('leads with a properties panel: kind, scope meaning, source, zone, times, status, findings by severity', async () => {
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/2');
    expect(await screen.findByRole('heading', { name: 'www.example.com' })).toBeInTheDocument();
    const props = await panel('Properties');
    expect(props.getByText('hostname')).toBeInTheDocument();
    expect(props.getByText('owned')).toBeInTheDocument();
    expect(props.getByText(/passive, active and intrusive checks/)).toBeInTheDocument();
    expect(props.getByRole('link', { name: 'cloudflare' })).toHaveAttribute('href', '/inventory?source=cloudflare');
    expect(props.getByRole('link', { name: 'example.com' })).toHaveAttribute('href', '/inventory?zone=example.com');
    expect(props.getByText(/30d ago/)).toBeInTheDocument(); // first seen
    expect(props.getByText('Live')).toBeInTheDocument();
    expect(props.getByLabelText('1 open critical findings')).toHaveAttribute('href', '/findings?asset_id=2&severity=critical');
    expect(props.getByLabelText('1 open medium findings')).toBeInTheDocument();
    expect(props.getByLabelText('1 open low findings')).toBeInTheDocument();
    expect(props.queryByLabelText(/open high findings/)).not.toBeInTheDocument();
  });

  it('shows the latest observation time per check and flags stale ones', async () => {
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/2');
    const props = await panel('Properties');
    const list = (await props.findByText('http.headers', { selector: 'span.font-mono' })).closest('ul') as HTMLElement;
    const row = (check: string) => within(list).getByText(check).closest('li') as HTMLElement;
    expect(within(row('http.headers')).getByText('7m ago')).toBeInTheDocument();
    expect(within(row('http.headers')).queryByText(/stale/)).not.toBeInTheDocument();
    expect(within(row('net.ports')).getByText(/2d ago/)).toBeInTheDocument();
    expect(within(row('net.ports')).getByText(/stale/)).toBeInTheDocument(); // 40h > 36h
  });

  it('shows a readable DNS path for a healthy chain, with the addresses it resolves to', async () => {
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/2');
    const dns = await panel('DNS chain');
    const hops = within(dns.getByRole('list', { name: 'Chain' })).getAllByRole('listitem');
    expect(hops.map((h) => h.textContent)).toEqual(['www.example.com', 'www.example.com.cdn.cloudflare.netresolves']);
    expect(dns.getByText('203.0.113.10')).toBeInTheDocument();
    expect(dns.getByText('The chain resolves.')).toBeInTheDocument();
  });

  it('highlights an NXDOMAIN chain end in red, with text', async () => {
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/11');
    const dns = await panel('DNS chain');
    const hops = within(dns.getByRole('list', { name: 'Chain' })).getAllByRole('listitem');
    expect(hops.map((h) => h.textContent?.replace(/NXDOMAIN$/, ' NXDOMAIN'))).toEqual([
      'promo.example.com',
      'promo-site.trafficmanager.net',
      'promo-site.azurewebsites.net NXDOMAIN',
    ]);
    const last = within(hops[2] as HTMLElement).getByText('promo-site.azurewebsites.net', { exact: false }).closest('span') as HTMLElement;
    expect(last.className).toContain('text-bad');
    expect(dns.getByText(/does not exist \(NXDOMAIN\)/)).toBeInTheDocument();
    expect(dns.queryByText(/Resolves to/)).not.toBeInTheDocument();
  });

  it('marks a removed asset', async () => {
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/4');
    const props = await panel('Properties');
    expect(props.getByText('Removed')).toBeInTheDocument();
    expect(props.queryByText('Live')).not.toBeInTheDocument();
  });

  it('shows observations readably and baselines with changed-since markers', async () => {
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/2');
    const obs = await panel('Latest observations');
    expect((await obs.findAllByText(/1 differ from baseline/)).length).toBe(2); // dns.baseline + net.ports
    await userEvent.click(obs.getByText('dns.baseline'));
    const table = obs.getByRole('table', { name: 'Observation dns.baseline' });
    expect(within(table).getByText('203.0.113.77')).toBeInTheDocument();
    expect(within(table).getByText('changed')).toBeInTheDocument();
    expect(table.textContent).not.toContain('{');

    const base = await panel('Baselines');
    expect(base.getByText('stable')).toBeInTheDocument();
    expect(base.getByText('learning (2)')).toBeInTheDocument();
    expect(base.getAllByText(/1 changed since 2d ago/).length).toBe(2);
    const dns = base.getByRole('table', { name: 'Baseline dns.baseline' });
    expect(within(dns).getAllByText('203.0.113.10')).toHaveLength(2); // baseline and latest
    expect(within(dns).getByText('changed')).toBeInTheDocument();
    expect(within(dns).getByText('203.0.113.77')).toBeInTheDocument();
  });

  it('lists open findings, opens one in the drawer, and triggers a rescan', async () => {
    let rescanned = false;
    server.use(http.post('*/api/v1/assets/2/rescan', () => { rescanned = true; return HttpResponse.json({}, { status: 202 }); }));
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/2');
    expect(await screen.findByText('Missing Strict-Transport-Security header')).toBeInTheDocument();
    expect(await screen.findByText('203.0.113.10', { selector: 'a' })).toBeInTheDocument(); // relation, from the wire-shape edge
    await userEvent.click(screen.getByRole('button', { name: 'Missing Strict-Transport-Security header' }));
    const dlg = await screen.findByRole('dialog', { name: 'Finding details' });
    expect(screen.getByTestId('location')).toHaveTextContent('/assets/2?finding=6');
    expect(await within(dlg).findByRole('heading', { name: 'Missing Strict-Transport-Security header' })).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /Rescan now/ }));
    await waitFor(() => expect(rescanned).toBe(true));
    expect(await screen.findByText('Rescan queued.')).toBeInTheDocument();
  });

  it('says what to do when nothing is known yet', async () => {
    server.use(
      http.get('*/api/v1/assets/16', () =>
        HttpResponse.json({
          asset: { id: 16, kind: 'url', key: 'https://staging.example.com/', source: 'kubernetes', scope: 'owned', first_seen: new Date().toISOString(), last_seen: new Date().toISOString() },
          edges: [],
          observations: [],
          baselines: [],
          findings: [],
        }),
      ),
    );
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/16');
    expect(await screen.findByText('No open findings on this asset.')).toBeInTheDocument();
    expect(screen.getByText(/Never scanned/)).toBeInTheDocument();
    expect(screen.getByText(/No baselines learned yet/)).toBeInTheDocument();
    expect(screen.getByText('No relations.')).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'DNS chain' })).not.toBeInTheDocument();
  });

  it('explains what shared and external scope mean for probing', async () => {
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/6');
    const props = await panel('Properties');
    expect(props.getByText('external')).toBeInTheDocument();
    expect(props.getByText(/never probed by IP or service port/)).toBeInTheDocument();
  });

  it('shows an error for unknown assets', async () => {
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/999');
    expect(await screen.findByRole('alert')).toHaveTextContent('asset not found');
  });
});

describe('Sources & scans', () => {
  it('shows sync status, scan errors and triggers a sync', async () => {
    let synced = '';
    server.use(http.post('*/api/v1/sources/:name/sync', ({ params }) => { synced = String(params.name); return HttpResponse.json({}, { status: 202 }); }));
    renderRoute(<Sources />, '/sources');
    expect(await screen.findByText('AccessDenied: sts:AssumeRole')).toBeInTheDocument();
    expect(await screen.findByText(/dial tcp 203.0.113.10:443/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Sync aws now' }));
    await waitFor(() => expect(synced).toBe('aws'));
  });

  it('disables write actions for read-only users', async () => {
    state.canWrite = false;
    renderRoute(<Sources />, '/sources');
    expect(await screen.findByRole('button', { name: 'Sync aws now' })).toBeDisabled();
    state.canWrite = true;
  });
});

describe('Login and auth gate', () => {
  const gate = () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    configureClient({ redirect: vi.fn(), onUnauthorized: () => void client.resetQueries({ queryKey: ['me'] }) });
    return render(
      <QueryClientProvider client={client}>
        <AuthGate><p>secret app</p></AuthGate>
      </QueryClientProvider>,
    );
  };

  it('shows login on bearer 401, then the app after a valid token is entered', async () => {
    server.use(
      http.get('*/api/v1/me', ({ request }) =>
        request.headers.get('authorization') === 'Bearer good'
          ? HttpResponse.json({ identity: 'tok', can_write: true })
          : HttpResponse.json({ error: { code: 'unauthorized', message: 'invalid token' } }, { status: 401 }),
      ),
      http.get('*/api/v1/events', () => new HttpResponse(null, { status: 503 })),
    );
    gate();
    const input = await screen.findByLabelText('API token');
    await userEvent.type(input, 'good');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText('secret app')).toBeInTheDocument();
    expect(sessionStorage.getItem('deckard_token')).toBe('good');
  });

  it('redirects to login_url for OIDC sessions', async () => {
    const redirect = vi.fn();
    server.use(
      http.get('*/api/v1/me', () =>
        HttpResponse.json({ error: { code: 'login_required', message: 'x', login_url: '/auth/login' } }, { status: 401 }),
      ),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    configureClient({ redirect });
    render(<QueryClientProvider client={client}><AuthGate><p>app</p></AuthGate></QueryClientProvider>);
    await waitFor(() => expect(redirect).toHaveBeenCalledWith('/auth/login'));
  });

  it('validates an empty token', async () => {
    render(<QueryClientProvider client={new QueryClient()}><Login /></QueryClientProvider>);
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Enter an API token.');
  });
});
