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
  it('lists open findings by default, filters from the URL, and sorts', async () => {
    renderRoute(<Findings />, '/findings', '/findings?min_severity=high');
    expect(await screen.findByText('possible subdomain takeover via Azure App Service')).toBeInTheDocument();
    expect(screen.getByText('SSH exposed to the internet')).toBeInTheDocument();
    expect(screen.queryByText('Missing Strict-Transport-Security header')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Min severity')).toHaveValue('high');
    // severity is text, not colour only
    expect(screen.getAllByText('critical').length).toBeGreaterThan(0);
    const rows = screen.getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('critical');
    await userEvent.click(screen.getByRole('button', { name: /^Age/ }));
    await userEvent.click(screen.getByRole('button', { name: /^Age/ }));
  });

  it('expands evidence and remediation', async () => {
    renderRoute(<Findings />, '/findings', '/findings?status=any');
    await userEvent.click(await screen.findByRole('button', { name: /Expand details for TLS certificate on 203/ }));
    expect(screen.getByLabelText(/Evidence for TLS certificate/)).toHaveTextContent('"issuer": "Let\'s Encrypt R3"');
    expect(screen.getAllByText(/Renew the certificate now/).length).toBeGreaterThan(0);
  });

  it('shows KEV badge and EPSS chip as text, and the intel details when expanded', async () => {
    renderRoute(<Findings />, '/findings', '/findings');
    const kevRow = (await screen.findByText(/Apache Log4j2 remote code execution/)).closest('tr') as HTMLElement;
    expect(within(kevRow).getByText('KEV')).toBeInTheDocument();
    expect(within(kevRow).getByText('EPSS 94.4%')).toBeInTheDocument();

    const epssRow = screen.getByText(/Example Server information disclosure/).closest('tr') as HTMLElement;
    expect(within(epssRow).getByText('EPSS 31.3%')).toBeInTheDocument();
    expect(within(epssRow).queryByText('KEV')).not.toBeInTheDocument();

    const plainRow = screen.getByText('SSH exposed to the internet').closest('tr') as HTMLElement;
    expect(within(plainRow).queryByText('KEV')).not.toBeInTheDocument();
    expect(within(plainRow).queryByText(/EPSS/)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /Expand details for Apache Log4j2/ }));
    const intel = await screen.findByLabelText('Exploit intelligence');
    expect(intel).toHaveTextContent('Known exploited (CISA KEV, added 2021-12-10)');
    expect(intel).toHaveTextContent('used in ransomware campaigns');
    expect(intel).toHaveTextContent('Required action: Apply updates per vendor instructions.');
    expect(intel).toHaveTextContent('(99.9th percentile)');
  });

  it('acknowledges directly and suppression requires a reason', async () => {
    renderRoute(<Findings />, '/findings', '/findings');
    await userEvent.click(await screen.findByRole('button', { name: /Acknowledge: SSH exposed/ }));
    await waitFor(() => expect(state.findings.find((f) => f.id === 4)?.status).toBe('acknowledged'));

    await userEvent.click(await screen.findByRole('button', { name: /Suppress: TLS certificate on 203/ }));
    const dlg = await screen.findByRole('dialog');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Suppress' }));
    expect(within(dlg).getByText('A reason is required.')).toBeInTheDocument();
    await userEvent.type(within(dlg).getByLabelText(/Reason/), 'accepted until renewal');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Suppress' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(state.findings.find((f) => f.id === 3)).toMatchObject({
      status: 'suppressed',
      suppression_note: 'accepted until renewal',
    });
  });
});

describe('Inventory', () => {
  it('lists, filters and paginates assets', async () => {
    renderRoute(<Inventory />, '/inventory');
    expect(await screen.findByRole('link', { name: 'www.example.com' })).toBeInTheDocument();
    expect(screen.queryByText('old.example.com')).not.toBeInTheDocument(); // removed hidden
    await userEvent.click(screen.getByLabelText('Include removed'));
    expect(await screen.findByRole('link', { name: 'old.example.com' })).toBeInTheDocument();
    expect(screen.getByText(/1-16 of 16/)).toBeInTheDocument();
  });

  it('renders the map view for an asset', async () => {
    renderRoute(<Inventory />, '/inventory', '/inventory?view=map&asset=2');
    const list = await screen.findByRole('list', { name: 'graph nodes' });
    expect(within(list).getByText('203.0.113.10')).toBeInTheDocument();
    expect(within(list).getByText('www.example.com')).toBeInTheDocument();
  });
});

describe('Asset detail', () => {
  it('shows relations, observations, baselines, findings and triggers a rescan', async () => {
    let rescanned = false;
    server.use(http.post('*/api/v1/assets/2/rescan', () => { rescanned = true; return HttpResponse.json({}, { status: 202 }); }));
    renderRoute(<AssetDetail />, '/assets/:id', '/assets/2');
    expect(await screen.findByRole('heading', { name: 'www.example.com' })).toBeInTheDocument();
    expect(await screen.findByText('203.0.113.10')).toBeInTheDocument(); // relation
    expect(screen.getByText('http.headers', { selector: 'span' })).toBeInTheDocument();
    expect(screen.getByText('stable')).toBeInTheDocument();
    expect(screen.getByText('learning (2)')).toBeInTheDocument();
    expect(screen.getByText('Missing Strict-Transport-Security header')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Rescan now/ }));
    await waitFor(() => expect(rescanned).toBe(true));
    expect(await screen.findByText('Rescan queued.')).toBeInTheDocument();
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
