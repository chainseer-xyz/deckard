import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { mockServer, renderRoute } from '../test/utils';
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
});
afterAll(() => server.close());

describe('Dashboard', () => {
  it('shows severity tiles, checks, changes and source health with stale highlighting', async () => {
    renderRoute(<Dashboard />);
    expect(await screen.findByLabelText('2 open critical findings')).toBeInTheDocument();
    expect(screen.getByLabelText('3 open high findings')).toBeInTheDocument();
    expect(screen.getByText('tls.cert')).toBeInTheDocument();
    expect((await screen.findAllByText('Finding opened')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Healthy')).length).toBeGreaterThan(0);
    expect(screen.getByText('Failing')).toBeInTheDocument();
    expect(screen.getAllByText('Stale').length).toBeGreaterThan(0);
    expect(screen.getByText(/AccessDenied/)).toBeInTheDocument();
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
