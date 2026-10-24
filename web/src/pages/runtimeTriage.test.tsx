import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { AppRoutes } from '../App';
import { makeFindings } from '../../mock/data';
import { LocationProbe, mockServer, renderRoute } from '../test/utils';
import Findings from './Findings';

const { server, state } = mockServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => {
  server.resetHandlers();
  state.findings = makeFindings();
  state.canWrite = true;
});
afterAll(() => server.close());

function renderApp(route: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <LocationProbe />
        <AppRoutes />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function runtimeFinding() {
  return {
    ...makeFindings()[0]!,
    check: 'ext.tetragon', source: 'ingest:tetragon', severity: 'medium' as const,
    title: 'Tetragon runtime policy: memory-execution-detect',
    asset_key: 'runtime:k8s:uid:cluster-123:tetragon:opaque-subject-hash',
    evidence: {
      runtime_namespace: 'apps', runtime_pod_name: 'web-1', runtime_rule: 'memory-execution-detect',
      runtime_first_seen: '2026-10-24T10:00:00Z', runtime_last_seen: '2026-10-24T10:05:00Z',
      runtime_batch_count: 23,
    },
  };
}

describe('finding notification links', () => {
  it('opens a legacy finding URL and preserves filters while the path ID wins', async () => {
    renderApp('/findings/13?source=cloudflare&finding=1');
    const drawer = await screen.findByRole('dialog', { name: 'Finding details' });
    expect(await within(drawer).findByRole('heading', { name: 'Unexpected port 8080 open' })).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/findings?source=cloudflare&finding=13');
    expect(screen.queryByRole('heading', { name: 'Dashboard' })).not.toBeInTheDocument();
  });

  it.each(['0', '-1', 'invalid', '1.5', '9007199254740992'])('rejects an invalid legacy finding ID: %s', async (id) => {
    renderApp(`/findings/${id}?source=cloudflare&finding=1`);
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/findings?source=cloudflare'));
    expect(screen.getByTestId('location')).not.toHaveTextContent('finding=');
    expect(screen.queryByRole('dialog', { name: 'Finding details' })).not.toBeInTheDocument();
  });
});

describe('runtime triage context', () => {
  it('shows the reported namespace and pod instead of an opaque attachment key in rows', async () => {
    state.findings = [runtimeFinding()];
    renderRoute(<Findings />, '/findings');
    const row = (await screen.findByRole('button', { name: state.findings[0]!.title })).closest('tr')!;
    expect(within(row).getByRole('link', { name: 'apps/web-1' })).toHaveAttribute('href', '/assets/11');
    expect(row).toHaveTextContent('Event-only · memory-execution-detect');
    expect(row).not.toHaveTextContent('opaque-subject-hash');
  });

  it('explains event-only lifecycle and exposes the latest batch without asserting coverage', async () => {
    state.findings = [runtimeFinding()];
    renderRoute(<Findings />, '/findings', '/findings?finding=1');
    const drawer = await screen.findByRole('dialog', { name: 'Finding details' });
    const runtime = await within(drawer).findByRole('region', { name: 'Runtime incident' });
    expect(runtime).toHaveTextContent('apps');
    expect(runtime).toHaveTextContent('web-1');
    expect(runtime).toHaveTextContent('memory-execution-detect');
    expect(runtime).toHaveTextContent('First event in latest batch');
    expect(runtime).toHaveTextContent('2026-10-24 10:00 UTC');
    expect(runtime).toHaveTextContent('Last event in latest batch');
    expect(runtime).toHaveTextContent('2026-10-24 10:05 UTC');
    expect(runtime).toHaveTextContent('Events in latest batch23');
    expect(runtime).toHaveTextContent(/Event silence, pod removal and empty reports do not prove remediation/);
    expect(within(drawer).queryByText('Missed runs')).not.toBeInTheDocument();
    expect(within(drawer).getByRole('button', { name: /Rescan asset/ })).toBeDisabled();
    expect(within(drawer).queryByText('Refresh this finding through its external scanner.')).not.toBeInTheDocument();
    // The exact stored attachment identity remains available, not rewritten.
    expect(within(drawer).getByRole('link', { name: state.findings[0]!.asset_key })).toBeInTheDocument();
  });

  it('keeps resolution behind an audit note after displaying runtime context', async () => {
    state.findings = [runtimeFinding()];
    let received: unknown;
    server.use(http.post('*/api/v1/findings/1/resolve', async ({ request }) => {
      received = await request.json();
      return HttpResponse.json({ ...state.findings[0]!, status: 'resolved' });
    }));
    renderRoute(<Findings />, '/findings', '/findings?finding=1');
    const drawer = await screen.findByRole('dialog', { name: 'Finding details' });
    const action = await within(drawer).findByRole('button', { name: 'Resolve incident' });
    await waitFor(() => expect(action).toBeEnabled());
    await userEvent.click(action);
    const modal = await screen.findByRole('dialog', { name: 'Resolve runtime incident' });
    await userEvent.click(within(modal).getByRole('button', { name: 'Resolve' }));
    expect(received).toBeUndefined();
    expect(within(modal).getByText('A reason is required.')).toBeInTheDocument();
    await userEvent.type(within(modal).getByRole('textbox', { name: /Reason/ }), 'Reviewed workload and contained the incident');
    await userEvent.click(within(modal).getByRole('button', { name: 'Resolve' }));
    await waitFor(() => expect(received).toEqual({ note: 'Reviewed workload and contained the incident' }));
  });
});
