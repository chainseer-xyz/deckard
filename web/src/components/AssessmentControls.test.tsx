import { afterAll, afterEach, beforeAll, expect, it } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { mockServer, renderRoute } from '../test/utils';
import { assets } from '../../mock/data';
import { AssessmentControls } from './AssessmentControls';

const { server } = mockServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
const asset = { ...assets[0]!, kind: 'url' as const, key: 'https://app.example.com', scope: 'owned' as const, source: 'cloudflare' };

it('shows disabled execution without implying scanner coverage', async () => {
  renderRoute(<AssessmentControls asset={asset} canWrite />);
  expect(await screen.findByText(/Isolated assessment execution is disabled/)).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Start assessment' })).not.toBeInTheDocument();
});

it('requires explicit authorization and starts only the chosen asset', async () => {
  let received: unknown;
  server.use(
    http.get('*/api/v1/assessments', () => HttpResponse.json({ enabled: true, tools: ['zap'], results_additive: true, timeout_seconds: 300 })),
    http.post('*/api/v1/assessments', async ({ request }) => {
      received = await request.json();
      return HttpResponse.json({ id: 'run-1', tool: 'zap', asset_ids: [asset.id], status: 'running', created_at: new Date().toISOString(), expires_at: new Date().toISOString() }, { status: 202 });
    }),
    http.get('*/api/v1/assessments/run-1', () => HttpResponse.json({ id: 'run-1', tool: 'zap', asset_ids: [asset.id], status: 'partial', reason: 'coverage_unproven', cleanup_pending: true })),
  );
  renderRoute(<AssessmentControls asset={asset} canWrite />);
  const start = await screen.findByRole('button', { name: 'Start assessment' });
  expect(start).toBeDisabled();
  await userEvent.click(screen.getByRole('checkbox'));
  await userEvent.click(start);
  await waitFor(() => expect(received).toEqual({ tool: 'zap', asset_ids: [asset.id] }));
  expect(await screen.findByText(/Cleanup pending/)).toBeInTheDocument();
  expect(screen.getByText(/partial/)).toBeInTheDocument();
});

it('does not offer scans on external metadata or read-only identities', async () => {
  server.use(http.get('*/api/v1/assessments', () => HttpResponse.json({ enabled: true, tools: ['zap'], results_additive: true, timeout_seconds: 300 })));
  const { unmount } = renderRoute(<AssessmentControls asset={{ ...asset, scope: 'external' }} canWrite />);
  expect(screen.queryByRole('button', { name: 'Start assessment' })).not.toBeInTheDocument();
  unmount();
  renderRoute(<AssessmentControls asset={asset} canWrite={false} />);
  expect(await screen.findByRole('button', { name: 'Start assessment' })).toBeDisabled();
});

it('offers recovery when a controller restart loses the session', async () => {
  server.use(
    http.get('*/api/v1/assessments', () => HttpResponse.json({ enabled: true, tools: ['zap'], results_additive: true, timeout_seconds: 300 })),
    http.post('*/api/v1/assessments', () => HttpResponse.json({ id: 'lost-run', tool: 'zap', asset_ids: [asset.id], status: 'running' }, { status: 202 })),
    http.get('*/api/v1/assessments/lost-run', () => HttpResponse.json({ error: { code: 'not_found', message: 'unknown assessment session' } }, { status: 404 })),
  );
  renderRoute(<AssessmentControls asset={asset} canWrite />);
  await screen.findByRole('button', { name: 'Start assessment' });
  await userEvent.click(screen.getByRole('checkbox'));
  await userEvent.click(screen.getByRole('button', { name: 'Start assessment' }));
  const clear = await screen.findByRole('button', { name: 'Clear unavailable session' });
  expect(screen.getByText(/An unavailable session is not a clean assessment/)).toBeInTheDocument();
  await userEvent.click(clear);
  await userEvent.click(screen.getByRole('checkbox'));
  expect(screen.getByRole('button', { name: 'Start assessment' })).toBeEnabled();
});
