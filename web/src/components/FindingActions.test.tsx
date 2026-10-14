import { afterAll, afterEach, beforeAll, expect, it } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { mockServer, renderRoute } from '../test/utils';
import { makeFindings } from '../../mock/data';
import { FindingActions } from './FindingActions';

const { server } = mockServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

it('requires a reason to resolve a runtime incident', async () => {
  let received: unknown;
  const f = { ...makeFindings()[0]!, check: 'ext.tetragon', source: 'ingest:tetragon', status: 'open' as const };
  server.use(http.post(`*/api/v1/findings/${f.id}/resolve`, async ({ request }) => {
    received = await request.json();
    return HttpResponse.json({ ...f, status: 'resolved' });
  }));
  renderRoute(<FindingActions f={f} />);
  const button = await screen.findByRole('button', { name: 'Resolve incident' });
  await waitFor(() => expect(button).toBeEnabled());
  await userEvent.click(button);
  const reason = await screen.findByRole('textbox', { name: /Reason/ });
  await userEvent.type(reason, 'Reviewed and contained');
  await userEvent.click(screen.getByRole('button', { name: 'Resolve' }));
  await waitFor(() => expect(received).toEqual({ note: 'Reviewed and contained' }));
});

it('does not offer manual healing for an assessment finding', () => {
  renderRoute(<FindingActions f={makeFindings()[0]!} />);
  expect(screen.queryByRole('button', { name: 'Resolve incident' })).not.toBeInTheDocument();
});
