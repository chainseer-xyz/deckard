import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { mockServer, renderRoute } from '../test/utils';
import Findings from './Findings';
import Inventory from './Inventory';

const { server } = mockServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterAll(() => server.close());
afterEach(() => server.resetHandlers());

describe('search debounce preserves newer filters', () => {
  it('keeps a severity change made while a findings search is pending', async () => {
    renderRoute(<Findings />, '/findings');
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search' }), 'needle');
    await userEvent.selectOptions(screen.getByLabelText('Min severity'), 'critical');
    expect(screen.getByTestId('location')).toHaveTextContent('min_severity=critical');
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('q=needle'));
    expect(screen.getByTestId('location')).toHaveTextContent('min_severity=critical');
    expect(screen.getByLabelText('Min severity')).toHaveValue('critical');
  });

  it('keeps a scope change made while an inventory search is pending', async () => {
    renderRoute(<Inventory />, '/inventory');
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search' }), 'needle');
    await userEvent.selectOptions(screen.getByLabelText('Scope'), 'owned');
    expect(screen.getByTestId('location')).toHaveTextContent('scope=owned');
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('q=needle'));
    expect(screen.getByTestId('location')).toHaveTextContent('scope=owned');
    expect(screen.getByLabelText('Scope')).toHaveValue('owned');
  });
});
