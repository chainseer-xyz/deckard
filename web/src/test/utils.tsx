import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { makeHandlers } from '../../mock/handlers';
import type { MockState } from '../../mock/handlers';
import { makeFindings } from '../../mock/data';

export function mockServer(state?: Partial<MockState>) {
  const s: MockState = { findings: makeFindings(), canWrite: true, ...state };
  return { state: s, server: setupServer(...makeHandlers(s)) };
}

export function renderRoute(ui: ReactElement, path = '/', route = path) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route path={path.split('?')[0]} element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
