import { lazy } from 'react';
import type { ReactNode } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ApiError, configureClient } from './api/client';
import { useMe } from './api/hooks';
import { Layout } from './components/Layout';
import { LiveProvider } from './components/Live';
import { ErrorBox, Loading } from './components/ui';
import { Login } from './pages/Login';
import { wasRejected } from './api/auth';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const Inventory = lazy(() => import('./pages/Inventory'));
const Findings = lazy(() => import('./pages/Findings'));
const AssetDetail = lazy(() => import('./pages/AssetDetail'));
const Sources = lazy(() => import('./pages/Sources'));

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: true,
        retry: (n, e) => !(e instanceof ApiError && e.status >= 400 && e.status < 500) && n < 2,
      },
    },
  });
}

/** Shows the login screen until /me succeeds; OIDC 401s redirect in the client. */
export function AuthGate({ children }: { children: ReactNode }) {
  const me = useMe();
  if (me.isLoading) return <Loading label="Connecting" />;
  if (me.error instanceof ApiError && me.error.status === 401) {
    // With a login_url the client already redirected; show nothing while it navigates.
    if (me.error.loginUrl) return <Loading label="Redirecting to sign-in" />;
    return <Login message={wasRejected() ? `Token rejected: ${me.error.message}` : undefined} />;
  }
  if (me.isError) return <ErrorBox error={me.error} onRetry={() => void me.refetch()} />;
  return <LiveProvider>{children}</LiveProvider>;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="inventory" element={<Inventory />} />
        <Route path="findings" element={<Findings />} />
        <Route path="assets/:id" element={<AssetDetail />} />
        <Route path="sources" element={<Sources />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default function App({ client }: { client?: QueryClient }) {
  const qc = client ?? makeQueryClient();
  configureClient({ onUnauthorized: () => void qc.resetQueries({ queryKey: ['me'] }) });
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <AuthGate>
          <AppRoutes />
        </AuthGate>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
