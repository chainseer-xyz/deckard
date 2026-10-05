import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { api, ApiError, buildQuery, configureClient, safeLoginUrl, setCsrfToken } from './client';
import { clearToken, getToken, setToken } from './auth';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const redirect = vi.fn();
const onUnauthorized = vi.fn();
beforeEach(() => {
  redirect.mockReset();
  onUnauthorized.mockReset();
  configureClient({ redirect, onUnauthorized });
  clearToken();
  setCsrfToken(null);
});

describe('api client', () => {
  it('preserves an empty group key for the no-zone member page', () => {
    expect(buildQuery({ group_by: 'zone', group_key: '', q: '' })).toBe('?group_by=zone&group_key=');
  });
  it('sends the bearer token and no CSRF header on GET', async () => {
    setToken('s3cret');
    let auth: string | null = null;
    let csrf: string | null = 'x';
    server.use(
      http.get('*/api/v1/stats', ({ request }) => {
        auth = request.headers.get('authorization');
        csrf = request.headers.get('x-csrf-token');
        return HttpResponse.json({});
      }),
    );
    await api.stats();
    expect(auth).toBe('Bearer s3cret');
    expect(csrf).toBeNull();
  });

  it('keeps the token in sessionStorage, not localStorage', () => {
    setToken('abc');
    expect(sessionStorage.getItem('deckard_token')).toBe('abc');
    expect(localStorage.length).toBe(0);
    expect(getToken()).toBe('abc');
  });

  it('reads csrf_token from /me and sends it on POST in cookie mode', async () => {
    let csrf: string | null = null;
    let body: unknown;
    server.use(
      http.get('*/api/v1/me', () => HttpResponse.json({ subject: 'u', method: 'cookie', csrf_token: 'tok123' })),
      http.post('*/api/v1/findings/7/acknowledge', async ({ request }) => {
        csrf = request.headers.get('x-csrf-token');
        body = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await api.me();
    await api.findingAction(7, 'acknowledge', { note: 'ok' });
    expect(csrf).toBe('tok123');
    expect(body).toEqual({ note: 'ok' });
  });

  it('fetches /me on demand when a write happens before /me, and refreshes on re-fetch', async () => {
    let n = 0;
    const seen: (string | null)[] = [];
    server.use(
      http.get('*/api/v1/me', () => HttpResponse.json({ subject: 'u', csrf_token: `t${++n}` })),
      http.post('*/api/v1/assets/1/rescan', ({ request }) => {
        seen.push(request.headers.get('x-csrf-token'));
        return new HttpResponse(null, { status: 202 });
      }),
    );
    await api.rescan(1);
    expect(seen).toEqual(['t1']);
    await api.me();
    await api.rescan(1);
    expect(seen).toEqual(['t1', 't2']);
  });

  it('never persists the CSRF token and never reads cookies', async () => {
    server.use(http.get('*/api/v1/me', () => HttpResponse.json({ subject: 'u', csrf_token: 'secret-csrf' })));
    await api.me();
    expect(JSON.stringify({ ...localStorage })).not.toContain('secret-csrf');
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('secret-csrf');
    expect(document.cookie).not.toContain('secret-csrf');
  });

  it('sends no CSRF header in bearer-token mode', async () => {
    setToken('s3cret');
    let csrf: string | null = 'x';
    let meCalls = 0;
    server.use(
      http.get('*/api/v1/me', () => {
        meCalls++;
        return HttpResponse.json({ subject: 'token' });
      }),
      http.post('*/api/v1/assets/1/rescan', ({ request }) => {
        csrf = request.headers.get('x-csrf-token');
        return new HttpResponse(null, { status: 202 });
      }),
    );
    await api.rescan(1);
    expect(csrf).toBeNull();
    expect(meCalls).toBe(0);
  });

  it('redirects to login_url on 401 login_required', async () => {
    server.use(
      http.get('*/api/v1/me', () =>
        HttpResponse.json(
          { error: { code: 'login_required', message: 'login', login_url: '/auth/login' } },
          { status: 401 },
        ),
      ),
    );
    await expect(api.me()).rejects.toMatchObject({ status: 401, code: 'login_required' });
    expect(redirect).toHaveBeenCalledWith('/auth/login');
  });

  it('clears the token and signals on a bearer 401', async () => {
    setToken('bad');
    server.use(
      http.get('*/api/v1/me', () =>
        HttpResponse.json({ error: { code: 'unauthorized', message: 'bad token' } }, { status: 401 }),
      ),
    );
    await expect(api.me()).rejects.toBeInstanceOf(ApiError);
    expect(getToken()).toBeNull();
    expect(onUnauthorized).toHaveBeenCalled();
    expect(redirect).not.toHaveBeenCalled();
  });

  it('does not signal unauthorized when no token was sent (avoids refetch loops)', async () => {
    server.use(
      http.get('*/api/v1/me', () =>
        HttpResponse.json({ error: { code: 'unauthorized', message: 'no token' } }, { status: 401 }),
      ),
    );
    await expect(api.me()).rejects.toMatchObject({ status: 401 });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it('refuses off-origin login URLs', () => {
    expect(safeLoginUrl('https://evil.example/x')).toBeUndefined();
    expect(safeLoginUrl('//evil.example')).toBeUndefined();
    expect(safeLoginUrl('/auth/login')).toBe('/auth/login');
  });

  it.each([
    ['tab', '/\t/evil.com'],
    ['newline', '/\n/evil.com'],
    ['cr', '/\r/evil.com'],
    ['nul', '/\x00/evil.com'],
    ['del', '/\x7f/evil.com'],
    ['backslash', '/\\evil.com'],
    ['mid backslash', '/a\\b'],
    ['double slash', '//evil.com'],
    ['http', 'http://evil.com'],
    ['javascript', 'javascript:alert(1)'],
    ['encoded tab', '/%09/evil.com'],
    ['encoded slash', '/%2f/evil.com'],
    ['encoded backslash', '/%5cevil.com'],
    ['relative', 'evil.com'],
    ['empty', ''],
  ])('safeLoginUrl rejects %s', (_n, u) => {
    expect(safeLoginUrl(u)).toBeUndefined();
  });

  it('safeLoginUrl accepts ordinary paths and unicode slashes', () => {
    expect(safeLoginUrl('/auth/login?next=%2Ffindings')).toBe('/auth/login?next=%2Ffindings');
    expect(safeLoginUrl('/\u2215evil.com')).toBe('/\u2215evil.com');
  });

  it('maps error envelopes to ApiError', async () => {
    server.use(
      http.get('*/api/v1/findings/9', () =>
        HttpResponse.json({ error: { code: 'not_found', message: 'no such finding' } }, { status: 404 }),
      ),
    );
    await expect(api.finding(9)).rejects.toMatchObject({
      status: 404,
      code: 'not_found',
      message: 'no such finding',
    });
  });

  it('maps non-JSON failures and network errors', async () => {
    server.use(http.get('*/api/v1/stats', () => new HttpResponse('boom', { status: 502 })));
    await expect(api.stats()).rejects.toMatchObject({ status: 502, code: 'http_502' });
    server.use(http.get('*/api/v1/stats', () => HttpResponse.error()));
    await expect(api.stats()).rejects.toMatchObject({ status: 0, code: 'network_error' });
  });

  it('builds repeated and omitted query params', () => {
    expect(buildQuery({ status: ['open', 'suppressed'], q: '', limit: 10, x: undefined })).toBe(
      '?status=open&status=suppressed&limit=10',
    );
  });

  it('normalises PascalCase baselines', async () => {
    server.use(
      http.get('*/api/v1/assets/1', () =>
        HttpResponse.json({
          asset: { id: 1 },
          edges: null,
          observations: null,
          findings: null,
          baselines: [
            { AssetID: 1, Check: 'tls', Data: { a: 1 }, Stable: true, Consistent: 5, UpdatedAt: 't' },
          ],
        }),
      ),
    );
    const d = await api.asset(1);
    expect(d.baselines[0]).toMatchObject({ asset_id: 1, check: 'tls', stable: true, consistent: 5 });
    expect(d.edges).toEqual([]);
  });
});

describe('api.asset edge normalisation', () => {
  const peer = { id: 2, kind: 'hostname', key: 'peer.example.com', scope: 'owned' };
  it('maps the server wire shape {direction, asset} to {outbound, other}', async () => {
    server.use(
      http.get('*/api/v1/assets/1', () =>
        HttpResponse.json({
          asset: { id: 1 },
          edges: [
            { direction: 'out', type: 'cname_to', asset: peer },
            { direction: 'in', type: 'in_zone', asset: peer },
          ],
          observations: [],
          baselines: [],
          findings: [],
        }),
      ),
    );
    const d = await api.asset(1);
    expect(d.edges).toEqual([
      { outbound: true, type: 'cname_to', other: peer },
      { outbound: false, type: 'in_zone', other: peer },
    ]);
  });

  it('passes already-normalised edges through', async () => {
    server.use(
      http.get('*/api/v1/assets/1', () =>
        HttpResponse.json({ asset: { id: 1 }, edges: [{ outbound: false, type: 'x', other: peer }], observations: [] }),
      ),
    );
    expect((await api.asset(1)).edges).toEqual([{ outbound: false, type: 'x', other: peer }]);
  });
});
