import { clearToken, getToken, markRejected } from './auth';
import type {
  AssetDetail,
  Asset,
  Baseline,
  ChangeEvent,
  Finding,
  FindingAction,
  FindingActionBody,
  Graph,
  Me,
  Page,
  ScanRun,
  Stats,
  SyncStatus,
} from './types';

export const API_BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  code: string;
  loginUrl?: string;
  constructor(status: number, code: string, message: string, loginUrl?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.loginUrl = loginUrl;
  }
  get isAuth(): boolean {
    return this.status === 401;
  }
}

// Hooks the app can override (and tests do).
interface Hooks {
  redirect: (url: string) => void;
  onUnauthorized: () => void;
}
const hooks: Hooks = {
  redirect: (url) => window.location.assign(url),
  onUnauthorized: () => {},
};
export function configureClient(h: Partial<Hooks>): void {
  Object.assign(hooks, h);
}

export type Query = Record<string, string | number | boolean | string[] | undefined | null>;

export function buildQuery(q?: Query): string {
  if (!q) return '';
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === '' || v === false) continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
    else sp.append(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

/**
 * Only same-origin relative paths may be followed; blocks open redirects.
 * Mirrors the server's safeNext: browsers strip tab/CR/LF before parsing, so
 * any control byte, backslash, or encoded variant of those is refused.
 */
export function safeLoginUrl(u: string | undefined): string | undefined {
  if (!u || !u.startsWith('/')) return undefined;
  let decoded = u;
  try {
    decoded = decodeURIComponent(u);
  } catch {
    /* keep raw */
  }
  for (const v of [u, decoded]) {
    if (v.startsWith('//') || v.includes('\\')) return undefined;
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      if (c < 0x20 || c === 0x7f) return undefined;
    }
  }
  try {
    const parsed = new URL(u, 'http://deckard.invalid');
    if (parsed.origin !== 'http://deckard.invalid') return undefined;
  } catch {
    return undefined;
  }
  return u;
}

// Session CSRF token (cookie-session mode). Memory only: it is delivered by
// GET /me, never stored in localStorage/sessionStorage or read from cookies.
let csrfToken: string | null = null;
export function setCsrfToken(t: string | null): void {
  csrfToken = t || null;
}
export function getCsrfToken(): string | null {
  return csrfToken;
}

interface ReqOpts {
  method?: string;
  query?: Query;
  body?: unknown;
  signal?: AbortSignal;
}

export function authHeaders(method = 'GET'): Record<string, string> {
  const h: Record<string, string> = { Accept: 'application/json' };
  const t = getToken();
  if (t) h.Authorization = `Bearer ${t}`;
  else if (method !== 'GET' && method !== 'HEAD' && csrfToken) h['X-CSRF-Token'] = csrfToken;
  return h;
}

export function absoluteUrl(path: string): string {
  return new URL(path, window.location.origin).toString();
}

export async function request<T>(path: string, opts: ReqOpts = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  // Cookie-session writes need the CSRF token from /me; fetch it if we have
  // not yet (bearer-token mode needs none).
  if (method !== 'GET' && method !== 'HEAD' && !getToken() && !csrfToken && path !== '/me') {
    await api.me();
  }
  const headers = authHeaders(method);
  let body: string | undefined;
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  let res: Response;
  try {
    res = await fetch(absoluteUrl(`${API_BASE}${path}${buildQuery(opts.query)}`), {
      method,
      headers,
      body,
      credentials: 'same-origin',
      signal: opts.signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network_error', e instanceof Error ? e.message : 'Network error');
  }

  const text = await res.text();
  let json: unknown;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
  }

  if (!res.ok) {
    const err = (json as { error?: { code?: string; message?: string; login_url?: string } } | undefined)
      ?.error;
    const apiErr = new ApiError(
      res.status,
      err?.code ?? `http_${res.status}`,
      err?.message ?? (res.statusText || `Request failed (${res.status})`),
      safeLoginUrl(err?.login_url),
    );
    if (res.status === 401) {
      if (apiErr.loginUrl) {
        hooks.redirect(apiErr.loginUrl);
      } else {
        // Only signal when we actually held a token; otherwise re-fetching /me
        // would 401 again and loop forever.
        if (getToken()) {
          clearToken();
          markRejected();
          hooks.onUnauthorized();
        }
      }
    }
    throw apiErr;
  }
  return json as T;
}

// ---- typed endpoints -------------------------------------------------------

export interface AssetsParams {
  kind?: string;
  source?: string;
  scope?: string;
  zone?: string;
  q?: string;
  include_removed?: boolean;
  limit?: number;
  offset?: number;
}

export interface FindingsParams {
  status?: string[];
  min_severity?: string;
  check?: string;
  zone?: string;
  source?: string;
  asset_id?: number;
  q?: string;
  limit?: number;
  offset?: number;
}

// Go's store.Baseline has no json tags, so it may arrive PascalCased.
function normBaseline(b: Record<string, unknown>): Baseline {
  const pick = <T>(a: string, b2: string): T => (b[a] ?? b[b2]) as T;
  return {
    asset_id: pick('asset_id', 'AssetID'),
    check: pick('check', 'Check'),
    data: pick<Record<string, unknown>>('data', 'Data') ?? {},
    stable: !!pick<boolean>('stable', 'Stable'),
    consistent: pick<number>('consistent', 'Consistent') ?? 0,
    updated_at: pick('updated_at', 'UpdatedAt'),
  };
}

export const api = {
  me: async (signal?: AbortSignal) => {
    const me = await request<Me>('/me', { signal });
    setCsrfToken(me.csrf_token ?? null);
    return me;
  },
  stats: () => request<Stats>('/stats'),
  assets: (p: AssetsParams = {}) => request<Page<Asset>>('/assets', { query: { ...p } }),
  asset: async (id: number): Promise<AssetDetail> => {
    const d = await request<AssetDetail>(`/assets/${id}`);
    return {
      ...d,
      edges: d.edges ?? [],
      observations: d.observations ?? [],
      findings: d.findings ?? [],
      baselines: ((d.baselines ?? []) as unknown as Record<string, unknown>[]).map(normBaseline),
    };
  },
  graph: (id: number, depth = 2) => request<Graph>(`/assets/${id}/graph`, { query: { depth } }),
  findings: (p: FindingsParams = {}) => request<Page<Finding>>('/findings', { query: { ...p } }),
  finding: (id: number) => request<Finding>(`/findings/${id}`),
  findingAction: (id: number, action: FindingAction, body: FindingActionBody) =>
    request<unknown>(`/findings/${id}/${action}`, { method: 'POST', body }),
  rescan: (assetId: number) => request<unknown>(`/assets/${assetId}/rescan`, { method: 'POST', body: {} }),
  syncSource: (name: string) =>
    request<unknown>(`/sources/${encodeURIComponent(name)}/sync`, { method: 'POST', body: {} }),
  sources: () => request<Page<SyncStatus>>('/sources'),
  scans: (limit = 50, offset = 0) => request<Page<ScanRun>>('/scans', { query: { limit, offset } }),
  changes: (limit = 25, since?: string) =>
    request<Page<ChangeEvent>>('/changes', { query: { limit, since } }),
};
