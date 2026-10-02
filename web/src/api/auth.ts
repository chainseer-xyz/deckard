// Bearer token lives in memory and sessionStorage only (never localStorage,
// never cookies). OIDC cookie sessions need no client-side state.

const KEY = 'deckard_token';
let memToken: string | null = null;

function ss(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  if (memToken) return memToken;
  try {
    const t = ss()?.getItem(KEY) ?? null;
    if (t) memToken = t;
    return t;
  } catch {
    return null;
  }
}

let rejected = false;
/** The server refused the token we sent (so the login screen can say so). */
export function markRejected(): void {
  rejected = true;
}
export const wasRejected = (): boolean => rejected;

export function setToken(token: string): void {
  rejected = false;
  memToken = token;
  try {
    ss()?.setItem(KEY, token);
  } catch {
    /* storage unavailable: memory only */
  }
}

export function clearToken(): void {
  memToken = null;
  try {
    ss()?.removeItem(KEY);
  } catch {
    /* ignore */
  }
}
