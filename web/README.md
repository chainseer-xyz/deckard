# deckard web UI

React 18 + Vite + TypeScript (strict) + Tailwind + react-router + TanStack Query.
Built to `web/dist`, which the Dockerfile copies to `internal/api/ui/dist` for `go:embed`.
No runtime network calls to third parties: icons (lucide) and fonts (system stack) are bundled.

## Scripts

Use Node 22 or 24 (`nvm use 22`).

| script | what |
| --- | --- |
| `npm run dev` | Vite dev server; proxies `/api` and `/auth` to `localhost:8080` |
| `npm run dev:mock` | dev server with an in-browser msw backend (`web/mock/`), no Go needed |
| `npm run build` | typecheck, then production build into `dist/` |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | vitest + testing-library + msw |
| `npm run lint` | eslint |

## Layout

- `src/api/` typed client (`client.ts`), bearer token handling (`auth.ts`), fetch-based SSE
  with reconnect state machine (`sse.ts`), TanStack hooks (`hooks.ts`), wire types (`types.ts`).
- `src/lib/` pure logic: findings filter/URL state and suppress validation, graph layout, formatting, theme.
- `src/components/`, `src/pages/` UI. Pages are route-code-split; the graph (reactflow) is a separate lazy chunk.
- `mock/` msw dataset and handlers, shared by `dev:mock` and the page tests.

## Auth

- Bearer: the login screen takes a token, kept in memory and `sessionStorage` only, sent as `Authorization: Bearer`.
  Tradeoff: any script running on the page origin (an XSS) can read `sessionStorage`, so the token is only as safe
  as the page's CSP and dependencies; it is cleared when the tab closes. Prefer OIDC (HttpOnly sealed cookie) for
  shared deployments.
- OIDC cookie session: a 401 `login_required` from `/me` redirects to `login_url` (same-origin paths only, same
  rule as the server: no control bytes, backslashes, `//` prefix or encoded variants).
- The session CSRF token comes from `GET /api/v1/me` (`csrf_token`), is held in module memory only (never
  storage, never a cookie) and is sent as `X-CSRF-Token` on every non-GET request in cookie-session mode; it is
  refreshed whenever `/me` is re-fetched. Bearer mode sends no CSRF header. Logout is `POST /auth/logout` with that header.

## Live updates

`GET /api/v1/events` is streamed with `fetch` (EventSource cannot send headers). `change` events invalidate
cached queries (debounced); on drop it reconnects with exponential backoff (1s doubling to 30s, jittered) and
refetches once back. The header shows Live / Connecting / Offline.

## Conventions and assumptions

- Findings URL state: `status` repeats; absent means `open`; `status=any` means all. Sorting (severity/age)
  is applied client-side to the fetched page because the API has no sort parameter.
- Source health: `failing` if the last run errored, `stale` if last success is older than 12h (`STALE_AFTER_MS`).
- Go `time.Time` zero values (`0001-01-01`) render as "never".
- `store.Baseline` has no json tags in Go, so the client accepts both `snake_case` and `PascalCase` keys.

## Node version

Develop and run the tests on **Node 22** (`nvm use` reads `.nvmrc`; CI and the
Dockerfile use 22). On Node 24 five async page tests fail inside jsdom because
Node 24 fetch rejects jsdom's AbortSignal (cross-realm brand check). The
production build is unaffected. Tracked as a follow-up (try happy-dom or a
vitest browser mode).
