import { NavLink, Outlet } from 'react-router-dom';
import { Suspense } from 'react';
import { Activity, Boxes, LayoutDashboard, Monitor, Moon, ShieldAlert, Sun } from 'lucide-react';
import { LiveIndicator } from './Live';
import { Loading } from './ui';
import { useTheme } from '../lib/theme';
import { useMe } from '../api/hooks';
import { Brand } from './Brand';

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/inventory', label: 'Inventory', icon: Boxes, end: false },
  { to: '/findings', label: 'Findings', icon: ShieldAlert, end: false },
  { to: '/sources', label: 'Sources & Scans', icon: Activity, end: false },
];

export function ThemeToggle() {
  const { pref, cycle } = useTheme();
  const Icon = pref === 'light' ? Sun : pref === 'dark' ? Moon : Monitor;
  return (
    <button
      className="btn btn-sm"
      onClick={cycle}
      aria-label={`Theme: ${pref}. Activate to change.`}
      title={`Theme: ${pref}`}
    >
      <Icon size={14} aria-hidden="true" />
      <span className="hidden sm:inline">{pref}</span>
    </button>
  );
}

export function Layout() {
  const me = useMe();
  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded-sm focus:bg-accent focus:px-3 focus:py-1 focus:text-accent-fg"
      >
        Skip to content
      </a>
      <header className="sticky top-0 z-40 border-b border-line bg-surface">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2">
          <Brand className="h-8 shrink-0" />
          <nav aria-label="Main" className="flex flex-1 flex-wrap items-center gap-1">
            {nav.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.end}
                className={({ isActive }) =>
                  `flex items-center gap-1.5 rounded-md px-2.5 py-1 text-sm ${
                    isActive ? 'bg-surface2 font-semibold text-fg' : 'text-muted hover:bg-surface2 hover:text-fg'
                  }`
                }
              >
                <n.icon size={14} aria-hidden="true" />
                {n.label}
              </NavLink>
            ))}
          </nav>
          <div className="flex items-center gap-2">
            <LiveIndicator />
            <ThemeToggle />
            {me.data && (
              <span className="hidden text-xs text-muted md:inline" title={me.data.can_write ? 'Read/write' : 'Read-only'}>
                {me.data.identity}
                {!me.data.can_write && ' (read-only)'}
              </span>
            )}
          </div>
        </div>
      </header>
      <main id="main" tabIndex={-1} className="mx-auto max-w-7xl px-4 py-4">
        <Suspense fallback={<Loading />}>
          <Outlet />
        </Suspense>
      </main>
    </div>
  );
}
