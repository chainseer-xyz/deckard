import { useCallback, useEffect, useState } from 'react';

export type ThemePref = 'light' | 'dark' | 'system';
const KEY = 'deckard_theme';

export function loadTheme(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'light' || v === 'dark') return v;
  } catch {
    /* ignore */
  }
  return 'system';
}

export function applyTheme(p: ThemePref): void {
  const el = document.documentElement;
  if (p === 'system') el.removeAttribute('data-theme');
  else el.setAttribute('data-theme', p);
}

export function useTheme() {
  const [pref, setPref] = useState<ThemePref>(loadTheme);
  useEffect(() => {
    applyTheme(pref);
    try {
      if (pref === 'system') localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, pref);
    } catch {
      /* ignore */
    }
  }, [pref]);
  const cycle = useCallback(
    () => setPref((p) => (p === 'system' ? 'light' : p === 'light' ? 'dark' : 'system')),
    [],
  );
  return { pref, cycle };
}
