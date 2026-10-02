const c = (v) => `rgb(var(--${v}) / <alpha-value>)`;

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: c('bg'),
        surface: c('surface'),
        surface2: c('surface2'),
        line: c('line'),
        fg: c('fg'),
        muted: c('muted'),
        accent: c('accent'),
        'accent-fg': c('accent-fg'),
        sev: {
          critical: c('sev-critical'),
          high: c('sev-high'),
          medium: c('sev-medium'),
          low: c('sev-low'),
          info: c('sev-info'),
        },
        ok: c('ok'),
        warn: c('warn'),
        bad: c('bad'),
      },
      fontFamily: {
        sans: ['ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};
