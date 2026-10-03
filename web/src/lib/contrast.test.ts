import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// vitest runs from web/ (css processing is off, so read the file directly)
const css = readFileSync(resolve(process.cwd(), 'src/index.css'), 'utf8');

/** Reads `--name: r g b;` tokens from the first block that follows `selector {`. */
function tokens(selector: string): Record<string, [number, number, number]> {
  const start = css.indexOf(`${selector} {`);
  const body = css.slice(start, css.indexOf('}', start));
  const out: Record<string, [number, number, number]> = {};
  for (const m of body.matchAll(/--([\w-]+):\s*(\d+)\s+(\d+)\s+(\d+);/g)) out[m[1] as string] = [Number(m[2]), Number(m[3]), Number(m[4])];
  return out;
}

const lum = ([r, g, b]: number[]) => {
  const f = (c: number) => ((c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * f(r as number) + 0.7152 * f(g as number) + 0.0722 * f(b as number);
};
const ratio = (a: number[], b: number[]) => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return ((hi as number) + 0.05) / ((lo as number) + 0.05);
};
/** Colour of `fg` at `alpha` over `bg`, as the tinted badge backgrounds render. */
const over = (fg: number[], bg: number[], alpha: number) => fg.map((c, i) => c * alpha + (bg[i] as number) * (1 - alpha));

const TEXT = ['sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info', 'ok', 'warn', 'bad', 'muted', 'accent'];

describe.each([
  ['light', ':root'],
  ['dark', ":root[data-theme='dark']"],
])('%s theme contrast (WCAG AA, 4.5:1)', (_name, selector) => {
  const t = tokens(selector);
  it.each(TEXT)('%s is readable on surface and surface2', (name) => {
    for (const bg of ['surface', 'surface2', 'bg']) expect(ratio(t[name] as number[], t[bg] as number[])).toBeGreaterThanOrEqual(4.5);
  });
  it.each(['sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info', 'warn', 'bad', 'ok'])(
    '%s text is readable on its own 10% tint (badge background)',
    (name) => {
      expect(ratio(t[name] as number[], over(t[name] as number[], t.surface as number[], 0.1))).toBeGreaterThanOrEqual(4.5);
    },
  );
});
