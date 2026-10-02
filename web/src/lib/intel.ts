import type { Finding } from '../api/types';

/** Exploit intelligence deckard attaches to CVE findings (CISA KEV, FIRST EPSS). */
export interface Intel {
  kev: boolean;
  kevDateAdded?: string;
  kevRansomware: boolean;
  kevRequiredAction?: string;
  /** EPSS exploitation probability, 0 to 1. */
  epss?: number;
  /** EPSS percentile, 0 to 1. */
  epssPercentile?: number;
}

function num(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1 ? v : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined;
}

/** Reads the kev tag and the kev/epss evidence keys; null when there is none. */
export function intelOf(f: Pick<Finding, 'tags' | 'evidence'>): Intel | null {
  const ev = f.evidence ?? {};
  const kev = (f.tags ?? []).some((t) => t.toLowerCase() === 'kev') || ev.kev === true;
  const epss = num(ev.epss);
  if (!kev && epss === undefined) return null;
  return {
    kev,
    kevDateAdded: str(ev.kev_date_added),
    kevRansomware: ev.kev_ransomware === true,
    kevRequiredAction: str(ev.kev_required_action),
    epss,
    epssPercentile: num(ev.epss_percentile),
  };
}

/** 0.99975 -> "99.9th percentile" (floored so a top score never reads as 100th). */
export function pctile(p: number): string {
  return `${(Math.floor(p * 1000) / 10).toFixed(1)}th percentile`;
}

/** 0.94434 -> "94.4%"; tiny non-zero scores show as "<0.1%". */
export function pct(p: number): string {
  if (p > 0 && p < 0.001) return '<0.1%';
  return `${(p * 100).toFixed(1)}%`;
}
