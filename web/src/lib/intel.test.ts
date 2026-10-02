import { describe, expect, it } from 'vitest';
import { intelOf, pct, pctile } from './intel';

describe('intelOf', () => {
  it('returns null without kev tag or epss evidence', () => {
    expect(intelOf({})).toBeNull();
    expect(intelOf({ tags: ['cve'], evidence: { matched: 'x' } })).toBeNull();
  });

  it('detects kev from the tag or the evidence flag', () => {
    expect(intelOf({ tags: ['KEV'] })?.kev).toBe(true);
    expect(intelOf({ evidence: { kev: true } })?.kev).toBe(true);
  });

  it('reads kev and epss details', () => {
    const i = intelOf({
      tags: ['kev'],
      evidence: {
        kev_date_added: '2021-12-10',
        kev_ransomware: true,
        kev_required_action: 'Patch.',
        epss: 0.5,
        epss_percentile: 0.9,
      },
    });
    expect(i).toEqual({
      kev: true,
      kevDateAdded: '2021-12-10',
      kevRansomware: true,
      kevRequiredAction: 'Patch.',
      epss: 0.5,
      epssPercentile: 0.9,
    });
  });

  it('ignores malformed epss values', () => {
    expect(intelOf({ evidence: { epss: '0.5' } })).toBeNull();
    expect(intelOf({ evidence: { epss: 7 } })).toBeNull();
  });
});

describe('pct', () => {
  it('formats probabilities', () => {
    expect(pct(0.94434)).toBe('94.4%');
    expect(pct(0)).toBe('0.0%');
    expect(pct(0.0004)).toBe('<0.1%');
  });

  it('formats percentiles without rounding up to 100', () => {
    expect(pctile(0.99975)).toBe('99.9th percentile');
    expect(pctile(0.5)).toBe('50.0th percentile');
  });
});
