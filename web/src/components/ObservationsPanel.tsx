import type { Baseline, Observation } from '../api/types';
import { baselineView, isStaleObservation } from '../lib/assetView';
import { diffData } from '../lib/evidence';
import { absTime, relTime } from '../lib/format';
import { ChangeMark, EvidenceTable, EvidenceValue } from './Evidence';
import { Card, Empty } from './ui';

/** Latest observation per check, with keys that differ from the learned baseline marked. */
export function ObservationsCard({ observations, baselines, now }: { observations: Observation[]; baselines: Baseline[]; now?: number }) {
  const base = new Map(baselines.map((b) => [b.check, b]));
  return (
    <Card title="Latest observations">
      {observations.length === 0 && <Empty>No observations yet. Use Rescan now to run the checks.</Empty>}
      {observations.map((o) => {
        const b = base.get(o.check);
        const changes = b ? diffData(b.data, o.data) : undefined;
        const stale = isStaleObservation(o.observed_at, now);
        return (
          <details key={o.check} className="border-b border-line px-3 py-2 last:border-b-0">
            <summary className="cursor-pointer text-sm">
              <span className="font-mono text-xs font-semibold">{o.check}</span>{' '}
              <span className={`text-xs ${stale ? 'font-semibold text-warn' : 'text-muted'}`} title={absTime(o.observed_at)}>
                {relTime(o.observed_at, now)}
                {stale && ' · stale'}
              </span>
              {changes && changes.size > 0 && (
                <span className="ml-2 text-xs font-medium text-warn">{changes.size} differ from baseline</span>
              )}
            </summary>
            <div className="mt-2">
              <EvidenceTable data={o.data} label={`Observation ${o.check}`} changes={changes} now={now} />
            </div>
          </details>
        );
      })}
    </Card>
  );
}

export function BaselinesCard({ observations, baselines, now }: { observations: Observation[]; baselines: Baseline[]; now?: number }) {
  const obs = new Map(observations.map((o) => [o.check, o]));
  return (
    <Card title="Baselines">
      {baselines.length === 0 && <Empty>No baselines learned yet. They are learned from repeated, consistent observations.</Empty>}
      {baselines.map((b) => {
        const v = baselineView(b, obs.get(b.check));
        const drift = v.sinceBaseline && v.changes > 0;
        return (
          <details key={b.check} className="border-b border-line px-3 py-2 last:border-b-0" open={drift}>
            <summary className="cursor-pointer text-sm">
              <span className="font-mono text-xs font-semibold">{b.check}</span>{' '}
              <span className={`text-xs ${b.stable ? 'text-ok' : 'text-warn'}`}>
                {b.stable ? 'stable' : `learning (${b.consistent})`}
              </span>
              {drift && (
                <span className="ml-2 text-xs font-medium text-warn">
                  {v.changes} changed since {relTime(b.updated_at, now)}
                </span>
              )}
            </summary>
            <p className="mt-1 text-xs text-muted">
              Baseline updated <span title={absTime(b.updated_at)}>{relTime(b.updated_at, now)}</span>, consistent for {b.consistent} runs.
            </p>
            <table className="mt-1 w-full text-sm" aria-label={`Baseline ${b.check}`}>
              <thead>
                <tr className="text-left text-xs text-muted">
                  <th scope="col" className="w-1/4 py-1 pr-3 font-medium">Key</th>
                  <th scope="col" className="py-1 pr-3 font-medium">Baseline</th>
                  <th scope="col" className="py-1 font-medium">Latest</th>
                </tr>
              </thead>
              <tbody>
                {v.rows.map((r) => (
                  <tr key={r.key} className="border-t border-line/60">
                    <th scope="row" className="py-1.5 pr-3 align-top text-xs font-medium text-muted">{r.label}</th>
                    <td className="py-1.5 pr-3 align-top">
                      {r.baseline === undefined ? <span className="text-muted">—</span> : <EvidenceValue row={{ kind: r.kind, label: r.label, value: r.baseline }} now={now} />}
                    </td>
                    <td className="py-1.5 align-top">
                      {r.change ? (
                        <>
                          {r.latest === undefined ? <span className="text-muted">—</span> : <EvidenceValue row={{ kind: r.kind, label: r.label, value: r.latest }} now={now} />}
                          <ChangeMark change={r.change} />
                        </>
                      ) : (
                        <span className="text-muted">same</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        );
      })}
    </Card>
  );
}
