import { AlertTriangle, CheckCircle2, CircleSlash, Radio } from 'lucide-react';
import type { CollectorState } from '../api/types';
import { absUtc, relTime } from '../lib/format';
import { Empty } from './ui';

const HEALTH = {
  never: { label: 'Never reported', cls: 'text-muted', Icon: CircleSlash },
  healthy: { label: 'Report fresh', cls: 'text-ok', Icon: CheckCircle2 },
  stale: { label: 'Report overdue', cls: 'text-warn', Icon: AlertTriangle },
  reporting: { label: 'Reporting', cls: 'text-muted', Icon: Radio },
};

const COVERAGE = {
  never: 'No assessment received',
  complete: 'Latest report complete',
  incomplete: 'Incomplete assessment',
  event_only: 'Events only',
};

function ReportTime({ at }: { at?: string }) {
  return at ? <time dateTime={at} title={absUtc(at)}>{relTime(at)}</time> : <>Never</>;
}

export function CollectorHealth({ collectors }: { collectors: CollectorState[] }) {
  if (collectors.length === 0) return <Empty>No collector reports configured or received.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table aria-label="Collector reports" className="w-full text-sm">
        <thead className="border-b border-line">
          <tr>
            <th scope="col" className="th">Tool / scope</th>
            <th scope="col" className="th">Report delivery</th>
            <th scope="col" className="th">Coverage</th>
            <th scope="col" className="th">Last report</th>
            <th scope="col" className="th">Last complete assessment</th>
            <th scope="col" className="th">Findings</th>
          </tr>
        </thead>
        <tbody>
          {collectors.map((c) => {
            const health = HEALTH[c.health];
            return (
              <tr key={JSON.stringify([c.tool, c.scope])} className="border-b border-line/60">
                <td className="td max-w-xs whitespace-normal">
                  <div className="font-medium">{c.tool}</div>
                  <div className="break-words text-xs text-muted">{c.scope}</div>
                </td>
                <td className="td">
                  <span className={`inline-flex items-center gap-1 text-xs font-medium ${health.cls}`}>
                    <health.Icon size={12} aria-hidden="true" />{health.label}
                  </span>
                  {c.expected_interval_seconds > 0 ? (
                    <div className="text-xs text-muted">Expected every {c.expected_interval_seconds}s</div>
                  ) : <div className="text-xs text-muted">No freshness interval configured</div>}
                </td>
                <td className="td max-w-xs whitespace-normal text-xs">
                  <span>{COVERAGE[c.coverage]}</span>
                  {c.coverage === 'event_only' && (
                    <div className="text-muted">Event silence does not establish complete coverage.</div>
                  )}
                </td>
                <td className="td text-xs"><ReportTime at={c.last_report} /></td>
                <td className="td text-xs">
                  {c.coverage === 'event_only' ? 'Not applicable' : <ReportTime at={c.last_complete} />}
                </td>
                <td className="td text-xs tabular-nums">{c.open_findings} open {c.open_findings === 1 ? 'finding' : 'findings'}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
