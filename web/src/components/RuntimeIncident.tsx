import type { RuntimeContext } from '../lib/runtimeFinding';
import { absUtc } from '../lib/format';

export function RuntimeIncident({ context }: { context: RuntimeContext }) {
  const fields = [
    ['Namespace', context.namespace],
    ['Reported pod', context.podName],
    ['Policy', context.policy],
    ['First event in latest batch', context.firstEvent ? absUtc(context.firstEvent) : undefined],
    ['Last event in latest batch', context.lastEvent ? absUtc(context.lastEvent) : undefined],
    ['Events in latest batch', context.batchCount?.toLocaleString()],
  ];
  return (
    <section aria-label="Runtime incident" className="space-y-2 rounded-md border border-line bg-surface2/40 p-3">
      <h3 className="text-sm font-semibold">Runtime incident · Event-only</h3>
      <p className="text-xs text-muted">
        This report records observed events, not complete security coverage. Event silence, pod removal and empty reports do not prove remediation.
      </p>
      <p className="text-xs text-muted">Review the incident and record a resolution with an audit note.</p>
      <dl className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
        {fields.map(([label, value]) => (
          <div key={label} className="min-w-0">
            <dt className="text-xs text-muted">{label}</dt>
            <dd className="break-words text-xs [overflow-wrap:anywhere]">{value ?? 'Unavailable'}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
