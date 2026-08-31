import { useMemo, useRef } from 'react';
import AlertRow from './AlertRow';
import EmptyState from '../common/EmptyState';
import { compareBySeverityThenTime } from '../../utils/severityUtils';

const COLS = [
  'Severity', 'Threat Class', 'Confidence',
  'Source', 'Destination', 'Proto', 'Time', 'Flow ID', '',
];

export default function LiveAlertFeed({
  alerts,
  onSelect,
  sortBySeverity = true,
  title          = 'Live Alert Feed',
  maxHeight      = 'max-h-[440px]',
}) {
  const seenIds = useRef(new Set());

  const sorted = useMemo(() => {
    const list = [...alerts];
    if (sortBySeverity) list.sort(compareBySeverityThenTime);
    return list;
  }, [alerts, sortBySeverity]);

  return (
    <div className="card flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-border shrink-0">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-ink-primary">{title}</h3>
          <span className="rounded-full bg-surface-3 px-2 py-0.5 mono text-2xs text-ink-muted">
            {alerts.length}
          </span>
        </div>
        {sorted.length > 0 && (
          <div className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-signal animate-pulseDot shrink-0" />
            <span className="text-xs font-medium text-signal">Live</span>
          </div>
        )}
      </div>

      {/* Body */}
      {sorted.length === 0
        ? <EmptyState title="No alerts to display" description="Adjust your filters or wait for new detections." />
        : (
          <div className={`overflow-auto ${maxHeight}`}>
            <table className="w-full border-collapse">
              <thead className="sticky top-0 z-10 bg-surface-2">
                <tr>
                  {COLS.map((c, i) => (
                    <th
                      key={i}
                      className="px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-widest text-ink-muted whitespace-nowrap border-b border-border"
                    >
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sorted.map((alert) => {
                  const isNew = !seenIds.current.has(alert.flow_id);
                  seenIds.current.add(alert.flow_id);
                  return (
                    <AlertRow
                      key={alert.flow_id}
                      alert={alert}
                      onClick={onSelect}
                      isNew={isNew}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
    </div>
  );
}
