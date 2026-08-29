import { useMemo, useRef } from 'react';
import AlertRow from './AlertRow';
import EmptyState from '../common/EmptyState';
import { compareBySeverityThenTime } from '../../utils/severityUtils';

const COLUMNS = ['Severity', 'Threat Class', 'Confidence', 'Source IP', 'Destination IP', 'Protocol', 'Timestamp', 'Flow ID'];

/**
 * Live, filterable alert table. Sorted severity-first so the most urgent
 * detections never scroll below the fold during a demo, with newest-first
 * as the tiebreaker.
 */
export default function LiveAlertFeed({ alerts, onSelect, sortBySeverity = true, title = 'Live Alert Feed', maxHeight = 'max-h-[420px]' }) {
  const seenIds = useRef(new Set());

  const sorted = useMemo(() => {
    const list = [...alerts];
    if (sortBySeverity) list.sort(compareBySeverityThenTime);
    return list;
  }, [alerts, sortBySeverity]);

  return (
    <div className="flex flex-col rounded-lg border border-border bg-surface-1 shadow-panel">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h3 className="text-sm font-semibold text-ink-primary">{title}</h3>
        <span className="font-mono text-[11px] text-ink-muted">{alerts.length} shown</span>
      </div>

      {sorted.length === 0 ? (
        <EmptyState
          title="No alerts match the current filters"
          description="Adjust filters, or wait for new detections to arrive on the live feed."
        />
      ) : (
        <div className={`overflow-auto ${maxHeight}`}>
          <table className="w-full border-collapse">
            <thead className="sticky top-0 z-10 bg-surface-2">
              <tr className="text-left text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                {COLUMNS.map((c) => (
                  <th key={c} className="whitespace-nowrap px-3 py-2 font-medium">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sorted.map((alert) => {
                const isNew = !seenIds.current.has(alert.flow_id);
                seenIds.current.add(alert.flow_id);
                return <AlertRow key={alert.flow_id} alert={alert} onClick={onSelect} isNew={isNew} />;
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
