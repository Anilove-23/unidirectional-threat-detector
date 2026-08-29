import { formatEvidenceKey } from '../../utils/threatUtils';
import { formatEvidenceValue as fmtVal } from '../../utils/alertFormatters';

/**
 * Renders whatever evidence fields are present on the alert — never
 * hardcoded to a specific threat class's field set (e.g. beacon interval
 * for BOTNET_C2_BEACONING). New evidence keys the backend adds later show
 * up automatically with a generated label.
 */
export default function EvidencePanel({ evidence }) {
  const entries = Object.entries(evidence ?? {});

  if (entries.length === 0) {
    return <p className="text-xs text-ink-muted">No supporting evidence attached to this alert.</p>;
  }

  return (
    <dl className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
      {entries.map(([key, value]) => (
        <div key={key} className="rounded border border-border bg-surface-2 px-3 py-2">
          <dt className="text-[10px] font-medium uppercase tracking-wide text-ink-muted">{formatEvidenceKey(key)}</dt>
          <dd className="mt-0.5 truncate font-mono text-xs text-ink-primary" title={fmtVal(value)}>
            {fmtVal(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}
