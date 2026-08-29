import { SEVERITY_META } from '../../utils/severityUtils';

/**
 * The single, consistent severity badge used everywhere in the app —
 * summary cards, table rows, filters, and the drill-down modal all render
 * severity through this component so the visual vocabulary never drifts.
 */
export default function SeverityBadge({ severity, size = 'md' }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.LOW;
  const sizeClasses = size === 'sm' ? 'text-[11px] px-1.5 py-0.5 gap-1' : 'text-xs px-2 py-1 gap-1.5';

  return (
    <span
      className={`inline-flex items-center rounded ${sizeClasses} font-mono font-semibold uppercase tracking-wide ${meta.bg} ${meta.text} ring-1 ${meta.ring}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} aria-hidden="true" />
      {meta.label}
    </span>
  );
}
