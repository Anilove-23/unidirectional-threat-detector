import { SEVERITY_META } from '../../utils/severityUtils';

export default function SeverityBadge({ severity, size = 'md' }) {
  const meta       = SEVERITY_META[severity] ?? SEVERITY_META.LOW;
  const isSmall    = size === 'sm';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded font-semibold uppercase tracking-wider mono
        ${isSmall ? 'text-[10px] px-1.5 py-0.5' : 'text-[11px] px-2 py-1'}
        ${meta.bg} ${meta.text}`}
      style={{ letterSpacing: '0.07em' }}
    >
      <span className={`rounded-full shrink-0 ${isSmall ? 'h-1 w-1' : 'h-1.5 w-1.5'} ${meta.dot}`} />
      {meta.label}
    </span>
  );
}
