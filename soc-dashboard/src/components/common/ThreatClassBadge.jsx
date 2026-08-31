import { threatClassShortLabel, threatClassColor } from '../../utils/threatUtils';

export default function ThreatClassBadge({ threatClass }) {
  const color = threatClassColor(threatClass);
  return (
    <span className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium text-ink-secondary whitespace-nowrap">
      <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: color }} />
      {threatClassShortLabel(threatClass)}
    </span>
  );
}
