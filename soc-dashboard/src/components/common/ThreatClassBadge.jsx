import { threatClassLabel, threatClassColor } from '../../utils/threatUtils';

export default function ThreatClassBadge({ threatClass }) {
  const color = threatClassColor(threatClass);
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded border border-border px-2 py-1 text-xs font-medium text-ink-secondary"
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} aria-hidden="true" />
      {threatClassLabel(threatClass)}
    </span>
  );
}
