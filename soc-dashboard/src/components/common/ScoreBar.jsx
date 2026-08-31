/**
 * Refined horizontal score bar for model contributions in alert drill-down.
 */
export default function ScoreBar({ label, value, color = '#3B7ADB' }) {
  const pct = Math.max(0, Math.min(1, value ?? 0)) * 100;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-xs">
        <span className="font-medium text-ink-secondary">{label}</span>
        <span className="mono text-ink-primary font-medium">{pct.toFixed(0)}%</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-3">
        <div
          className="h-full rounded-full transition-all duration-300 ease-out"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}
