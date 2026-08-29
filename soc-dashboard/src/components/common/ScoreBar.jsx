/**
 * Horizontal model-contribution bar used in the drill-down modal —
 * supervised / anomaly / sequence scores are all rendered through this so
 * they stay visually comparable.
 */
export default function ScoreBar({ label, value, color = '#2DD4BF' }) {
  const pct = Math.max(0, Math.min(1, value ?? 0)) * 100;
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="font-medium text-ink-secondary">{label}</span>
        <span className="font-mono text-ink-primary">{pct.toFixed(0)}%</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-surface-3">
        <div
          className="h-full rounded-full transition-[width] duration-500 ease-out"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}
