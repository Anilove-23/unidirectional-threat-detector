export default function StatCard({ label, value, tone = 'default', sublabel }) {
  const toneClass = {
    default: 'text-ink-primary',
    critical: 'text-sev-critical',
    high: 'text-sev-high',
    medium: 'text-sev-medium',
    low: 'text-sev-low',
    signal: 'text-signal',
  }[tone];

  return (
    <div className="flex flex-col justify-between rounded-lg border border-border bg-surface-1 px-4 py-3 shadow-panel">
      <span className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">{label}</span>
      <span className={`mt-1 font-mono text-2xl font-semibold ${toneClass}`}>{value}</span>
      {sublabel && <span className="mt-0.5 text-[11px] text-ink-muted">{sublabel}</span>}
    </div>
  );
}
