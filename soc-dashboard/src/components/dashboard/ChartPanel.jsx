export default function ChartPanel({ title, subtitle, children, action }) {
  return (
    <div className="flex flex-col rounded-lg border border-border bg-surface-1 p-4 shadow-panel">
      <div className="mb-3 flex items-start justify-between">
        <div>
          <h3 className="text-sm font-semibold text-ink-primary">{title}</h3>
          {subtitle && <p className="text-[11px] text-ink-muted">{subtitle}</p>}
        </div>
        {action}
      </div>
      <div className="min-h-0 flex-1">{children}</div>
    </div>
  );
}
