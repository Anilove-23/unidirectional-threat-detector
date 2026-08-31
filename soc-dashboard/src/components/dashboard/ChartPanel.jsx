export default function ChartPanel({ title, subtitle, children, action }) {
  return (
    <div className="card flex flex-col">
      <div className="flex items-center justify-between px-5 py-4 border-b border-border">
        <div>
          <h3 className="text-sm font-semibold text-ink-primary">{title}</h3>
          {subtitle && <p className="text-2xs text-ink-muted mt-0.5">{subtitle}</p>}
        </div>
        {action}
      </div>
      <div className="p-5 flex-1">{children}</div>
    </div>
  );
}
