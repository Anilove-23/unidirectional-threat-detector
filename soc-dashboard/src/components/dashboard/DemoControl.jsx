export default function DemoControl({ demo, onStart, onStop }) {
  return (
    <div className="card flex items-center justify-between gap-3 border-accent/40 bg-accent-dim/40 px-4 py-2.5">
      <div className="flex items-center gap-2.5">
        <span className="h-2 w-2 rounded-full bg-accent animate-pulseDot shrink-0" />
        <span className="text-xs font-semibold text-accent-hover tracking-wide">Demo Simulator Active</span>
        {demo.active && (
          <>
            <span className="text-ink-muted">·</span>
            <span className="text-xs text-ink-secondary">{demo.stepLabel}</span>
          </>
        )}
      </div>

      {demo.active ? (
        <button
          onClick={onStop}
          className="rounded border border-border bg-surface-2 px-3 py-1 text-xs font-medium text-ink-secondary hover:border-border-strong hover:text-ink-primary transition-colors"
        >
          Stop Simulation
        </button>
      ) : (
        <button
          onClick={onStart}
          className="rounded bg-accent px-3 py-1 text-xs font-medium text-white hover:bg-accent-hover transition-colors"
        >
          Run Attack Simulation
        </button>
      )}
    </div>
  );
}
