/**
 * Live Demo Mode control — a development/demo utility, clearly separated
 * from the real/mock data toggle. Only rendered when VITE_USE_MOCK_DATA is
 * true; never shown against a real backend connection.
 */
export default function DemoControl({ demo, onStart, onStop }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-signal/30 bg-signal/5 px-4 py-2.5">
      <span className="font-mono text-[10px] uppercase tracking-widest text-signal">Demo Mode</span>
      {demo.active ? (
        <>
          <span className="text-xs text-ink-secondary">{demo.stepLabel}</span>
          <button
            onClick={onStop}
            className="ml-auto rounded border border-border px-2.5 py-1 text-xs font-medium text-ink-secondary transition-colors hover:border-border-strong hover:text-ink-primary"
          >
            Stop
          </button>
        </>
      ) : (
        <button
          onClick={onStart}
          className="ml-auto rounded bg-signal/15 px-2.5 py-1 text-xs font-medium text-signal transition-colors hover:bg-signal/25"
        >
          Run scripted demo sequence
        </button>
      )}
    </div>
  );
}
