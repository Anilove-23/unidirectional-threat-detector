const CONFIG = {
  CONNECTED:    { label: 'Live',         dot: 'bg-signal animate-pulseDot', text: 'text-signal' },
  CONNECTING:   { label: 'Connecting',   dot: 'bg-ink-muted animate-pulseDot', text: 'text-ink-secondary' },
  RECONNECTING: { label: 'Reconnecting', dot: 'bg-sev-high animate-pulseDot', text: 'text-sev-high' },
  DISCONNECTED: { label: 'Offline',      dot: 'bg-sev-critical', text: 'text-sev-critical' },
};

export default function ConnectionStatus({ status }) {
  const cfg = CONFIG[status] ?? CONFIG.DISCONNECTED;
  return (
    <div className="flex items-center gap-2" role="status" aria-live="polite">
      <span className={`h-2 w-2 rounded-full shrink-0 ${cfg.dot}`} />
      <span className={`text-xs font-medium ${cfg.text}`}>{cfg.label}</span>
    </div>
  );
}
