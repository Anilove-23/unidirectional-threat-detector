const CONFIG = {
  CONNECTED: { label: 'LIVE', dotClass: 'bg-signal animate-pulseDot', textClass: 'text-signal' },
  CONNECTING: { label: 'CONNECTING…', dotClass: 'bg-ink-muted animate-pulseDot', textClass: 'text-ink-secondary' },
  RECONNECTING: { label: 'RECONNECTING…', dotClass: 'bg-sev-high animate-pulseDot', textClass: 'text-sev-high' },
  DISCONNECTED: { label: 'DISCONNECTED', dotClass: 'bg-sev-critical', textClass: 'text-sev-critical' },
};

/**
 * Reflects the real WebSocketService status, never a hardcoded "online"
 * indicator — see hooks/useWebSocket.js for where this state originates.
 */
export default function ConnectionStatus({ status }) {
  const cfg = CONFIG[status] ?? CONFIG.DISCONNECTED;
  return (
    <div className="flex items-center gap-2 font-mono text-xs" role="status" aria-live="polite">
      <span className={`h-2 w-2 rounded-full ${cfg.dotClass}`} aria-hidden="true" />
      <span className={`${cfg.textClass} tracking-wide`}>{cfg.label}</span>
    </div>
  );
}
