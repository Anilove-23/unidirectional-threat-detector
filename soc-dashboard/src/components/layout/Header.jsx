import { useEffect, useState } from 'react';
import ConnectionStatus from '../common/ConnectionStatus';
import PipelineStrip from './PipelineStrip';

/**
 * Global header: product identity, live pipeline strip, connection status,
 * sensor/pipeline metadata, and current time. Always visible so an analyst
 * never loses track of whether they're looking at a live feed.
 */
export default function Header({ connectionStatus, latestAlert, sensorId, pipelineVersion }) {
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-surface-2/95 backdrop-blur">
      <div className="flex h-16 items-center justify-between gap-4 px-4 sm:px-6">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded border border-border-strong bg-surface-1">
            <span className="font-mono text-xs font-bold text-signal">S-D</span>
          </div>
          <div className="leading-tight">
            <h1 className="text-sm font-semibold tracking-tight text-ink-primary">
              SENTINEL-D
            </h1>
            <p className="text-[11px] text-ink-muted">Passive Threat Detection · Read-Only Ingestion</p>
          </div>
        </div>

        <PipelineStrip pulseKey={latestAlert?.flow_id} />

        <div className="flex items-center gap-4 sm:gap-6">
          <div className="hidden flex-col items-end text-[11px] text-ink-muted md:flex">
            <span>Sensor <span className="font-mono text-ink-secondary">{sensorId ?? '—'}</span></span>
            <span>Pipeline <span className="font-mono text-ink-secondary">v{pipelineVersion ?? '—'}</span></span>
          </div>
          <div className="hidden flex-col items-end text-[11px] text-ink-muted sm:flex">
            <span className="font-mono text-ink-secondary">{now.toLocaleTimeString(undefined, { hour12: false })}</span>
            <span>{now.toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' })}</span>
          </div>
          <ConnectionStatus status={connectionStatus} />
        </div>
      </div>
    </header>
  );
}
