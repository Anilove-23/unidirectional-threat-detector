import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import ConnectionStatus from '../common/ConnectionStatus';
import PipelineStrip from './PipelineStrip';

const NAV = [
  { to: '/dashboard', label: 'Overview' },
  { to: '/alerts', label: 'Alerts' },
];

export default function Header({ connectionStatus, latestAlert, sensorId, pipelineVersion }) {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="sticky top-0 z-30 bg-surface-1 border-b border-border">
      <div className="flex items-center h-14 px-6 gap-6">

        {/* Logo */}
        <div className="flex items-center gap-2.5 shrink-0">
          <div className="flex h-7 w-7 items-center justify-center rounded bg-accent">
            <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" aria-hidden="true">
              <path d="M10 2L3 6v5c0 3.55 3 6.87 7 7.93C17 16.87 20 13.55 20 11V6L10 2z" fill="white" opacity="0.9"/>
              <path d="M8 10l2 2 4-4" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <div>
            <div className="text-sm font-semibold text-ink-primary leading-none">SENTINEL-D</div>
            <div className="text-2xs text-ink-muted mt-0.5">SIH26145 · NTRO</div>
          </div>
        </div>

        {/* Nav tabs inside header */}
        <nav className="flex items-center gap-1 ml-2">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) =>
                `px-3 py-1.5 text-sm rounded font-medium transition-colors ${
                  isActive
                    ? 'bg-surface-3 text-ink-primary'
                    : 'text-ink-muted hover:text-ink-secondary hover:bg-surface-2'
                }`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>

        {/* Pipeline strip */}
        <div className="flex-1 flex justify-center">
          <PipelineStrip pulseKey={latestAlert?.flow_id} />
        </div>

        {/* Right cluster */}
        <div className="flex items-center gap-4 shrink-0">
          <div className="hidden sm:flex flex-col items-end gap-0.5">
            <span className="mono text-xs text-ink-primary tabular-nums">
              {now.toLocaleTimeString(undefined, { hour12: false })}
            </span>
            <span className="text-2xs text-ink-muted">
              {now.toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' })}
            </span>
          </div>
          <div className="h-4 w-px bg-border" />
          <ConnectionStatus status={connectionStatus} />
        </div>
      </div>
    </header>
  );
}
