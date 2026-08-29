import { useEffect, useState } from 'react';

/**
 * Signature element: a compact rendering of the actual one-way pipeline
 * (Sensor -> Feature -> ML -> Ensemble -> Alert -> Dashboard). A dot travels
 * left-to-right whenever a new alert lands, reinforcing — visually, not
 * just in copy — that data only ever flows one direction into this
 * dashboard. Ties the chrome directly to the system's real architecture
 * instead of being decorative.
 */
const STAGES = ['SENSOR', 'FEATURE', 'ML', 'ENSEMBLE', 'ALERT', 'DASHBOARD'];

export default function PipelineStrip({ pulseKey }) {
  const [pulses, setPulses] = useState([]);

  useEffect(() => {
    if (pulseKey == null) return;
    const id = pulseKey;
    setPulses((p) => [...p, id]);
    const t = setTimeout(() => {
      setPulses((p) => p.filter((x) => x !== id));
    }, 2400);
    return () => clearTimeout(t);
  }, [pulseKey]);

  return (
    <div className="hidden items-center gap-0 overflow-hidden lg:flex" aria-hidden="true">
      <div className="relative flex items-center">
        {STAGES.map((stage, i) => (
          <div key={stage} className="flex items-center">
            <span className="whitespace-nowrap font-mono text-[10px] tracking-widest text-ink-muted">
              {stage}
            </span>
            {i < STAGES.length - 1 && (
              <span className="relative mx-2 h-px w-8 bg-border-strong">
                {pulses.map((p) => (
                  <span
                    key={`${p}-${i}`}
                    className="absolute left-0 top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full bg-signal animate-travel"
                  />
                ))}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
