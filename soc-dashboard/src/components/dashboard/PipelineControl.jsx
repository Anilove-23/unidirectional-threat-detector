import { useEffect, useState } from 'react';
import { usePipelineStats } from '../../hooks/usePipelineStats';
import { API_BASE } from '../../services/config';

export default function PipelineControl() {
  const [simulation, setSimulation] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const { source, processedTotal, inferenceP95, queueLag, modelProfile, driftStatus } = usePipelineStats();

  useEffect(() => {
    let active = true;
    async function refresh() {
      try {
        const response = await fetch(`${API_BASE}/simulation`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const json = await response.json();
        if (active) setSimulation(json.data);
      } catch { if (active) setSimulation(null); }
    }
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => { active = false; clearInterval(timer); };
  }, []);

  async function control(action) {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/simulation/${action}`, { method: 'POST' });
      const json = await response.json();
      if (!response.ok) throw new Error(json.message || `HTTP ${response.status}`);
      setSimulation(json.data);
    } catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  }

  return <section className="card rounded-2xl px-5 py-4 space-y-3" aria-label="Agent pipeline">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h2 className="text-sm font-bold text-forest">Agent 1 observation → Agent 2 detection</h2>
        <p className="text-xs text-ink-muted mt-1">{source === 'agent2_detection_product' ? `${processedTotal ?? 0} observations processed` : 'Waiting for pipeline telemetry'} · {simulation?.running ? 'Simulator running' : 'Simulator stopped'}</p>
      </div>
      <button disabled={busy || !simulation} onClick={() => control(simulation?.running ? 'stop' : 'start')}
        className="rounded-full bg-forest px-4 py-2 text-xs font-semibold text-white disabled:opacity-50">
        {busy ? 'Updating…' : simulation?.running ? 'Stop simulation' : 'Run pipeline simulation'}
      </button>
    </div>
    <p className="text-xs text-ink-secondary">The simulator sends observations through both agents. Candidate models show their scores; decisions remain UNCERTAIN until their threshold policy is validated.</p>
    {source === 'agent2_detection_product' && <p className="text-xs text-ink-muted">
      Models: {Array.isArray(modelProfile) ? modelProfile.join(', ') || 'Unconfigured' : modelProfile || 'Unconfigured'} · Inference p95: {inferenceP95 == null ? '—' : `${inferenceP95.toFixed(1)} ms`} · Queue lag: {queueLag ?? '—'} · Drift: {driftStatus || '—'}
    </p>}
    {(error || simulation?.error) && <p className="text-xs text-red-700" role="alert">{error || simulation.error}</p>}
  </section>;
}
