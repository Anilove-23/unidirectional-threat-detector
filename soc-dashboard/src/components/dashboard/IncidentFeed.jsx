import { useAlertStore } from '../../store/alertStore';
import { usePipelineStats } from '../../hooks/usePipelineStats';

export default function IncidentFeed() {
  const incidents = useAlertStore(s => s.incidents);
  const { inferenceP95, queueLag, modelProfile, driftStatus } = usePipelineStats();
  return <section className="card p-5 space-y-4" aria-label="Incident timeline">
    <h2 className="text-lg font-bold">Incidents and detection health</h2>
    <p className="text-xs text-ink-muted">Inference p95: {inferenceP95 == null ? 'Unavailable' : `${inferenceP95.toFixed(1)} ms`} · Queue lag: {queueLag ?? 'Unavailable'} · Drift: {driftStatus ?? 'Unavailable'} · Profile: {Array.isArray(modelProfile) ? modelProfile.join(', ') || 'Unconfigured' : modelProfile || 'Unavailable'}</p>
    {incidents.length === 0 ? <p className="text-sm text-ink-muted">No correlated V2 incidents received.</p> : incidents.slice(0, 10).map(incident => <details key={incident.incident_id} className="border-t border-border pt-3 text-sm">
      <summary className="cursor-pointer">{incident.entity} · {incident.severity} · {incident.count} decisions · {incident.status}</summary>
      <p className="text-xs mt-2">{Object.keys(incident.labels).join(' + ')} · {incident.first_seen} — {incident.last_seen}</p>
      <ol className="text-xs mt-2 space-y-1">{incident.timeline.map(event => <li key={event.decision_id}>{event.event_time} · {event.labels.join(' + ')}</li>)}</ol>
    </details>)}
  </section>;
}
