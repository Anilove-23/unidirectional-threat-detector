import ScoreBar from '../common/ScoreBar';
import { formatConfidence } from '../../utils/alertFormatters';
import { useAlertStore } from '../../store/alertStore';

export default function DecisionDetails({ alert }) {
  const incidents = useAlertStore(s => s.incidents);
  if (!alert.decision_state) return null;
  const related = incidents.filter(i => i.sensor_id === alert.sensor_id && i.timeline.some(e => e.decision_id === alert.decision_id));
  const unavailable = Object.entries(alert.visibility || {}).filter(([, value]) => value === false).map(([key]) => key);
  return <section className="space-y-4" aria-label="V2 decision details">
    <h4 className="font-bold text-forest">{alert.decision_state} · {alert.primary_class || 'No assigned threat class'}</h4>
    {alert.reason_codes?.includes('POLICY_NOT_VALIDATED') && <p className="rounded-lg bg-amber-50 p-3 text-xs text-amber-900">Candidate model scores are available, but the decision policy has not been validated. This result is abstaining and requires analyst review.</p>}
    <div className="flex flex-wrap gap-2">
      {Object.entries(alert.labels || {}).map(([label, value]) => <span key={label} className="rounded-full px-3 py-1 text-xs bg-forest-light">{label} {formatConfidence(value)}</span>)}
    </div>
    <div className="grid gap-3 sm:grid-cols-2">
      {Object.entries(alert.label_probabilities || {}).map(([label, value]) => <ScoreBar key={label} label={`Model score: ${label}`} value={value} />)}
    </div>
    <div className="grid gap-3 sm:grid-cols-2">
      {Object.entries(alert.uncertainty || {}).map(([label, value]) => <ScoreBar key={label} label={`Uncertainty: ${label.replaceAll('_', ' ')}`} value={value} />)}
      {Object.entries(alert.ood || {}).map(([label, value]) => <ScoreBar key={label} label={`OOD: ${label.replaceAll('_', ' ')}`} value={value} color="#D97706" />)}
    </div>
    <p className="text-xs">Visibility {formatConfidence(alert.visibility_ratio)} · History {alert.history_length} events · {alert.history?.window_complete ? 'Complete window' : 'Incomplete window'}</p>
    <p className="text-xs">Unavailable visibility: {unavailable.join(', ') || 'None reported'}</p>
    <p className="text-xs">Drift: {alert.drift_status} · Profile: {alert.model_profile}</p>
    <p className="text-xs">Thresholds: {alert.threshold_version} · Routing: {alert.routing_policy_version}</p>
    <details className="text-xs"><summary className="cursor-pointer font-semibold">Models, thresholds, and routing evidence</summary>
      <pre className="whitespace-pre-wrap break-all mt-2">{JSON.stringify({ versions: alert.model_versions, label_probabilities: alert.label_probabilities, evidence: alert.evidence, thresholds: alert.thresholds, score_presence: alert.score_presence, routes: alert.routing, reason_codes: alert.reason_codes }, null, 2)}</pre>
    </details>
    {related.map(incident => <div key={incident.incident_id} className="border-t border-border pt-3 text-xs space-y-2">
      <h5 className="font-bold">Incident {incident.incident_id.slice(0, 12)} · {incident.status} · {incident.count} decisions</h5>
      <p>{incident.first_seen} — {incident.last_seen}</p>
      <p>{Object.keys(incident.labels).join(' + ')}</p>
      <ol className="space-y-1">{incident.timeline.map(event => <li key={event.decision_id}>{event.event_time} · {event.labels.join(' + ')}</li>)}</ol>
    </div>)}
  </section>;
}
