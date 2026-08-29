import SeverityBadge from '../common/SeverityBadge';
import ThreatClassBadge from '../common/ThreatClassBadge';
import { formatClock, formatConfidence, formatFlowId } from '../../utils/alertFormatters';

const CRITICAL_ROW_CLASS = 'bg-sev-criticalBg/40 hover:bg-sev-criticalBg/60';
const DEFAULT_ROW_CLASS = 'hover:bg-surface-3';

export default function AlertRow({ alert, onClick, isNew }) {
  return (
    <tr
      onClick={() => onClick(alert)}
      className={`cursor-pointer border-b border-border/60 text-xs transition-colors last:border-b-0 ${
        alert.severity === 'CRITICAL' ? CRITICAL_ROW_CLASS : DEFAULT_ROW_CLASS
      } ${isNew ? 'animate-slideIn' : ''}`}
    >
      <td className="whitespace-nowrap px-3 py-2.5"><SeverityBadge severity={alert.severity} size="sm" /></td>
      <td className="whitespace-nowrap px-3 py-2.5"><ThreatClassBadge threatClass={alert.threat_class} /></td>
      <td className="whitespace-nowrap px-3 py-2.5 font-mono text-ink-primary">{formatConfidence(alert.confidence_score)}</td>
      <td className="whitespace-nowrap px-3 py-2.5 font-mono text-ink-secondary">{alert.five_tuple.src_ip}</td>
      <td className="whitespace-nowrap px-3 py-2.5 font-mono text-ink-secondary">{alert.five_tuple.dst_ip}</td>
      <td className="whitespace-nowrap px-3 py-2.5 text-ink-muted">{alert.five_tuple.protocol}</td>
      <td className="whitespace-nowrap px-3 py-2.5 font-mono text-ink-muted">{formatClock(alert.timestamp)}</td>
      <td className="whitespace-nowrap px-3 py-2.5 font-mono text-ink-muted">{formatFlowId(alert.flow_id)}</td>
    </tr>
  );
}
