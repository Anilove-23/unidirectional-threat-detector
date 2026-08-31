import SeverityBadge from '../common/SeverityBadge';
import ThreatClassBadge from '../common/ThreatClassBadge';
import { formatClock, formatConfidence, formatFlowId } from '../../utils/alertFormatters';

// Thin left-border accent for critical rows
const criticalClass = 'border-l-2 border-l-sev-critical bg-sev-criticalBg/20';

export default function AlertRow({ alert, onClick, isNew }) {
  const isCritical = alert.severity === 'CRITICAL';
  const conf = Math.round(alert.confidence_score * 100);

  return (
    <tr
      onClick={() => onClick(alert)}
      className={`trow ${isCritical ? criticalClass : ''} ${isNew ? 'animate-slideIn' : ''}`}
    >
      {/* Severity */}
      <td className="px-4 py-3 whitespace-nowrap">
        <SeverityBadge severity={alert.severity} size="sm" />
      </td>

      {/* Threat class */}
      <td className="px-4 py-3 whitespace-nowrap">
        <ThreatClassBadge threatClass={alert.threat_class} />
      </td>

      {/* Confidence — mini bar + number */}
      <td className="px-4 py-3 whitespace-nowrap">
        <div className="flex items-center gap-2">
          <div className="w-14 h-1 rounded-full bg-surface-3 overflow-hidden shrink-0">
            <div
              className="h-full rounded-full bg-accent"
              style={{ width: `${conf}%` }}
            />
          </div>
          <span className="mono text-[11px] text-ink-secondary">{conf}%</span>
        </div>
      </td>

      {/* Source IP */}
      <td className="px-4 py-3 whitespace-nowrap mono text-[11px] text-ink-secondary">
        {alert.five_tuple.src_ip}
        <span className="text-ink-muted">:{alert.five_tuple.src_port}</span>
      </td>

      {/* Dest IP */}
      <td className="px-4 py-3 whitespace-nowrap mono text-[11px] text-ink-secondary">
        {alert.five_tuple.dst_ip}
        <span className="text-ink-muted">:{alert.five_tuple.dst_port}</span>
      </td>

      {/* Protocol */}
      <td className="px-4 py-3 whitespace-nowrap">
        <span className="inline-block rounded bg-surface-3 px-1.5 py-0.5 mono text-2xs text-ink-muted">
          {alert.five_tuple.protocol}
        </span>
      </td>

      {/* Time */}
      <td className="px-4 py-3 whitespace-nowrap mono text-[11px] text-ink-muted">
        {formatClock(alert.timestamp)}
      </td>

      {/* Flow ID */}
      <td className="px-4 py-3 whitespace-nowrap mono text-[11px] text-ink-muted">
        {formatFlowId(alert.flow_id)}
      </td>

      {/* Arrow */}
      <td className="px-3 py-3 text-ink-muted">
        <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
      </td>
    </tr>
  );
}
