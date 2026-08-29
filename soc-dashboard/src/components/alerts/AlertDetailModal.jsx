import { useEffect, useRef } from 'react';
import SeverityBadge from '../common/SeverityBadge';
import ThreatClassBadge from '../common/ThreatClassBadge';
import ModelContribution from './ModelContribution';
import EvidencePanel from './EvidencePanel';
import { formatTimestamp, formatConfidence } from '../../utils/alertFormatters';

function Field({ label, value, mono = true }) {
  return (
    <div>
      <dt className="text-[10px] font-medium uppercase tracking-wide text-ink-muted">{label}</dt>
      <dd className={`mt-0.5 text-sm text-ink-primary ${mono ? 'font-mono' : ''}`}>{value}</dd>
    </div>
  );
}

/**
 * Alert drill-down. Works for all seven threat classes — nothing here is
 * conditioned on threat_class beyond the badge label; the evidence section
 * dynamically renders whatever fields the alert carries (see
 * EvidencePanel.jsx).
 */
export default function AlertDetailModal({ alert, onClose }) {
  const closeBtnRef = useRef(null);

  useEffect(() => {
    closeBtnRef.current?.focus();
    function onKeyDown(e) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  if (!alert) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-10 backdrop-blur-sm sm:pt-16"
      role="dialog"
      aria-modal="true"
      aria-label="Alert details"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-2xl animate-slideIn rounded-lg border border-border-strong bg-surface-1 shadow-panel">
        <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
          <div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <ThreatClassBadge threatClass={alert.threat_class} />
            </div>
            <p className="mt-2 font-mono text-[11px] text-ink-muted">Flow {alert.flow_id}</p>
          </div>
          <button
            ref={closeBtnRef}
            onClick={onClose}
            aria-label="Close alert details"
            className="rounded border border-border px-2 py-1 text-xs text-ink-secondary transition-colors hover:border-border-strong hover:text-ink-primary"
          >
            Close ✕
          </button>
        </div>

        <div className="max-h-[70vh] space-y-6 overflow-y-auto px-5 py-5">
          <section>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-muted">General</h4>
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <Field label="Confidence" value={formatConfidence(alert.confidence_score)} />
              <Field label="Timestamp" value={formatTimestamp(alert.timestamp)} />
              <Field label="Sensor" value={alert.ingestion_meta?.sensor_id ?? '—'} />
              <Field label="Capture Interface" value={alert.ingestion_meta?.capture_interface ?? '—'} />
              <Field label="Pipeline Version" value={alert.ingestion_meta?.pipeline_version ?? '—'} />
            </dl>
          </section>

          <section>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-muted">Network Flow</h4>
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <Field label="Source IP" value={alert.five_tuple.src_ip} />
              <Field label="Destination IP" value={alert.five_tuple.dst_ip} />
              <Field label="Source Port" value={alert.five_tuple.src_port} />
              <Field label="Destination Port" value={alert.five_tuple.dst_port} />
              <Field label="Protocol" value={alert.five_tuple.protocol} />
            </dl>
          </section>

          <section>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-muted">Model Contribution</h4>
            <ModelContribution modelSource={alert.model_source} />
          </section>

          <section>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-muted">Evidence</h4>
            <EvidencePanel evidence={alert.evidence} />
          </section>
        </div>

        <div className="border-t border-border px-5 py-3">
          <p className="text-[11px] text-ink-muted">
            Passive detection record for analyst review. This alert is advisory only — SENTINEL-D does not send,
            block, reset, or otherwise act on the monitored network.
          </p>
        </div>
      </div>
    </div>
  );
}
