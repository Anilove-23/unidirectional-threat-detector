import { useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAlertStore } from '../store/alertStore';
import AlertDetailModal from '../components/alerts/AlertDetailModal';

/**
 * Deep-linkable alert detail. Renders the same drill-down modal used from
 * the dashboard/alerts tables, resolving the alert by flow_id from the
 * store so a direct visit to /alerts/:flowId works as long as that alert
 * is still in the retained alert window.
 */
export default function AlertDetailRoute() {
  const { flowId } = useParams();
  const navigate = useNavigate();
  const selectAlertByFlowId = useAlertStore((s) => s.selectAlertByFlowId);
  const selectedAlert = useAlertStore((s) => s.selectedAlert);
  const clearSelectedAlert = useAlertStore((s) => s.clearSelectedAlert);

  useEffect(() => {
    selectAlertByFlowId(flowId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flowId]);

  function close() {
    clearSelectedAlert();
    navigate(-1);
  }

  if (!selectedAlert) {
    return (
      <div className="mx-auto max-w-lg px-6 py-16 text-center">
        <p className="text-sm font-medium text-ink-secondary">Alert not found</p>
        <p className="mt-1 text-xs text-ink-muted">
          Flow <span className="font-mono">{flowId}</span> is not in the currently retained alert window.
        </p>
        <button
          onClick={() => navigate('/alerts')}
          className="mt-4 rounded border border-border px-3 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink-primary"
        >
          Back to alerts
        </button>
      </div>
    );
  }

  return <AlertDetailModal alert={selectedAlert} onClose={close} />;
}
