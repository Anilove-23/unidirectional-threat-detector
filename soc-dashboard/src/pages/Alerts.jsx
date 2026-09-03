import { useNavigate, Outlet } from 'react-router-dom';
import { useAlertStore, selectFilteredAlerts } from '../store/alertStore';
import AlertFilters from '../components/alerts/AlertFilters';
import LiveAlertFeed from '../components/alerts/LiveAlertFeed';

export default function Alerts() {
  const filters = useAlertStore((s) => s.filters);
  const searchQuery = useAlertStore((s) => s.searchQuery);
  const setSeverityFilter = useAlertStore((s) => s.setSeverityFilter);
  const setThreatFilter = useAlertStore((s) => s.setThreatFilter);
  const setTimeRangeFilter = useAlertStore((s) => s.setTimeRangeFilter);
  const setSearchQuery = useAlertStore((s) => s.setSearchQuery);
  const clearFilters = useAlertStore((s) => s.clearFilters);
  const selectAlert = useAlertStore((s) => s.selectAlert);
  const filtered = useAlertStore(selectFilteredAlerts);
  const navigate = useNavigate();

  function openAlert(alert) {
    selectAlert(alert);
    navigate(`/alerts/${alert.flow_id}`);
  }

  return (
    <div className="mx-auto flex max-w-[1600px] flex-col gap-5 px-4 sm:px-6 py-6 animate-fadeUp">
      {/* Page Title Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-ink-primary font-sans tracking-tight">Threat Registry</h1>
          <p className="text-xs sm:text-sm font-medium text-ink-muted mt-1">
            Filter, analyze, and inspect unidirectional passive detections in real time.
          </p>
        </div>
      </div>

      {/* Search & Filters */}
      <AlertFilters
        filters={filters}
        searchQuery={searchQuery}
        onSeverity={setSeverityFilter}
        onThreat={setThreatFilter}
        onTimeRange={setTimeRangeFilter}
        onSearch={setSearchQuery}
        onClear={clearFilters}
      />

      {/* Main Alert Feed Table */}
      <LiveAlertFeed
        alerts={filtered}
        onSelect={openAlert}
        title="Threat Alert Registry"
        maxHeight="max-h-[calc(100vh-320px)]"
      />

      <Outlet />
    </div>
  );
}
