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
    <div className="mx-auto flex max-w-[1600px] flex-col gap-5 px-6 py-6 animate-fadeUp">
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
        maxHeight="max-h-[calc(100vh-270px)]"
      />

      <Outlet />
    </div>
  );
}
