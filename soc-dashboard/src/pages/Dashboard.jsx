import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAlertStore, selectStats } from '../store/alertStore';
import SummaryStats from '../components/dashboard/SummaryStats';
import ThreatActivityChart from '../components/dashboard/ThreatActivityChart';
import ThreatDistributionChart from '../components/dashboard/ThreatDistributionChart';
import ThroughputChart from '../components/dashboard/ThroughputChart';
import EntropyChart from '../components/dashboard/EntropyChart';
import DemoControl from '../components/dashboard/DemoControl';
import LiveAlertFeed from '../components/alerts/LiveAlertFeed';
import { useLiveDemo } from '../hooks/useLiveDemo';

const USE_MOCK = String(import.meta.env.VITE_USE_MOCK_DATA).toLowerCase() === 'true';

export default function Dashboard() {
  const alerts = useAlertStore((s) => s.alerts);
  const stats = useAlertStore(selectStats);
  const demo = useAlertStore((s) => s.demo);
  const selectAlert = useAlertStore((s) => s.selectAlert);
  const { start, stop } = useLiveDemo();
  const navigate = useNavigate();

  const recentAlerts = useMemo(() => alerts.slice(0, 25), [alerts]);

  function openAlert(alert) {
    selectAlert(alert);
    navigate(`/alerts/${alert.flow_id}`);
  }

  return (
    <div className="mx-auto flex max-w-[1600px] flex-col gap-6 px-6 py-6 animate-fadeUp">
      {USE_MOCK && <DemoControl demo={demo} onStart={start} onStop={stop} />}

      {/* Summary Stats Row */}
      <SummaryStats stats={stats} />

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <ThreatActivityChart alerts={alerts} />
        <ThreatDistributionChart alerts={alerts} />
        <ThroughputChart alerts={alerts} />
        <EntropyChart alerts={alerts} />
      </div>

      {/* Live Feed */}
      <LiveAlertFeed alerts={recentAlerts} onSelect={openAlert} title="Recent Ingested Alerts" />
    </div>
  );
}
