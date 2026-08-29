import { Routes, Route, Navigate, Outlet } from 'react-router-dom';
import Header from './components/layout/Header';
import NavTabs from './components/layout/NavTabs';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import AlertDetailRoute from './pages/AlertDetailRoute';
import { useAlertStore } from './store/alertStore';
import { useWebSocket } from './hooks/useWebSocket';

function AppShell() {
  const connectionStatus = useAlertStore((s) => s.connectionStatus);
  const alerts = useAlertStore((s) => s.alerts);
  const latestAlert = alerts[0];

  useWebSocket();

  return (
    <div className="min-h-screen bg-surface-0 text-ink-primary">
      <Header
        connectionStatus={connectionStatus}
        latestAlert={latestAlert}
        sensorId={latestAlert?.ingestion_meta?.sensor_id}
        pipelineVersion={latestAlert?.ingestion_meta?.pipeline_version}
      />
      <NavTabs />
      <Outlet />
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />}>
          <Route path=":flowId" element={<AlertDetailRoute />} />
        </Route>
      </Route>
    </Routes>
  );
}
