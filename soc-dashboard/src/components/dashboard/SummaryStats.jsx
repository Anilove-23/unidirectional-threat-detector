import StatCard from '../common/StatCard';

export default function SummaryStats({ stats }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      <StatCard label="Total Alerts" value={stats.total} tone="signal" />
      <StatCard label="Critical" value={stats.critical} tone="critical" />
      <StatCard label="High" value={stats.high} tone="high" />
      <StatCard label="Medium" value={stats.medium} tone="medium" />
      <StatCard label="Low" value={stats.low} tone="low" />
      <StatCard label="Active Flows" value={stats.activeFlows} sublabel="distinct flow IDs" />
    </div>
  );
}
