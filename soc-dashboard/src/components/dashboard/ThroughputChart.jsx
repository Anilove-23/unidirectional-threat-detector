import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';

function buildData(alerts) {
  return alerts
    .filter((a) => a.evidence?.packets_per_second != null)
    .slice(0, 15)
    .reverse()
    .map((a) => ({
      t:   new Date(a.timestamp).toLocaleTimeString(undefined, { hour12: false, minute: '2-digit', second: '2-digit' }),
      pps: a.evidence.packets_per_second,
    }));
}

const TIP_STYLE = {
  background: '#FFFFFF',
  border: '1px solid #E1E8E3',
  borderRadius: '12px',
  boxShadow: '0 4px 20px -2px rgba(11, 79, 48, 0.12)',
  fontSize: 12,
  padding: '8px 12px',
};

export default function ThroughputChart({ alerts }) {
  const data = buildData(alerts);
  return (
    <ChartPanel title="Traffic Throughput" subtitle="Packets / second on flagged flows">
      {data.length === 0
        ? <EmptyState title="No throughput data yet" description="Populated from evidence.packets_per_second." />
        : (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={data} margin={{ top: 10, right: 10, left: -24, bottom: 0 }}>
              <CartesianGrid stroke="#EEF3F0" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" tick={{ fill: '#7A9183', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#7A9183', fontSize: 10 }} axisLine={false} tickLine={false} width={30} />
              <Tooltip
                contentStyle={TIP_STYLE}
                labelStyle={{ color: '#496052', fontWeight: 600, marginBottom: 2 }}
                itemStyle={{ color: '#0B4F30', fontWeight: 700 }}
                formatter={(v) => [`${v} pps`, '']}
                cursor={{ fill: 'rgba(232, 245, 238, 0.6)' }}
              />
              <Bar dataKey="pps" fill="#0B4F30" radius={[8, 8, 0, 0]} maxBarSize={22} />
            </BarChart>
          </ResponsiveContainer>
        )}
    </ChartPanel>
  );
}
