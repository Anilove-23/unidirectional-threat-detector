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
  background: '#141D2E', border: '1px solid #1E2D45',
  borderRadius: 6, fontSize: 12, padding: '8px 12px',
};

export default function ThroughputChart({ alerts }) {
  const data = buildData(alerts);
  return (
    <ChartPanel title="Traffic Throughput" subtitle="Packets / second on flagged flows">
      {data.length === 0
        ? <EmptyState title="No throughput data yet" description="Populated from evidence.packets_per_second." />
        : (
          <ResponsiveContainer width="100%" height={210}>
            <BarChart data={data} margin={{ top: 6, right: 0, left: -28, bottom: 0 }}>
              <CartesianGrid stroke="#1E2D45" strokeDasharray="2 4" vertical={false} />
              <XAxis dataKey="t" tick={{ fill: '#4A5A72', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#4A5A72', fontSize: 10 }} axisLine={false} tickLine={false} width={30} />
              <Tooltip
                contentStyle={TIP_STYLE}
                labelStyle={{ color: '#8898B0', marginBottom: 4 }}
                itemStyle={{ color: '#60A5FA', fontWeight: 600 }}
                formatter={(v) => [`${v} pps`, '']}
                cursor={{ fill: 'rgba(30,45,69,0.5)' }}
              />
              <Bar dataKey="pps" fill="#3B7ADB" radius={[3, 3, 0, 0]} maxBarSize={20} />
            </BarChart>
          </ResponsiveContainer>
        )}
    </ChartPanel>
  );
}
