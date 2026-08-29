import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';

/**
 * Traffic throughput derived from evidence.bytes_out_total /
 * evidence.packets_per_second when present on an alert. Per the spec: if a
 * metric isn't in the alert JSON yet, this chart degrades to an empty state
 * rather than fabricating data — swapping in a dedicated backend metrics
 * channel later requires no rewrite, just populating `alerts` differently.
 */
function buildData(alerts) {
  const withThroughput = alerts
    .filter((a) => a.evidence?.packets_per_second != null || a.evidence?.bytes_out_total != null)
    .slice(0, 12)
    .reverse();

  return withThroughput.map((a) => ({
    label: new Date(a.timestamp).toLocaleTimeString(undefined, { hour12: false, minute: '2-digit', second: '2-digit' }),
    pps: a.evidence.packets_per_second ?? 0,
  }));
}

export default function ThroughputChart({ alerts }) {
  const data = buildData(alerts);

  return (
    <ChartPanel title="Traffic Throughput" subtitle="Packets / second on flagged flows">
      {data.length === 0 ? (
        <EmptyState
          title="No throughput evidence yet"
          description="Populated from evidence.packets_per_second on incoming alerts."
        />
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
            <CartesianGrid stroke="#1E2733" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: '#5C6B80', fontSize: 10 }} axisLine={{ stroke: '#1E2733' }} tickLine={false} />
            <YAxis tick={{ fill: '#5C6B80', fontSize: 10 }} axisLine={false} tickLine={false} width={40} />
            <Tooltip
              contentStyle={{ background: '#121826', border: '1px solid #1E2733', borderRadius: 6, fontSize: 12 }}
              labelStyle={{ color: '#93A1B4' }}
              itemStyle={{ color: '#E6EBF2' }}
            />
            <Bar dataKey="pps" fill="#5B8DEF" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </ChartPanel>
  );
}
