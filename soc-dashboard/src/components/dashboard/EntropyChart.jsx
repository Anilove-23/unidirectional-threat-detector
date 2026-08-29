import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';

/** Source-IP entropy / anomaly trend, from evidence.src_ip_entropy when present. */
function buildData(alerts) {
  const withEntropy = alerts
    .filter((a) => a.evidence?.src_ip_entropy != null)
    .slice(0, 20)
    .reverse();

  return withEntropy.map((a) => ({
    label: new Date(a.timestamp).toLocaleTimeString(undefined, { hour12: false, minute: '2-digit', second: '2-digit' }),
    entropy: a.evidence.src_ip_entropy,
  }));
}

export default function EntropyChart({ alerts }) {
  const data = buildData(alerts);

  return (
    <ChartPanel title="IP Entropy / Behaviour Anomaly Trend" subtitle="Source-IP entropy on flagged flows">
      {data.length === 0 ? (
        <EmptyState
          title="No entropy evidence yet"
          description="Populated from evidence.src_ip_entropy on incoming alerts."
        />
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
            <CartesianGrid stroke="#1E2733" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: '#5C6B80', fontSize: 10 }} axisLine={{ stroke: '#1E2733' }} tickLine={false} />
            <YAxis domain={[0, 1]} tick={{ fill: '#5C6B80', fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
            <Tooltip
              contentStyle={{ background: '#121826', border: '1px solid #1E2733', borderRadius: 6, fontSize: 12 }}
              labelStyle={{ color: '#93A1B4' }}
              itemStyle={{ color: '#E6EBF2' }}
            />
            <Line type="monotone" dataKey="entropy" stroke="#E8C547" strokeWidth={2} dot={{ r: 2 }} />
          </LineChart>
        </ResponsiveContainer>
      )}
    </ChartPanel>
  );
}
