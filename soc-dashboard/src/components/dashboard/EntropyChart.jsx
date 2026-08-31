import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';

function buildData(alerts) {
  return alerts
    .filter((a) => a.evidence?.src_ip_entropy != null)
    .slice(0, 20)
    .reverse()
    .map((a) => ({
      t:       new Date(a.timestamp).toLocaleTimeString(undefined, { hour12: false, minute: '2-digit', second: '2-digit' }),
      entropy: parseFloat(a.evidence.src_ip_entropy.toFixed(3)),
    }));
}

const TIP_STYLE = {
  background: '#141D2E', border: '1px solid #1E2D45',
  borderRadius: 6, fontSize: 12, padding: '8px 12px',
};

export default function EntropyChart({ alerts }) {
  const data = buildData(alerts);
  return (
    <ChartPanel title="IP Entropy Trend" subtitle="Source-IP entropy — higher = more anomalous">
      {data.length === 0
        ? <EmptyState title="No entropy data yet" description="Populated from evidence.src_ip_entropy." />
        : (
          <ResponsiveContainer width="100%" height={210}>
            <LineChart data={data} margin={{ top: 6, right: 0, left: -28, bottom: 0 }}>
              <CartesianGrid stroke="#1E2D45" strokeDasharray="2 4" vertical={false} />
              <XAxis dataKey="t" tick={{ fill: '#4A5A72', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 1]} tick={{ fill: '#4A5A72', fontSize: 10 }} axisLine={false} tickLine={false} width={22} />
              <ReferenceLine y={0.7} stroke="#F04A5A" strokeDasharray="3 5" strokeOpacity={0.4} label={false} />
              <Tooltip
                contentStyle={TIP_STYLE}
                labelStyle={{ color: '#8898B0', marginBottom: 4 }}
                itemStyle={{ color: '#FBBF24', fontWeight: 600 }}
                formatter={(v) => [v, 'entropy']}
                cursor={{ stroke: '#273750' }}
              />
              <Line
                type="monotone" dataKey="entropy"
                stroke="#FBBF24" strokeWidth={2}
                dot={{ r: 2.5, fill: '#FBBF24', strokeWidth: 0 }}
                activeDot={{ r: 4, strokeWidth: 0 }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
    </ChartPanel>
  );
}
