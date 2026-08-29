import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';

/** Buckets alerts into 1-minute windows over the last 30 minutes. */
function buildSeries(alerts) {
  const BUCKET_MS = 60 * 1000;
  const BUCKETS = 30;
  const now = Date.now();
  const buckets = Array.from({ length: BUCKETS }, (_, i) => ({
    t: now - (BUCKETS - 1 - i) * BUCKET_MS,
    count: 0,
  }));
  for (const a of alerts) {
    const ts = new Date(a.timestamp).getTime();
    const age = now - ts;
    if (age < 0 || age > BUCKETS * BUCKET_MS) continue;
    const idx = BUCKETS - 1 - Math.floor(age / BUCKET_MS);
    if (buckets[idx]) buckets[idx].count += 1;
  }
  return buckets.map((b) => ({
    label: new Date(b.t).toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit' }),
    count: b.count,
  }));
}

export default function ThreatActivityChart({ alerts }) {
  const data = buildSeries(alerts);
  const hasActivity = data.some((d) => d.count > 0);

  return (
    <ChartPanel title="Threat Activity Over Time" subtitle="Detections per minute · last 30 min">
      {!hasActivity ? (
        <EmptyState title="No threat activity yet" description="Detections will appear here as alerts arrive." />
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#2DD4BF" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#2DD4BF" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1E2733" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fill: '#5C6B80', fontSize: 10 }}
              interval={5}
              axisLine={{ stroke: '#1E2733' }}
              tickLine={false}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: '#5C6B80', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              width={28}
            />
            <Tooltip
              contentStyle={{ background: '#121826', border: '1px solid #1E2733', borderRadius: 6, fontSize: 12 }}
              labelStyle={{ color: '#93A1B4' }}
              itemStyle={{ color: '#E6EBF2' }}
            />
            <Area type="monotone" dataKey="count" stroke="#2DD4BF" strokeWidth={2} fill="url(#activityFill)" />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </ChartPanel>
  );
}
