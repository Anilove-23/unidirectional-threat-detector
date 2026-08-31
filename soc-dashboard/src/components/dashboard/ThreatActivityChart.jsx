import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';

function buildSeries(alerts) {
  const BUCKET_MS = 60_000;
  const BUCKETS   = 30;
  const now        = Date.now();
  const buckets    = Array.from({ length: BUCKETS }, (_, i) => ({
    t:     now - (BUCKETS - 1 - i) * BUCKET_MS,
    count: 0,
  }));
  for (const a of alerts) {
    const age = now - new Date(a.timestamp).getTime();
    if (age < 0 || age > BUCKETS * BUCKET_MS) continue;
    const idx = BUCKETS - 1 - Math.floor(age / BUCKET_MS);
    if (buckets[idx]) buckets[idx].count += 1;
  }
  return buckets.map((b) => ({
    t:     new Date(b.t).toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit' }),
    count: b.count,
  }));
}

const TIP_STYLE = {
  background: '#141D2E',
  border:     '1px solid #1E2D45',
  borderRadius: 6,
  fontSize:   12,
  padding:    '8px 12px',
};

export default function ThreatActivityChart({ alerts }) {
  const data        = buildSeries(alerts);
  const hasActivity = data.some((d) => d.count > 0);

  return (
    <ChartPanel title="Threat Activity" subtitle="Detections per minute · last 30 min">
      {!hasActivity
        ? <EmptyState title="No activity yet" description="Detections appear here as alerts arrive." />
        : (
          <ResponsiveContainer width="100%" height={210}>
            <AreaChart data={data} margin={{ top: 6, right: 0, left: -28, bottom: 0 }}>
              <defs>
                <linearGradient id="grad-activity" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor="#3B7ADB" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#3B7ADB" stopOpacity={0}   />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#1E2D45" strokeDasharray="2 4" vertical={false} />
              <XAxis
                dataKey="t"
                tick={{ fill: '#4A5A72', fontSize: 10, fontFamily: 'Inter' }}
                axisLine={false} tickLine={false} interval={5}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: '#4A5A72', fontSize: 10, fontFamily: 'Inter' }}
                axisLine={false} tickLine={false} width={22}
              />
              <Tooltip
                contentStyle={TIP_STYLE}
                labelStyle={{ color: '#8898B0', marginBottom: 4 }}
                itemStyle={{ color: '#60A5FA', fontWeight: 600 }}
                formatter={(v) => [`${v} detections`, '']}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#3B7ADB"
                strokeWidth={2}
                fill="url(#grad-activity)"
                dot={false}
                activeDot={{ r: 4, fill: '#3B7ADB', strokeWidth: 0 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
    </ChartPanel>
  );
}
