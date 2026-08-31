import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';
import { THREAT_CLASSES } from '../../types/alert';
import { threatClassShortLabel, threatClassColor } from '../../utils/threatUtils';

function buildData(alerts) {
  const counts = {};
  for (const a of alerts) counts[a.threat_class] = (counts[a.threat_class] ?? 0) + 1;
  return THREAT_CLASSES
    .filter((c) => counts[c])
    .map((c) => ({ name: threatClassShortLabel(c), value: counts[c], color: threatClassColor(c) }));
}

const TIP_STYLE = {
  background: '#141D2E', border: '1px solid #1E2D45',
  borderRadius: 6, fontSize: 12, padding: '8px 12px',
};

export default function ThreatDistributionChart({ alerts }) {
  const data  = buildData(alerts);
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <ChartPanel title="Threat Distribution" subtitle="Alerts by detected class">
      {data.length === 0
        ? <EmptyState title="No classified alerts yet" />
        : (
          <div className="flex items-center gap-6 h-[210px]">
            {/* Donut */}
            <div className="shrink-0 w-[160px] h-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data} dataKey="value" nameKey="name"
                    innerRadius={52} outerRadius={74}
                    paddingAngle={2} strokeWidth={0} startAngle={90} endAngle={-270}
                  >
                    {data.map((d) => <Cell key={d.name} fill={d.color} />)}
                  </Pie>
                  <Tooltip
                    contentStyle={TIP_STYLE}
                    itemStyle={{ color: '#E2E8F2' }}
                    formatter={(v, n) => [`${v} (${((v/total)*100).toFixed(0)}%)`, n]}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Legend */}
            <div className="flex flex-col gap-2.5 flex-1 min-w-0">
              {data.map((d) => (
                <div key={d.name} className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: d.color }} />
                    <span className="text-xs text-ink-secondary truncate">{d.name}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-xs font-semibold text-ink-primary mono">{d.value}</span>
                    <span className="text-2xs text-ink-muted w-8 text-right">
                      {((d.value / total) * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
    </ChartPanel>
  );
}
