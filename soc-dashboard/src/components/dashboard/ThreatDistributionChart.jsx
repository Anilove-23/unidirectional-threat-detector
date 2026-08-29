import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';
import { THREAT_CLASSES } from '../../types/alert';
import { threatClassShortLabel, threatClassColor } from '../../utils/threatUtils';

function buildData(alerts) {
  const counts = Object.fromEntries(THREAT_CLASSES.map((c) => [c, 0]));
  for (const a of alerts) counts[a.threat_class] = (counts[a.threat_class] ?? 0) + 1;
  return THREAT_CLASSES.map((c) => ({ name: threatClassShortLabel(c), value: counts[c], color: threatClassColor(c) })).filter(
    (d) => d.value > 0
  );
}

export default function ThreatDistributionChart({ alerts }) {
  const data = buildData(alerts);

  return (
    <ChartPanel title="Threat Class Distribution" subtitle="Share of alerts by detected class">
      {data.length === 0 ? (
        <EmptyState title="No classified alerts yet" />
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius={48} outerRadius={78} paddingAngle={2}>
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} stroke="#0D1219" strokeWidth={2} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: '#121826', border: '1px solid #1E2733', borderRadius: 6, fontSize: 12 }}
              itemStyle={{ color: '#E6EBF2' }}
            />
            <Legend
              layout="vertical"
              align="right"
              verticalAlign="middle"
              wrapperStyle={{ fontSize: 11, color: '#93A1B4' }}
            />
          </PieChart>
        </ResponsiveContainer>
      )}
    </ChartPanel>
  );
}
