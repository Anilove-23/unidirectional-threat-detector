/**
 * Stats row — bold numbers separated by dividers, Devfolio-style.
 * Single wide card, no individual boxes.
 */

const SEV_DOT = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
};

const SEV_VALUE = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  signal: 'text-signal',
  default: 'text-ink-primary',
};

function StatItem({ label, value, tone = 'default', dot }) {
  return (
    <div className="flex flex-col gap-1 px-6 py-5 min-w-[100px] flex-1">
      <span className="flex items-center gap-2 text-xs font-medium text-ink-muted">
        {dot && (
          <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[dot] ?? ''}`} />
        )}
        {label}
      </span>
      <span className={`text-3xl font-bold tabular-nums leading-none mt-0.5 mono ${SEV_VALUE[tone]}`}>
        {value}
      </span>
    </div>
  );
}

export default function SummaryStats({ stats }) {
  return (
    <div className="card flex flex-wrap divide-x divide-border overflow-hidden">
      <StatItem label="Total Alerts"  value={stats.total}       tone="default" />
      <StatItem label="Critical"      value={stats.critical}    tone="critical"  dot="critical" />
      <StatItem label="High"          value={stats.high}        tone="high"      dot="high" />
      <StatItem label="Medium"        value={stats.medium}      tone="medium"    dot="medium" />
      <StatItem label="Low"           value={stats.low}         tone="low"       dot="low" />
      <StatItem label="Active Flows"  value={stats.activeFlows} tone="signal" />
    </div>
  );
}
