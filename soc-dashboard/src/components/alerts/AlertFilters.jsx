import { THREAT_CLASSES } from '../../types/alert';
import { threatClassShortLabel } from '../../utils/threatUtils';

const SEVERITY_OPTIONS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const TIME_OPTIONS = [
  { value: 'all', label: 'All time' },
  { value: '5m', label: 'Last 5 min' },
  { value: '15m', label: 'Last 15 min' },
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24h' },
];

function Select({ label, value, onChange, children }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[11px] font-medium uppercase tracking-wide text-ink-muted">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink-primary outline-none focus:border-signal"
      >
        {children}
      </select>
    </label>
  );
}

export default function AlertFilters({ filters, searchQuery, onSeverity, onThreat, onTimeRange, onSearch, onClear }) {
  return (
    <div className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-surface-1 p-3 shadow-panel">
      <Select label="Severity" value={filters.severity} onChange={onSeverity}>
        {SEVERITY_OPTIONS.map((s) => (
          <option key={s} value={s}>
            {s === 'ALL' ? 'All' : s.charAt(0) + s.slice(1).toLowerCase()}
          </option>
        ))}
      </Select>

      <Select label="Threat class" value={filters.threatClass} onChange={onThreat}>
        <option value="ALL">All</option>
        {THREAT_CLASSES.map((c) => (
          <option key={c} value={c}>
            {threatClassShortLabel(c)}
          </option>
        ))}
      </Select>

      <Select label="Time range" value={filters.timeRange} onChange={onTimeRange}>
        {TIME_OPTIONS.map((t) => (
          <option key={t.value} value={t.value}>
            {t.label}
          </option>
        ))}
      </Select>

      <label className="flex min-w-[220px] flex-1 flex-col gap-1">
        <span className="text-[11px] font-medium uppercase tracking-wide text-ink-muted">
          Search (Source IP, Dest IP, Flow ID, class)
        </span>
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="e.g. 198.51.100.23"
          className="rounded border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-ink-primary outline-none placeholder:text-ink-muted focus:border-signal"
        />
      </label>

      <button
        onClick={onClear}
        className="rounded border border-border px-3 py-1.5 text-xs font-medium text-ink-secondary transition-colors hover:border-border-strong hover:text-ink-primary"
      >
        Clear filters
      </button>
    </div>
  );
}
