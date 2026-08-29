/**
 * Small, pure formatting helpers shared across alert-related components.
 */

export function formatTimestamp(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatClock(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '--:--:--';
  return d.toLocaleTimeString(undefined, { hour12: false });
}

export function formatConfidence(score) {
  return `${Math.round((score ?? 0) * 100)}%`;
}

export function formatFlowId(flowId, length = 8) {
  if (!flowId) return '—';
  return flowId.length > length ? `${flowId.slice(0, length)}…` : flowId;
}

export function formatEvidenceValue(value) {
  if (Array.isArray(value)) return `[${value.join(', ')}]`;
  if (typeof value === 'boolean') return value ? 'True' : 'False';
  if (typeof value === 'number') {
    return Number.isInteger(value) ? String(value) : value.toFixed(3);
  }
  return String(value);
}

/** Relative "Xs ago" for the live feed — recomputed on each render tick. */
export function formatRelativeTime(iso) {
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffSec = Math.max(0, Math.round(diffMs / 1000));
  if (diffSec < 5) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  return `${diffHr}h ago`;
}

const TIME_RANGE_MS = {
  '5m': 5 * 60 * 1000,
  '15m': 15 * 60 * 1000,
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
};

export function isWithinTimeRange(iso, rangeKey) {
  if (!rangeKey || rangeKey === 'all') return true;
  const ms = TIME_RANGE_MS[rangeKey];
  if (!ms) return true;
  return Date.now() - new Date(iso).getTime() <= ms;
}
