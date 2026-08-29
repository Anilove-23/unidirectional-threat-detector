/**
 * Severity presentation helpers. CRITICAL always sorts first.
 */

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export const SEVERITY_META = {
  CRITICAL: {
    label: 'Critical',
    text: 'text-sev-critical',
    bg: 'bg-sev-criticalBg',
    ring: 'ring-sev-critical/40',
    dot: 'bg-sev-critical',
  },
  HIGH: {
    label: 'High',
    text: 'text-sev-high',
    bg: 'bg-sev-highBg',
    ring: 'ring-sev-high/40',
    dot: 'bg-sev-high',
  },
  MEDIUM: {
    label: 'Medium',
    text: 'text-sev-medium',
    bg: 'bg-sev-mediumBg',
    ring: 'ring-sev-medium/40',
    dot: 'bg-sev-medium',
  },
  LOW: {
    label: 'Low',
    text: 'text-sev-low',
    bg: 'bg-sev-lowBg',
    ring: 'ring-sev-low/40',
    dot: 'bg-sev-low',
  },
};

export function severityRank(severity) {
  const idx = SEVERITY_ORDER.indexOf(severity);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

export function compareBySeverityThenTime(a, b) {
  const rankDiff = severityRank(a.severity) - severityRank(b.severity);
  if (rankDiff !== 0) return rankDiff;
  return new Date(b.timestamp) - new Date(a.timestamp);
}
