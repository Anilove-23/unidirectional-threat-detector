/**
 * Centralized alert store (Zustand). All alert/filter/connection state
 * lives here — components read from it and dispatch actions, they never
 * hold their own copy of alert data.
 */
import { create } from 'zustand';

const MAX_ALERTS_RETAINED = 500;

const initialFilters = {
  severity: 'ALL',
  threatClass: 'ALL',
  timeRange: 'all', // '5m' | '15m' | '1h' | '24h' | 'all'
};

export const useAlertStore = create((set, get) => ({
  alerts: [],
  selectedAlert: null,
  filters: initialFilters,
  searchQuery: '',
  connectionStatus: 'DISCONNECTED',
  demo: { active: false, stepLabel: null, stepIndex: -1 },

  // --- alert ingestion -----------------------------------------------
  addAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts].slice(0, MAX_ALERTS_RETAINED),
    })),

  setAlerts: (alerts) => set({ alerts: alerts.slice(0, MAX_ALERTS_RETAINED) }),

  clearAlerts: () => set({ alerts: [] }),

  // --- selection --------------------------------------------------------
  selectAlert: (alert) => set({ selectedAlert: alert }),
  selectAlertByFlowId: (flowId) => {
    const found = get().alerts.find((a) => a.flow_id === flowId) ?? null;
    set({ selectedAlert: found });
    return found;
  },
  clearSelectedAlert: () => set({ selectedAlert: null }),

  // --- filters ------------------------------------------------------
  setSeverityFilter: (severity) =>
    set((state) => ({ filters: { ...state.filters, severity } })),
  setThreatFilter: (threatClass) =>
    set((state) => ({ filters: { ...state.filters, threatClass } })),
  setTimeRangeFilter: (timeRange) =>
    set((state) => ({ filters: { ...state.filters, timeRange } })),
  setSearchQuery: (searchQuery) => set({ searchQuery }),
  clearFilters: () => set({ filters: initialFilters, searchQuery: '' }),

  // --- connection ------------------------------------------------------
  setConnectionStatus: (connectionStatus) => set({ connectionStatus }),

  // --- demo mode ---------------------------------------------------
  setDemoStep: (stepIndex, stepLabel) =>
    set({ demo: { active: true, stepIndex, stepLabel } }),
  endDemo: () => set({ demo: { active: false, stepLabel: null, stepIndex: -1 } }),
}));

// --- derived selectors (kept here so components stay declarative) --------

export function selectFilteredAlerts(state) {
  const { severity, threatClass, timeRange } = state.filters;
  const q = state.searchQuery.trim().toLowerCase();

  return state.alerts.filter((a) => {
    if (severity !== 'ALL' && a.severity !== severity) return false;
    if (threatClass !== 'ALL' && a.threat_class !== threatClass) return false;
    if (timeRange !== 'all') {
      const ranges = { '5m': 5, '15m': 15, '1h': 60, '24h': 1440 };
      const mins = ranges[timeRange];
      if (mins && Date.now() - new Date(a.timestamp).getTime() > mins * 60 * 1000) {
        return false;
      }
    }
    if (q) {
      const haystack = `${a.five_tuple.src_ip} ${a.five_tuple.dst_ip} ${a.flow_id} ${a.threat_class}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
}

export function selectStats(state) {
  const stats = {
    total: state.alerts.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    activeFlows: 0,
  };
  const seenFlows = new Set();
  for (const a of state.alerts) {
    if (a.severity === 'CRITICAL') stats.critical += 1;
    else if (a.severity === 'HIGH') stats.high += 1;
    else if (a.severity === 'MEDIUM') stats.medium += 1;
    else if (a.severity === 'LOW') stats.low += 1;
    seenFlows.add(a.flow_id);
  }
  stats.activeFlows = seenFlows.size;
  return stats;
}
