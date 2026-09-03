/**
 * usePipelineStats.js
 * ====================
 * Polls /api/stats every POLL_INTERVAL_MS milliseconds and returns the
 * current pipeline throughput snapshot.
 *
 * Falls back gracefully when the backend or ML engine is not yet running:
 *   - Returns null until the first successful response.
 *   - Continues polling; recovers automatically when the service comes up.
 *
 * Usage:
 *   const { flowsPerSec, alertsPerMin, processedTotal, uptime } = usePipelineStats();
 */
import { useState, useEffect, useRef } from 'react';

const POLL_INTERVAL_MS = 5_000;
const API_BASE = import.meta.env.VITE_API_URL || '';

export function usePipelineStats() {
  const [stats, setStats] = useState(null);
  const timerRef = useRef(null);

  async function fetchStats() {
    try {
      const res = await fetch(`${API_BASE}/api/stats`);
      if (!res.ok) return;
      const json = await res.json();
      if (json.status === 'success' && json.data) {
        setStats(json.data);
      }
    } catch (_) {
      // Backend not reachable — keep previous value, retry next interval
    }
  }

  useEffect(() => {
    fetchStats();
    timerRef.current = setInterval(fetchStats, POLL_INTERVAL_MS);
    return () => clearInterval(timerRef.current);
  }, []);

  return {
    flowsPerSec:     stats?.flows_per_sec     ?? null,
    alertsPerMin:    stats?.alerts_per_min    ?? null,
    processedTotal:  stats?.processed_total   ?? null,
    uptimeS:         stats?.uptime_s          ?? null,
    trackedSrcIps:   stats?.tracked_src_ips   ?? null,
    throughputWindow: stats?.throughput_window_s ?? 10,
    source:          stats?.source            ?? null,
  };
}
