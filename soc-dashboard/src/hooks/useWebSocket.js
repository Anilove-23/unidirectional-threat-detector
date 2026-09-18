/**
 * useWebSocket — the single integration point between the transport layer
 * (services/websocket.js) and the Zustand store.
 *
 * Chooses a real WebSocketService or the MockWebSocketService based on
 * VITE_USE_MOCK_DATA, connects on mount, tears down on unmount, and wires
 * 'status' / 'message' events into store actions. Also exposes the live
 * service instance so Live Demo Mode can inject scripted alerts through the
 * same path a real alert would take.
 */
import { useEffect, useRef, useState } from 'react';
import { useAlertStore } from '../store/alertStore';
import { WebSocketService, MockWebSocketService } from '../services/websocket';
import { generateSeedAlerts } from '../mock/mockAlerts';
import { normalizeAlert } from '../types/alert';
import { API_BASE } from '../services/config';

const USE_MOCK = String(import.meta.env.VITE_USE_MOCK_DATA).toLowerCase() === 'true';
const WS_URL = import.meta.env.VITE_WS_URL || `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`;

export function useWebSocket() {
  const addAlert = useAlertStore((s) => s.addAlert);
  const upsertIncident = useAlertStore((s) => s.upsertIncident);
  const setAlerts = useAlertStore((s) => s.setAlerts);
  const setConnectionStatus = useAlertStore((s) => s.setConnectionStatus);
  const serviceRef = useRef(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const service = USE_MOCK ? new MockWebSocketService() : new WebSocketService(WS_URL);
    serviceRef.current = service;

    // Recover alerts and incidents missed while the browser was disconnected.
    function refreshHistory() {
      fetch(`${API_BASE}/alerts?limit=100`)
        .then((res) => (res.ok ? res.json() : Promise.reject(res)))
        .then((json) => {
          if (json?.data?.alerts && Array.isArray(json.data.alerts)) {
            json.data.alerts.map(normalizeAlert).filter(Boolean).reverse().forEach(addAlert);
          }
        })
        .catch((err) => {
          console.warn('[Dashboard] Could not fetch initial alerts from /api/alerts:', err);
        });
      fetch(`${API_BASE}/v2/incidents?limit=100`).then(res => res.ok ? res.json() : null)
        .then(json => json?.data?.items?.slice().reverse().forEach(upsertIncident)).catch(() => {});
      fetch(`${API_BASE}/v2/decisions?limit=100`).then(res => res.ok ? res.json() : null)
        .then(json => json?.data?.items?.filter(d => d.decision_state !== 'BENIGN').map(normalizeAlert).filter(Boolean).reverse().forEach(addAlert)).catch(() => {});
    }

    if (USE_MOCK) setAlerts(generateSeedAlerts());
    const offStatus = service.on('status', status => {
      setConnectionStatus(status);
      if (!USE_MOCK && status === 'CONNECTED') refreshHistory();
    });
    const offMessage = service.on('message', addAlert);
    const offIncident = service.on('incident', upsertIncident);

    service.connect();
    setReady(true);

    return () => {
      offStatus();
      offMessage();
      offIncident();
      service.disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { service: serviceRef.current, isMock: USE_MOCK, ready };
}
