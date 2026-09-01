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

const USE_MOCK = String(import.meta.env.VITE_USE_MOCK_DATA).toLowerCase() === 'true';
const WS_URL = import.meta.env.VITE_WS_URL ?? 'ws://localhost:5000';

export function useWebSocket() {
  const addAlert = useAlertStore((s) => s.addAlert);
  const setAlerts = useAlertStore((s) => s.setAlerts);
  const setConnectionStatus = useAlertStore((s) => s.setConnectionStatus);
  const serviceRef = useRef(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const service = USE_MOCK ? new MockWebSocketService() : new WebSocketService(WS_URL);
    serviceRef.current = service;

    // Seed the dashboard so it isn't empty on first paint in mock mode.
    if (USE_MOCK) {
      setAlerts(generateSeedAlerts());
    } else {
      // In live mode, fetch persisted alerts from backend on mount
      fetch('/api/alerts?limit=100')
        .then((res) => (res.ok ? res.json() : Promise.reject(res)))
        .then((json) => {
          if (json?.data?.alerts && Array.isArray(json.data.alerts)) {
            setAlerts(json.data.alerts);
          }
        })
        .catch((err) => {
          console.warn('[Dashboard] Could not fetch initial alerts from /api/alerts:', err);
        });
    }

    const offStatus = service.on('status', setConnectionStatus);
    const offMessage = service.on('message', addAlert);

    service.connect();
    setReady(true);

    return () => {
      offStatus();
      offMessage();
      service.disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { service: serviceRef.current, isMock: USE_MOCK, ready };
}
