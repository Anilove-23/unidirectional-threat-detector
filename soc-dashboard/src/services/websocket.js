/**
 * WebSocket service abstraction.
 *
 * Wraps a native WebSocket with reconnect + exponential backoff, and
 * exposes a small pub/sub surface (`on('message'|'status', cb)`), so
 * useWebSocket (and, through it, the Zustand store) never touches a raw
 * WebSocket instance directly.
 *
 * A parallel MockWebSocketService implements the same interface backed by
 * the local mock alert generator, so the rest of the app is completely
 * indifferent to whether it's talking to Person 4's real backend or to
 * local mock data — flipping VITE_USE_MOCK_DATA is the only thing that
 * changes which one gets constructed (see hooks/useWebSocket.js).
 */
import { normalizeAlert } from '../types/alert';
import { generateRandomAlert } from '../mock/mockAlerts';

const MAX_BACKOFF_MS = 30000;
const BASE_BACKOFF_MS = 1000;

class Emitter {
  constructor() {
    this._listeners = { message: new Set(), status: new Set() };
  }
  on(event, cb) {
    this._listeners[event]?.add(cb);
    return () => this._listeners[event]?.delete(cb);
  }
  emit(event, payload) {
    this._listeners[event]?.forEach((cb) => cb(payload));
  }
}

export class WebSocketService extends Emitter {
  constructor(url) {
    super();
    this.url = url;
    this.socket = null;
    this.status = 'DISCONNECTED';
    this.attempt = 0;
    this._manualClose = false;
    this._reconnectTimer = null;
  }

  _setStatus(status) {
    this.status = status;
    this.emit('status', status);
  }

  connect() {
    this._manualClose = false;
    this._setStatus(this.attempt > 0 ? 'RECONNECTING' : 'CONNECTING');

    try {
      this.socket = new WebSocket(this.url);
    } catch (err) {
      this._scheduleReconnect();
      return;
    }

    this.socket.onopen = () => {
      this.attempt = 0;
      this._setStatus('CONNECTED');
    };

    this.socket.onmessage = (event) => {
      let parsed;
      try {
        parsed = JSON.parse(event.data);
      } catch {
        return; // drop malformed frames rather than crash the dashboard
      }
      const alert = normalizeAlert(parsed);
      if (alert) this.emit('message', alert);
    };

    this.socket.onclose = () => {
      if (this._manualClose) {
        this._setStatus('DISCONNECTED');
        return;
      }
      this._scheduleReconnect();
    };

    this.socket.onerror = () => {
      // onclose fires right after in browsers; let it drive reconnect logic.
    };
  }

  _scheduleReconnect() {
    this._setStatus('RECONNECTING');
    const delay = Math.min(BASE_BACKOFF_MS * 2 ** this.attempt, MAX_BACKOFF_MS);
    this.attempt += 1;
    clearTimeout(this._reconnectTimer);
    this._reconnectTimer = setTimeout(() => this.connect(), delay);
  }

  disconnect() {
    this._manualClose = true;
    clearTimeout(this._reconnectTimer);
    this.socket?.close();
    this._setStatus('DISCONNECTED');
  }
}

/**
 * Mock transport: same interface (`connect`, `disconnect`, `on`), but emits
 * a synthetic 'CONNECTED' status shortly after connect() and then streams
 * one randomly-generated, schema-valid alert every few seconds. Lets the
 * whole dashboard — including the connection-status UI and reconnect
 * indicator — be exercised without a real backend.
 */
export class MockWebSocketService extends Emitter {
  constructor({ intervalMs = 6000 } = {}) {
    super();
    this.status = 'DISCONNECTED';
    this.intervalMs = intervalMs;
    this._interval = null;
    this._connectTimeout = null;
  }

  _setStatus(status) {
    this.status = status;
    this.emit('status', status);
  }

  connect() {
    this._setStatus('CONNECTING');
    clearTimeout(this._connectTimeout);
    this._connectTimeout = setTimeout(() => {
      this._setStatus('CONNECTED');
      clearInterval(this._interval);
      this._interval = setInterval(() => {
        this.emit('message', generateRandomAlert());
      }, this.intervalMs);
    }, 600);
  }

  disconnect() {
    clearTimeout(this._connectTimeout);
    clearInterval(this._interval);
    this._setStatus('DISCONNECTED');
  }

  /** Used by Live Demo Mode to inject a specific alert on cue. */
  emitAlert(alert) {
    this.emit('message', alert);
  }
}
