/**
 * useLiveDemo — SIH demo utility. Plays the scripted alert sequence
 * (mock/demoMode.js) through whatever transport is active, so alerts
 * arrive via the exact same store path as a real WebSocket message.
 * Only meaningful in mock mode; guarded in the UI accordingly.
 */
import { useCallback, useRef } from 'react';
import { useAlertStore } from '../store/alertStore';
import { runDemoSequence } from '../mock/demoMode';

export function useLiveDemo() {
  const addAlert = useAlertStore((s) => s.addAlert);
  const setDemoStep = useAlertStore((s) => s.setDemoStep);
  const endDemo = useAlertStore((s) => s.endDemo);
  const cancelRef = useRef(null);

  const start = useCallback(() => {
    cancelRef.current?.();
    cancelRef.current = runDemoSequence({
      onStep: (idx, label) => setDemoStep(idx, label),
      onAlert: (alert) => addAlert(alert),
      onComplete: () => endDemo(),
    });
  }, [addAlert, setDemoStep, endDemo]);

  const stop = useCallback(() => {
    cancelRef.current?.();
    endDemo();
  }, [endDemo]);

  return { start, stop };
}
