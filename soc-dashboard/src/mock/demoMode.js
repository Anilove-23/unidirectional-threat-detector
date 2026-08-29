/**
 * Live Demo Mode — a development/demo utility only.
 *
 * Plays a fixed, narratively-ordered sequence of alerts into the dashboard
 * over time, so a judge sees the "attack traffic -> alert" story unfold
 * exactly once, on demand. This is NOT a simulation of live AI detection —
 * it replays canned mock alerts on a timer. It is only ever wired up when
 * mock mode is active; it never runs against a real backend connection.
 */
import {
  makePortScanAlert,
  makeDnsTunnelingAlert,
  makeVolumetricDdosAlert,
  makeBotnetC2Alert,
  makeAnomalousAlert,
} from './mockAlerts';

/**
 * @typedef {Object} DemoStep
 * @property {string} label   Shown in the demo control while this step plays
 * @property {() => import('../types/alert').Alert | null} build  null = "quiet" beat, no alert
 */

/** @type {DemoStep[]} */
export const DEMO_SCRIPT = [
  { label: 'Baseline traffic — nothing unusual', build: () => null },
  { label: 'Reconnaissance sweep detected', build: makePortScanAlert },
  { label: 'DNS tunnelling channel detected', build: makeDnsTunnelingAlert },
  { label: 'Volumetric flood detected', build: makeVolumetricDdosAlert },
  { label: 'Botnet C2 beaconing detected', build: makeBotnetC2Alert },
  { label: 'Anomalous flow flagged', build: makeAnomalousAlert },
];

const STEP_INTERVAL_MS = 3200;

/**
 * Runs the demo script, invoking `onStep(stepIndex, label)` when a new step
 * begins and `onAlert(alert)` whenever a step produces an alert. Returns a
 * cancel function.
 */
export function runDemoSequence({ onStep, onAlert, onComplete }) {
  let cancelled = false;
  let idx = 0;

  function tick() {
    if (cancelled || idx >= DEMO_SCRIPT.length) {
      if (!cancelled) onComplete?.();
      return;
    }
    const step = DEMO_SCRIPT[idx];
    onStep?.(idx, step.label);
    const alert = step.build();
    if (alert) onAlert?.(alert);
    idx += 1;
    setTimeout(tick, STEP_INTERVAL_MS);
  }

  tick();
  return () => {
    cancelled = true;
  };
}
