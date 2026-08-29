/**
 * Standardized JSON Alert contract — SIH26145.
 *
 * This module is the single source of truth for the shape of an alert as it
 * crosses the Backend → WebSocket → Frontend boundary. Nothing downstream of
 * this file should invent, rename, or silently coerce fields — if the
 * backend contract changes, change it here first.
 *
 * Written as JSDoc typedefs so editors get real autocomplete/type-checking
 * in a plain-JS (non-TypeScript) project, per project constraints.
 */

/**
 * @typedef {'VOLUMETRIC_DDOS'|'PORT_SCAN'|'DATA_EXFILTRATION'|'DGA_DOMAIN'|'DNS_TUNNELING'|'BOTNET_C2_BEACONING'|'ANOMALOUS_UNCLASSIFIED'} ThreatClass
 */

/**
 * @typedef {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} Severity
 */

/**
 * @typedef {Object} FiveTuple
 * @property {string} src_ip
 * @property {string} dst_ip
 * @property {number} src_port
 * @property {number} dst_port
 * @property {string} protocol
 */

/**
 * @typedef {Object} ModelSource
 * @property {number} supervised_score
 * @property {number} anomaly_score
 * @property {number} sequence_score
 * @property {string[]} fired_models
 */

/**
 * Evidence is intentionally an open bag of fields — different threat classes
 * surface different evidence (e.g. beacon_interval_seconds for C2 beaconing,
 * packet-per-second fan-out for a port scan). The UI must render whatever is
 * present without hardcoding a field list per threat class.
 * @typedef {Object.<string, string|number|boolean|number[]>} Evidence
 */

/**
 * @typedef {Object} IngestionMeta
 * @property {string} sensor_id
 * @property {string} capture_interface
 * @property {string} pipeline_version
 */

/**
 * @typedef {Object} Alert
 * @property {string} timestamp        ISO-8601
 * @property {string} flow_id          UUID
 * @property {FiveTuple} five_tuple
 * @property {ThreatClass} threat_class
 * @property {number} confidence_score 0..1
 * @property {Severity} severity
 * @property {ModelSource} model_source
 * @property {Evidence} evidence
 * @property {IngestionMeta} ingestion_meta
 */

export const THREAT_CLASSES = /** @type {const} */ ([
  'VOLUMETRIC_DDOS',
  'PORT_SCAN',
  'DATA_EXFILTRATION',
  'DGA_DOMAIN',
  'DNS_TUNNELING',
  'BOTNET_C2_BEACONING',
  'ANOMALOUS_UNCLASSIFIED',
]);

export const SEVERITIES = /** @type {const} */ (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

/** WebSocket / pipeline connection states shown in the UI. Never faked. */
export const CONNECTION_STATES = /** @type {const} */ ([
  'CONNECTED',
  'CONNECTING',
  'DISCONNECTED',
  'RECONNECTING',
]);

/**
 * Runtime shape check for a message arriving off the wire. Does not throw —
 * returns null for anything that doesn't satisfy the contract so the caller
 * can drop malformed messages instead of crashing the dashboard.
 * @param {any} raw
 * @returns {Alert|null}
 */
export function normalizeAlert(raw) {
  if (!raw || typeof raw !== 'object') return null;
  if (!THREAT_CLASSES.includes(raw.threat_class)) return null;
  if (!SEVERITIES.includes(raw.severity)) return null;
  if (!raw.five_tuple || !raw.flow_id || !raw.timestamp) return null;

  return {
    timestamp: raw.timestamp,
    flow_id: raw.flow_id,
    five_tuple: {
      src_ip: raw.five_tuple.src_ip ?? 'unknown',
      dst_ip: raw.five_tuple.dst_ip ?? 'unknown',
      src_port: raw.five_tuple.src_port ?? 0,
      dst_port: raw.five_tuple.dst_port ?? 0,
      protocol: raw.five_tuple.protocol ?? 'unknown',
    },
    threat_class: raw.threat_class,
    confidence_score: typeof raw.confidence_score === 'number' ? raw.confidence_score : 0,
    severity: raw.severity,
    model_source: {
      supervised_score: raw.model_source?.supervised_score ?? 0,
      anomaly_score: raw.model_source?.anomaly_score ?? 0,
      sequence_score: raw.model_source?.sequence_score ?? 0,
      fired_models: raw.model_source?.fired_models ?? [],
    },
    evidence: raw.evidence ?? {},
    ingestion_meta: {
      sensor_id: raw.ingestion_meta?.sensor_id ?? 'unknown',
      capture_interface: raw.ingestion_meta?.capture_interface ?? 'unknown',
      pipeline_version: raw.ingestion_meta?.pipeline_version ?? 'unknown',
    },
  };
}
