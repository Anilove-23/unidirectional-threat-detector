// Bounded product projection; Redis decision/incident streams are the durable log.
const fs = require('fs');
const path = require('path');

class ProductStore {
  constructor({ capacity = 10000, journal = null } = {}) {
    this.capacity = capacity;
    this.journal = journal;
    this.decisions = new Map();
    this.incidents = new Map();
    this.lines = 0;
    if (journal && fs.existsSync(journal)) {
      const lines = fs.readFileSync(journal, 'utf8').split('\n');
      for (const [index, line] of lines.entries()) {
        if (!line) continue;
        try {
          const entry = JSON.parse(line);
          this.put(entry.kind, entry.value, false);
        } catch (error) {
          // Only a torn final append can be discarded after a crash.
          if (index < lines.length - 2) throw error;
        }
      }
    }
  }

  put(kind, value, persist = true) {
    const map = kind === 'decision' ? this.decisions : this.incidents;
    const key = kind === 'decision' ? value.decision_id : value.incident_id;
    const previous = map.get(key);
    if (previous && (kind === 'decision' || value.count < previous.count || (value.count === previous.count && value.status === previous.status))) return false;
    if (persist && this.journal) {
      fs.mkdirSync(path.dirname(this.journal), { recursive: true });
      fs.appendFileSync(this.journal, `${JSON.stringify({ kind, value })}\n`);
      this.lines += 1;
    }
    map.delete(key);
    map.set(key, value);
    while (map.size > this.capacity) map.delete(map.keys().next().value);
    if (this.journal && this.lines > this.capacity * 4) {
      const contents = [...this.decisions.values()].map(value => JSON.stringify({ kind: 'decision', value }))
        .concat([...this.incidents.values()].map(value => JSON.stringify({ kind: 'incident', value }))).join('\n');
      fs.writeFileSync(`${this.journal}.tmp`, `${contents}\n`);
      fs.renameSync(`${this.journal}.tmp`, this.journal);
      this.lines = this.decisions.size + this.incidents.size;
    }
    return true;
  }

  list(kind, { state, label, limit = 100, offset = 0 } = {}) {
    const map = kind === 'decision' ? this.decisions : this.incidents;
    const values = [...map.values()].filter(value => (!state || (value.decision_state || value.status) === state) && (!label || Object.hasOwn(value.labels, label)))
      .sort((a, b) => Date.parse(b.event_time || b.last_seen) - Date.parse(a.event_time || a.last_seen));
    return { total: values.length, items: values.slice(offset, offset + limit) };
  }
}

function decisionAlert(decision) {
  const confidence = decision.confidence;
  return {
    ...decision,
    timestamp: decision.event_time, flow_id: decision.decision_id,
    observation_flow_id: decision.entity_keys.flow_id,
    five_tuple: { src_ip: decision.entity_keys.source, dst_ip: decision.entity_keys.destination, src_port: null, dst_port: null, protocol: decision.protocol },
    threat_class: decision.primary_class || decision.decision_state,
    confidence_score: confidence,
    severity: decision.decision_state === 'UNCERTAIN' ? 'LOW' : confidence >= .9 ? 'CRITICAL' : 'HIGH',
    model_source: { supervised_score: null, anomaly_score: null, sequence_score: null, fired_models: Object.keys(decision.model_versions) },
    ingestion_meta: { sensor_id: decision.sensor_id, capture_interface: null, pipeline_version: '2.0.0' },
  };
}

module.exports = { ProductStore, decisionAlert };
