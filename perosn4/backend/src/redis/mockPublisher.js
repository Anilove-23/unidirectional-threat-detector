const Redis = require('ioredis');
const { crypto } = require('crypto');
const config = require('../config');

// Helper to generate UUIDs
function generateUuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

const THREAT_CLASSES = [
  'BOTNET_C2_BEACONING',
  'MALWARE_EXFILTRATION',
  'UNAUTHORIZED_TUNNEL',
  'PORT_SCAN_RECON',
  'DDOS_VOLUMETRIC',
  'DATA_DIODE_BYPASS_ATTEMPT',
  'SUSPICIOUS_ANOMALY'
];

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function generateMockAlert() {
  const threatClass = THREAT_CLASSES[Math.floor(Math.random() * THREAT_CLASSES.length)];
  const severity = SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)];
  const flowId = generateUuid();
  const srcHost = Math.floor(Math.random() * 200) + 10;
  const dstHost = Math.floor(Math.random() * 200) + 1;

  return {
    timestamp: new Date().toISOString(),
    flow_id: flowId,
    five_tuple: {
      src_ip: `10.44.${srcHost}.15`,
      dst_ip: `198.51.100.${dstHost}`,
      src_port: Math.floor(Math.random() * 40000) + 1024,
      dst_port: [80, 443, 8080, 53, 22][Math.floor(Math.random() * 5)],
      protocol: 'TCP/TLS'
    },
    threat_class: threatClass,
    confidence_score: parseFloat((Math.random() * 0.4 + 0.6).toFixed(2)),
    severity: severity,
    model_source: {
      supervised_score: parseFloat((Math.random() * 0.5 + 0.4).toFixed(2)),
      anomaly_score: parseFloat((Math.random() * 0.6 + 0.3).toFixed(2)),
      sequence_score: parseFloat((Math.random() * 0.7 + 0.2).toFixed(2)),
      fired_models: ['lstm_beacon_v2', 'isolation_forest_v3']
    },
    evidence: {
      ja3_fingerprint: 'e7fe94cc92f237ed970e704870560a69',
      beacon_interval_seconds: parseFloat((Math.random() * 30 + 10).toFixed(1)),
      src_ip_entropy: parseFloat((Math.random() * 0.5).toFixed(2))
    },
    ingestion_meta: {
      sensor_id: 'diode-sensor-04',
      capture_interface: 'eth1-rx-only',
      pipeline_version: '1.3.0'
    }
  };
}

async function startMockPublisher(intervalMs = 3000) {
  console.log(`[Mock Publisher] Connecting to Redis at ${config.redisUrl}...`);
  
  const publisher = new Redis(config.redisUrl, {
    retryStrategy() { return 2000; },
    lazyConnect: true
  });

  try {
    await publisher.connect();
    console.log('[Mock Publisher] Connected to Redis publisher client.');
  } catch (err) {
    console.warn('[Mock Publisher] Could not connect to Redis:', err.message);
  }

  console.log(`[Mock Publisher] Starting mock alert publisher on channel "${config.alertChannel}" every ${intervalMs}ms...`);

  setInterval(async () => {
    const mockAlert = generateMockAlert();
    const payload = JSON.stringify(mockAlert);

    if (publisher.status === 'ready') {
      await publisher.publish(config.alertChannel, payload);
      console.log(`[Mock Publisher] Published mock alert ${mockAlert.flow_id} (${mockAlert.threat_class}) to Redis`);
    } else {
      console.log(`[Mock Publisher - Standalone] Generated mock alert: ${mockAlert.flow_id} (${mockAlert.threat_class})`);
    }
  }, intervalMs);
}

if (require.main === module) {
  startMockPublisher();
}

module.exports = {
  generateMockAlert,
  startMockPublisher
};
