const Redis = require('ioredis');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const config = require('../config');
const alertSchema = require('../schemas/alertSchema.json');
const AlertModel = require('../db/models/Alert');
const { broadcastAlert, broadcastEvent } = require('../websocket/broadcaster');
const { ProductStore, decisionAlert } = require('../../../../agent2_detection_product/backend/store.cjs');
const decisionSchema = require('../../../../agent2_detection_product/contracts/decision/schema.json');
const incidentSchema = require('../../../../agent2_detection_product/contracts/incident/schema.json');

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);
const validateAlert = ajv.compile(alertSchema);
const validateDecision = ajv.compile(decisionSchema);
const validateIncident = ajv.compile(incidentSchema);
const productStore = new ProductStore({ journal: process.env.V2_STORE_PATH || null });

async function handleV2Message(channel, message) {
  const data = JSON.parse(message);
  const isDecision = channel === 'decision.new';
  const validate = isDecision ? validateDecision : validateIncident;
  if (!validate(data)) throw new Error(`Invalid V2 payload: ${ajv.errorsText(validate.errors)}`);
  if (isDecision && data.decision_state === 'KNOWN_ATTACK' && !Object.hasOwn(data.labels, data.primary_class)) {
    throw new Error('Primary class must be one of the passing labels');
  }
  if (!productStore.put(isDecision ? 'decision' : 'incident', data)) return false;
  if (isDecision) {
    if (data.decision_state !== 'BENIGN') {
      const alert = decisionAlert(data);
      await AlertModel.saveAlert(alert);
      broadcastAlert(alert);
    }
  } else {
    broadcastEvent('incident', data);
  }
  return true;
}

let redisSubscriber = null;
let streamReader = null;
let isConnected = false;

// Replay retained decisions on startup and resume after a disconnected dashboard
// backend. V2 uses one ordered stream reader so incident close/reopen updates
// cannot race a second pub/sub delivery of older history.
async function consumeStreams(client) {
  const cursors = { 'decision.v2': '0-0', 'incident.v2': '0-0' };
  while (client.status !== 'end') {
    try {
      const batches = await client.xread('BLOCK', 2000, 'COUNT', 250, 'STREAMS', ...Object.keys(cursors), ...Object.values(cursors));
      for (const [stream, records] of batches || []) {
        for (const [id, fields] of records) {
          const payloadIndex = fields.indexOf('payload');
          try {
            if (payloadIndex < 0) throw new Error('Missing payload');
            await handleV2Message(stream === 'decision.v2' ? 'decision.new' : 'incident.update', fields[payloadIndex + 1]);
          } catch (error) {
            console.warn(`[Redis Streams] Rejected ${stream}/${id}:`, error.message);
          }
          cursors[stream] = id;
        }
      }
    } catch (error) {
      if (client.status === 'end') break;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
}

function closeSubscriber() {
  streamReader?.disconnect();
  redisSubscriber?.disconnect();
  isConnected = false;
}

/**
 * Initialize Redis Subscriber listening to "alert.new" channel
 */
function initSubscriber() {
  console.log(`[Redis Subscriber] Connecting to Redis at ${config.redisUrl}...`);
  for (const decision of productStore.decisions.values()) {
    if (decision.decision_state !== 'BENIGN') AlertModel.saveAlert(decisionAlert(decision));
  }

  streamReader = new Redis(config.redisUrl, { maxRetriesPerRequest: 1 });
  streamReader.on('error', () => {});
  consumeStreams(streamReader).catch(error => console.warn('[Redis Streams]', error.message));

  redisSubscriber = new Redis(config.redisUrl, {
    retryStrategy(times) {
      const delay = Math.min(times * 100, 3000);
      return delay;
    },
    maxRetriesPerRequest: null,
    enableOfflineQueue: true,
    lazyConnect: true
  });

  redisSubscriber.on('connect', () => {
    isConnected = true;
    console.log('[Redis Subscriber] Connected to Redis server.');
  });

  redisSubscriber.on('error', (err) => {
    isConnected = false;
    console.warn('[Redis Subscriber] Redis error (retrying):', err.message);
  });
  redisSubscriber.on('close', () => { isConnected = false; });

  // Attempt async connection
  redisSubscriber.connect().then(() => {
    redisSubscriber.subscribe(config.alertChannel, (err, count) => {
      if (err) {
        console.error(`[Redis Subscriber] Failed to subscribe to channel ${config.alertChannel}:`, err.message);
      } else {
        console.log(`[Redis Subscriber] Subscribed to Redis channel: "${config.alertChannel}" (Total channels: ${count})`);
      }
    });

    redisSubscriber.on('message', async (channel, message) => {
      if (channel === config.alertChannel) {
        await handleAlertMessage(message);
      }
    });
  }).catch((err) => {
    console.warn(`[Redis Subscriber] Redis connection failed (${err.message}). Local backend will continue operating.`);
  });

  return redisSubscriber;
}

/**
 * Handle incoming serialized alert message from Redis
 * @param {String} rawMessage 
 */
async function handleAlertMessage(rawMessage) {
  try {
    const alertData = JSON.parse(rawMessage);

    // Ensure timestamp exists
    if (!alertData.timestamp) {
      alertData.timestamp = new Date().toISOString();
    }

    // Validate payload against alertSchema.json
    const valid = validateAlert(alertData);
    if (!valid) {
      console.warn('[Redis Subscriber] Received alert failing schema validation:', validateAlert.errors);
      return false;
    }

    // 1. Persist to Database
    await AlertModel.saveAlert(alertData);
    console.log(`[Redis Subscriber] Saved alert ${alertData.flow_id} (${alertData.severity} - ${alertData.threat_class})`);

    // 2. Broadcast via WebSocket to dashboard clients
    broadcastAlert(alertData);

  } catch (err) {
    console.error('[Redis Subscriber] Failed to parse Redis alert message:', err.message);
  }
}

/**
 * Check subscriber connection status
 */
function getSubscriberStatus() {
  return {
    isConnected,
    channel: config.alertChannel,
    decision_stream: 'decision.v2',
    incident_stream: 'incident.v2',
    stream_recovery: streamReader?.status === 'ready'
  };
}

module.exports = {
  initSubscriber,
  handleAlertMessage,
  getSubscriberStatus,
  handleV2Message,
  productStore,
  consumeStreams,
  closeSubscriber
};
