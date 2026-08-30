const Redis = require('ioredis');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const config = require('../config');
const alertSchema = require('../schemas/alertSchema.json');
const AlertModel = require('../db/models/Alert');
const { broadcastAlert } = require('../websocket/broadcaster');

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);
const validateAlert = ajv.compile(alertSchema);

let redisSubscriber = null;
let isConnected = false;

/**
 * Initialize Redis Subscriber listening to "alert.new" channel
 */
function initSubscriber() {
  console.log(`[Redis Subscriber] Connecting to Redis at ${config.redisUrl}...`);

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

    // Validate payload against alertSchema.json
    const valid = validateAlert(alertData);
    if (!valid) {
      console.warn('[Redis Subscriber] Received alert failing schema validation:', validateAlert.errors);
      // Persist anyway or log validation failure
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
    channel: config.alertChannel
  };
}

module.exports = {
  initSubscriber,
  handleAlertMessage,
  getSubscriberStatus
};
