const express = require('express');
const router = express.Router();
const { getDbStatus } = require('../db/connection');
const { getSubscriberStatus } = require('../redis/subscriber');
const { getClientCount } = require('../websocket/broadcaster');
const AlertModel = require('../db/models/Alert');

const startTime = new Date();

/**
 * @route   GET /api/health
 * @desc    Pipeline & service health check
 */
router.get('/', async (req, res) => {
  try {
    const dbStatus = getDbStatus();
    const redisStatus = getSubscriberStatus();
    const wsClients = getClientCount();
    const totalAlertsStored = await AlertModel.getCount();

    res.json({
      status: 'healthy',
      service: 'SIH26145-Backend-Person4',
      uptime_seconds: Math.floor((new Date() - startTime) / 1000),
      timestamp: new Date().toISOString(),
      components: {
        database: dbStatus,
        redis_subscriber: redisStatus,
        websocket_broadcaster: {
          active_connections: wsClients
        },
        alert_store: {
          total_alerts: totalAlertsStored
        }
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'unhealthy',
      error: err.message
    });
  }
});

module.exports = router;
