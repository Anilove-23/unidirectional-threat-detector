const express = require('express');
const router = express.Router();
const AlertModel = require('../db/models/Alert');

/**
 * @route   GET /api/alerts/search
 * @desc    Filtered historical search for alerts
 * @query   threat_class, severity, from, to, page, limit
 */
router.get('/search', async (req, res) => {
  try {
    const { threat_class, severity, from, to, page = 1, limit = 20 } = req.query;

    const result = await AlertModel.searchAlerts({
      threat_class,
      severity,
      from,
      to,
      page: parseInt(page, 10),
      limit: parseInt(limit, 10)
    });

    res.json({
      status: 'success',
      data: result
    });
  } catch (err) {
    console.error('[API] Error in /api/alerts/search:', err.message);
    res.status(500).json({ status: 'error', message: 'Failed to search historical alerts' });
  }
});

/**
 * @route   GET /api/alerts
 * @desc    Get paginated list of alerts, newest first
 * @query   page, limit
 */
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;

    const result = await AlertModel.getAlerts({
      page: parseInt(page, 10),
      limit: parseInt(limit, 10)
    });

    res.json({
      status: 'success',
      data: result
    });
  } catch (err) {
    console.error('[API] Error in /api/alerts:', err.message);
    res.status(500).json({ status: 'error', message: 'Failed to fetch alerts' });
  }
});

/**
 * @route   GET /api/alerts/:flow_id
 * @desc    Fetch a single alert by flow_id
 */
router.get('/:flow_id', async (req, res) => {
  try {
    const { flow_id } = req.params;
    const alert = await AlertModel.getAlertByFlowId(flow_id);

    if (!alert) {
      return res.status(404).json({
        status: 'error',
        message: `Alert with flow_id '${flow_id}' not found`
      });
    }

    res.json({
      status: 'success',
      data: alert
    });
  } catch (err) {
    console.error(`[API] Error in /api/alerts/${req.params.flow_id}:`, err.message);
    res.status(500).json({ status: 'error', message: 'Failed to fetch alert detail' });
  }
});

/**
 * @route   DELETE /api/alerts
 * @desc    Clear all stored alerts
 */
router.delete('/', async (req, res) => {
  try {
    await AlertModel.clearAll();
    res.json({
      status: 'success',
      message: 'All stored alerts cleared successfully'
    });
  } catch (err) {
    console.error('[API] Error in DELETE /api/alerts:', err.message);
    res.status(500).json({ status: 'error', message: 'Failed to clear alerts' });
  }
});

module.exports = router;
